package store

import (
	"awg-panel/internal/auth"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The encryption key is a separate private file, never a SQLite column or log
// value. AWG_TOTP_KEY_FILE can place it on a separate persistent secret mount.
// Missing keys are generated only when there are no encrypted factors to lose.
func (s *Store) ConfigureMFAKey(path string) error {
	if s.mfaBox != nil {
		return nil
	}
	if path == "" {
		path = filepath.Join(filepath.Dir(s.Path), "totp.key")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		var count int
		if err = s.db.QueryRow("SELECT count(*) FROM account_totp").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("TOTP encryption key is missing; restore the key or use offline recovery")
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fmt.Errorf("cannot create TOTP key directory")
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		err = AtomicCreate(path, key, 0600)
		clear(key)
		if err != nil {
			return fmt.Errorf("cannot persist TOTP encryption key")
		}
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return fmt.Errorf("cannot read TOTP encryption key")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("TOTP key must be a private regular file (0600)")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return fmt.Errorf("cannot read TOTP encryption key")
	}
	box, err := auth.NewSecretBox(key)
	clear(key)
	if err != nil {
		return err
	}
	rows, err := s.db.Query("SELECT account_id,secret FROM account_totp")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var sealed []byte
		if err = rows.Scan(&id, &sealed); err != nil {
			return err
		}
		if _, err = box.Decrypt(id, sealed); err != nil {
			return err
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	s.mfaBox = box
	return nil
}

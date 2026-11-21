package store

import (
	"awg-panel/internal/auth"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	mfaBox *auth.SecretBox
	Path   string
	db     *sql.DB
	lock   *os.File
}

func privateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("storage path must be a regular file")
	}
	if err == nil {
		err = f.Chmod(0600)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func Open(dir string) (_ *Store, err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := privateFile(filepath.Join(dir, ".lock"))
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("another panel instance owns the state: %w", err)
	}
	s := &Store{Path: filepath.Join(dir, "panel.db"), lock: lock}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	if _, e := os.Lstat(filepath.Join(dir, "state.json")); e == nil {
		return nil, fmt.Errorf("legacy state.json found: JSON migration is not supported; keep the old data and use a new data directory for this alpha version")
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	f, err := privateFile(s.Path)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	// A single connection and the existing process lock serialize this small
	// control plane. DELETE/FULL avoids retained WAL copies of client secrets.
	// SQLite's native allocations are outside Go's GOMEMLIMIT: cap its page cache.
	uri := url.URL{Scheme: "file", Path: s.Path}
	q := url.Values{"mode": {"rw"}, "_foreign_keys": {"on"}, "_busy_timeout": {"3000"}, "_synchronous": {"FULL"}, "_secure_delete": {"on"}, "_cache_size": {"-1024"}, "_txlock": {"immediate"}}
	uri.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite3", uri.String())
	if err != nil {
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	s.db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = s.prepare(ctx); err != nil {
		return nil, fmt.Errorf("open SQLite state: %w", err)
	}
	return s, nil
}

func (s *Store) prepare(ctx context.Context) error {
	var version, appID int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return err
	}
	if version == 0 && appID == 0 {
		var count int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("unrecognized database; refusing initialization")
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d; PRAGMA application_id=%d", schemaVersion, applicationID)); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	} else if version != schemaVersion || appID != applicationID {
		return fmt.Errorf("unsupported database schema or application (version %d); no automatic migration is available", version)
	}
	var check string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("database integrity check failed")
	}
	rows, err := s.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	bad := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return rowErr
	}
	if bad {
		return fmt.Errorf("database contains invalid ownership references")
	}
	var journal string
	if err = s.db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journal); err != nil {
		return err
	}
	if journal != "delete" {
		return fmt.Errorf("cannot enable rollback journal")
	}
	_, err = s.db.ExecContext(ctx, "PRAGMA temp_store=MEMORY")
	return err
}

func (s *Store) Close() error {
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	if s.lock != nil {
		err = errors.Join(err, s.lock.Close())
	}
	return err
}

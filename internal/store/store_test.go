package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"awg-panel/internal/auth"
	"awg-panel/internal/model"
)

const testPassword = "test-password-long-enough"

func initialized(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStateSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if other, e := Open(dir); e == nil {
		other.Close()
		t.Fatal("concurrent state writer accepted")
	}
	state.Peers[0].Name = "Saved name"
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// This value is intentionally invalid as a new password. It must be ignored.
	if err = s.Initialize("changed", false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("state lost: %v", err)
	}
	account, err := s.Account(model.BootstrapAccountID)
	if err != nil || !auth.VerifyPassword(account.PasswordHash, testPassword) || auth.VerifyPassword(account.PasswordHash, "changed") {
		t.Fatal("bootstrap credentials changed")
	}
	if account.Role != "superadmin" || !account.Enabled || got.Peers[0].OwnerID != account.ID {
		t.Fatal("invalid initial account ownership")
	}
	for _, name := range []string{s.Path, filepath.Join(dir, ".lock")} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("storage file is not private")
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("data directory is not private")
	}
	raw, err := os.ReadFile(s.Path)
	if err != nil || bytes.Contains(raw, []byte(testPassword)) {
		t.Fatal("plaintext password persisted")
	}
	var version string
	if err = s.db.QueryRow("SELECT sqlite_version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Log("SQLite", version)
}

func TestInitializationIsAtomicAndRequiresPassword(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Initialize("", false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err == nil {
		t.Fatal("initialized without credentials")
	}
	if _, err = s.Load(); err == nil {
		t.Fatal("uninitialized state accepted")
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count)
	if count != 0 {
		t.Fatal("partial account initialized")
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	// A stored password change survives a subsequent bootstrap and reopen.
	hash, _ := auth.HashPassword("updated-password-long-enough")
	if _, err = s.db.Exec("UPDATE accounts SET password_hash=? WHERE id=?", hash, model.BootstrapAccountID); err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Account(model.BootstrapAccountID)
	if !auth.VerifyPassword(a.PasswordHash, "updated-password-long-enough") {
		t.Fatal("changed password reset")
	}
}

func TestLegacyAndUnsupportedDataAreNotReplaced(t *testing.T) {
	t.Run("legacy JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state.json")
		data := []byte("legacy secret fixture")
		os.WriteFile(path, data, 0600)
		if s, err := Open(dir); err == nil {
			s.Close()
			t.Fatal("legacy state ignored")
		}
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, data) {
			t.Fatal("legacy data changed")
		}
		if _, err := os.Stat(filepath.Join(dir, "panel.db")); !os.IsNotExist(err) {
			t.Fatal("database created alongside legacy")
		}
	})
	for _, kind := range []string{"version", "corruption", "foreign database"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			path := s.Path
			switch kind {
			case "version":
				_, err = s.db.Exec("PRAGMA user_version=999")
			case "foreign database":
				_, err = s.db.Exec("PRAGMA application_id=123")
			}
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			if kind == "corruption" {
				os.WriteFile(path, []byte("not a database"), 0600)
			}
			before, _ := os.ReadFile(path)
			if s, err = Open(dir); err == nil {
				s.Close()
				t.Fatal("unsupported data accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("unsupported data replaced")
			}
		})
	}
}

func TestTransactionsOwnershipAndOptionalSecrets(t *testing.T) {
	s := initialized(t)
	before, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	changed := before
	changed.Peers = append([]model.Peer{}, before.Peers...)
	changed.Peers[0].OwnerID = "missing-account"
	changed.Peers[0].Name = "Must roll back"
	if err = s.Save(changed); err == nil {
		t.Fatal("missing owner accepted")
	}
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, before) {
		t.Fatal("failed transaction changed durable state")
	}
	for _, query := range []string{
		"DELETE FROM accounts",
		"UPDATE devices SET owner_id=NULL",
		"UPDATE devices SET slot=255",
		"UPDATE devices SET enabled=2",
		"UPDATE devices SET network_group='invalid'",
		"UPDATE accounts SET manager_id=id",
	} {
		if _, err = s.db.Exec(query); err == nil {
			t.Fatalf("invalid data accepted: %s", query)
		}
	}
	changed.Peers[0] = before.Peers[0]
	changed.Peers[0].PrivateKey = ""
	if err = s.Save(changed); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err != nil || got.Peers[0].PrivateKey != "" || got.Peers[0].PublicKey != before.Peers[0].PublicKey || got.Peers[0].PresharedKey != before.Peers[0].PresharedKey {
		t.Fatal("optional secret damaged device")
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM device_secrets").Scan(&count)
	if count != 0 {
		t.Fatal("empty secret persisted")
	}
	guest, _ := model.NewPeer("Guest", "guest", 3, model.BootstrapAccountID)
	got.Peers = append(got.Peers, guest)
	if err = s.Save(got); err != nil {
		t.Fatal(err)
	}
	got.Peers = got.Peers[:1]
	if err = s.Save(got); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow("SELECT count(*) FROM device_secrets").Scan(&count)
	if count != 0 {
		t.Fatal("deleted device left secret")
	}
}

func TestReadOnlyFailureAndConcurrentReaders(t *testing.T) {
	s := initialized(t)
	before, _ := s.Load()
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(before); err == nil {
		t.Fatal("read-only write accepted")
	}
	s.db.Exec("PRAGMA query_only=OFF")
	got, _ := s.Load()
	if !reflect.DeepEqual(got, before) {
		t.Fatal("read-only failure changed state")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				got, err := s.Load()
				if err != nil || got.PrivateKey != before.PrivateKey {
					t.Error("concurrent read failed")
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if err := s.Save(before); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestJournalPermissionsAndBoundedLockWait(t *testing.T) {
	s := initialized(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE devices SET name='Uncommitted'"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Path + "-journal")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal is not private")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err = s.db.ExecContext(ctx, "SELECT 1"); err == nil {
		t.Fatal("connection wait ignored deadline")
	}
	tx.Rollback()
	var journal string
	var foreignKeys, syncMode, cache, secure int
	s.db.QueryRow("PRAGMA journal_mode").Scan(&journal)
	s.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys)
	s.db.QueryRow("PRAGMA synchronous").Scan(&syncMode)
	s.db.QueryRow("PRAGMA cache_size").Scan(&cache)
	s.db.QueryRow("PRAGMA secure_delete").Scan(&secure)
	if journal != "delete" || foreignKeys != 1 || syncMode != 2 || cache != -1024 || secure != 1 {
		t.Fatal("unexpected durability/resource settings")
	}
}

func TestInterruptedTransactionRecovers(t *testing.T) {
	if dir := os.Getenv("AWG_STORE_CRASH_TEST_DIR"); dir != "" {
		s, err := Open(dir)
		if err != nil {
			os.Exit(2)
		}
		tx, err := s.db.Begin()
		if err != nil {
			os.Exit(3)
		}
		if _, err = tx.Exec("UPDATE devices SET name='Interrupted'"); err != nil {
			os.Exit(4)
		}
		os.Exit(42) // Deliberately bypass Close/Rollback to leave a hot journal.
	}
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Load()
	s.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInterruptedTransactionRecovers$")
	cmd.Env = append(os.Environ(), "AWG_STORE_CRASH_TEST_DIR="+dir)
	err = cmd.Run()
	if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 42 {
		t.Fatal("crash fixture failed", err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(before, got) {
		t.Fatal("interrupted transaction was not recovered")
	}
}

func TestFullDatabaseRollsBack(t *testing.T) {
	s := initialized(t)
	before, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	var pages int
	if err = s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
		t.Fatal(err)
	}
	next := before
	next.Peers = append([]model.Peer{}, before.Peers...)
	for slot := 3; slot <= 254; slot++ {
		p, err := model.NewPeer("Capacity test", "guest", slot, model.BootstrapAccountID)
		if err != nil {
			t.Fatal(err)
		}
		next.Peers = append(next.Peers, p)
	}
	err = s.Save(next)
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code != sqlite3.ErrFull {
		t.Fatalf("expected SQLITE_FULL, got %v", err)
	}
	got, err := s.Load()
	if err != nil || !reflect.DeepEqual(got, before) {
		t.Fatal("full database lost committed state")
	}
}

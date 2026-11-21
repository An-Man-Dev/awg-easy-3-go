package store

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"errors"
	"testing"
)

func TestPasswordChangePersistsAndRejectsStaleCredentials(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Account(model.BootstrapAccountID)
	if err != nil {
		t.Fatal(err)
	}
	const next = "new-test-password-12345"
	if err = s.ReplacePassword(before.ID, before.PasswordHash, next); err != nil {
		t.Fatal(err)
	}
	if err = s.ReplacePassword(before.ID, before.PasswordHash, "stale-test-password"); !errors.Is(err, ErrCredentialsChanged) {
		t.Fatal("stale update accepted")
	}
	after, err := s.Account(before.ID)
	if err != nil || !auth.VerifyPassword(after.PasswordHash, next) || auth.VerifyPassword(after.PasswordHash, testPassword) {
		t.Fatal("password change failed")
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReplacePassword(before.ID, after.PasswordHash, "failed-test-password"); err == nil {
		t.Fatal("read-only update accepted")
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	after, err = s.Account(before.ID)
	if err != nil || !auth.VerifyPassword(after.PasswordHash, next) {
		t.Fatal("restart or bootstrap reset password")
	}
}

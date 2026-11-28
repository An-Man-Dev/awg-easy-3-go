package store

import (
	"awg-panel/internal/model"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const vectorSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func enrolled(t *testing.T) (*Store, Account, []string) {
	t.Helper()
	s := initialized(t)
	if err := s.ConfigureMFAKey(""); err != nil {
		t.Fatal(err)
	}
	a, err := s.Account(model.BootstrapAccountID)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.EnableMFA(a.ID, a.Revision, vectorSecret, "287082", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	a, err = s.Account(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s, a, codes
}
func TestMFAEncryptionReplayAndRestart(t *testing.T) {
	s, a, codes := enrolled(t)
	content, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range append(codes, vectorSecret, strings.ReplaceAll(codes[0], "-", "")) {
		if bytes.Contains(content, []byte(secret)) {
			t.Fatal("plaintext second-factor material in SQLite")
		}
	}
	keyPath := filepath.Join(filepath.Dir(s.Path), "totp.key")
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != 32 || bytes.Contains(content, key) {
		t.Fatal("encryption key persisted incorrectly")
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("key permissions")
	}
	dir := filepath.Dir(s.Path)
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.ConfigureMFAKey(""); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyMFA(a.ID, a.Revision, "287082", time.Unix(59, 0)); !errors.Is(err, ErrMFAInvalid) {
		t.Fatal("enrollment code replayed after restart", err)
	}
	if err = s.VerifyMFA(a.ID, a.Revision, "359152", time.Unix(89, 0)); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyMFA(a.ID, a.Revision, codes[0], time.Unix(89, 0)); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyMFA(a.ID, a.Revision, codes[0], time.Unix(89, 0)); !errors.Is(err, ErrMFAInvalid) {
		t.Fatal("recovery reused", err)
	}
	status, err := s.MFAStatus(a.ID)
	if err != nil || status.RecoveryRemaining != 9 || !status.Enabled {
		t.Fatal("recovery count")
	}
}
func TestMFAConcurrentConsumptionAndThrottle(t *testing.T) {
	s, a, codes := enrolled(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Go(func() {
			if s.VerifyMFA(a.ID, a.Revision, codes[0], time.Unix(60, 0)) == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("recovery code consumed more than once")
	}
	for i := 0; i < 5; i++ {
		_ = s.VerifyMFA(a.ID, a.Revision, "not-a-code", time.Unix(61, 0))
	}
	if err := s.VerifyMFA(a.ID, a.Revision, codes[1], time.Unix(62, 0)); !errors.Is(err, ErrMFARate) {
		t.Fatal("account throttle bypassed", err)
	}
	// Persisted throttle also applies to proof in security changes.
	if _, err := s.ManageMFA(a.ID, a.PasswordHash, codes[1], true, time.Unix(62, 0)); !errors.Is(err, ErrMFARate) {
		t.Fatal("management bypassed throttle", err)
	}
	if err := s.VerifyMFA(a.ID, a.Revision, codes[1], time.Unix(400, 0)); err != nil {
		t.Fatal("throttle failed to expire", err)
	}
}
func TestMFARecoveryReplacementPasswordAndOfflineReset(t *testing.T) {
	s, a, codes := enrolled(t)
	if err := s.ReplacePassword(a.ID, a.PasswordHash, "replacement-test-password"); !errors.Is(err, ErrMFAInvalid) {
		t.Fatal("password changed without second factor", err)
	}
	replacement, err := s.ManageMFA(a.ID, a.PasswordHash, codes[0], false, time.Unix(65, 0))
	if err != nil {
		t.Fatal(err)
	}
	a, _ = s.Account(a.ID)
	if err = s.VerifyMFA(a.ID, a.Revision, codes[1], time.Unix(65, 0)); !errors.Is(err, ErrMFAInvalid) {
		t.Fatal("old recovery set survived")
	}
	if err = s.ReplacePassword(a.ID, a.PasswordHash, "replacement-test-password", replacement[0]); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifyMFA(a.ID, a.Revision, replacement[1], time.Unix(70, 0)); !errors.Is(err, ErrCredentialsChanged) {
		t.Fatal("old account revision retained proof")
	}
	keyPath := filepath.Join(filepath.Dir(s.Path), "totp.key")
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(s.Path)
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.ConfigureMFAKey(""); err == nil {
		t.Fatal("missing key silently replaced")
	}
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("lost key overwritten")
	}
	if err = s.ResetMFA("admin"); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureMFAKey(""); err != nil {
		t.Fatal(err)
	}
	status, _ := s.MFAStatus(a.ID)
	if status.Enabled || status.RecoveryRemaining != 0 {
		t.Fatal("offline recovery incomplete")
	}
}
func TestAdminMFAResetEnforcesHierarchyAndOwnFactor(t *testing.T) {
	s, root, rootCodes := enrolled(t)
	manager, err := s.WriteAccount(root.ID, Account{Login: "manager", Role: "admin", DeviceLimit: 10, Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.WriteAccount(root.ID, Account{Login: "member", Role: "user", DeviceLimit: 10, ManagerID: manager.ID, Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnableMFA(user.ID, user.Revision, vectorSecret, "287082", time.Unix(59, 0)); err != nil {
		t.Fatal(err)
	}
	manager, _ = s.Account(manager.ID)
	if err = s.AdminResetMFA(manager.ID, root.ID, manager.PasswordHash, "", time.Unix(60, 0)); err == nil {
		t.Fatal("admin reset superadmin")
	}
	if err = s.AdminResetMFA(root.ID, user.ID, root.PasswordHash, "", time.Unix(60, 0)); !errors.Is(err, ErrMFAInvalid) {
		t.Fatal("actor second factor skipped", err)
	}
	if err = s.AdminResetMFA(root.ID, user.ID, root.PasswordHash, rootCodes[0], time.Unix(60, 0)); err != nil {
		t.Fatal(err)
	}
	user, _ = s.Account(user.ID)
	if _, err = s.EnableMFA(user.ID, user.Revision, vectorSecret, "287082", time.Unix(59, 0)); err != nil {
		t.Fatal(err)
	}
	if err = s.AdminResetMFA(manager.ID, user.ID, manager.PasswordHash, "", time.Unix(60, 0)); err != nil {
		t.Fatal("manager could not reset subordinate", err)
	}
	rootStatus, _ := s.MFAStatus(root.ID)
	userStatus, _ := s.MFAStatus(user.ID)
	if !rootStatus.Enabled || rootStatus.RecoveryRemaining != 9 || userStatus.Enabled {
		t.Fatal("wrong account factor reset")
	}
}

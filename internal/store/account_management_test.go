package store

import (
	"awg-panel/internal/model"
	"encoding/json"
	"strings"
	"testing"
)

func TestAccountBlockingProjectionAndRootConstraints(t *testing.T) {
	s := initialized(t)
	admin, err := s.WriteAccount(model.BootstrapAccountID, Account{Login: "manager", Role: "admin", DeviceLimit: 10, Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.WriteAccount(admin.ID, Account{Login: "member", Role: "user", DeviceLimit: 10, ManagerID: admin.ID, Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := model.NewPeer("Member", "home", 3, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	state.Peers = append(state.Peers, peer)
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	admin.Enabled = false
	admin, err = s.WriteAccount(model.BootstrapAccountID, admin, "", false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Peers[1].Enabled || !got.Peers[1].AccountBlocked || got.Runtime().Peers[1].Enabled {
		t.Fatal("blocking overwrote device intent or runtime stayed enabled")
	}
	a, err := s.Account(user.ID)
	if err != nil || !a.Enabled || a.Active {
		t.Fatal("inherited account blocking missing")
	}
	if err = s.Save(got); err != nil {
		t.Fatal(err)
	}
	admin.Enabled = true
	if _, err = s.WriteAccount(model.BootstrapAccountID, admin, "", false); err != nil {
		t.Fatal(err)
	}
	got, err = s.Load()
	if err != nil || got.Peers[1].AccountBlocked || !got.Peers[1].Enabled {
		t.Fatal("unblock did not restore desired state")
	}
	for _, query := range []string{"DELETE FROM accounts WHERE role='superadmin'", "UPDATE accounts SET enabled=0 WHERE role='superadmin'", "UPDATE accounts SET role='admin' WHERE role='superadmin'"} {
		if _, err = s.db.Exec(query); err == nil {
			t.Fatal("root invariant bypass", query)
		}
	}
	if _, err = s.WriteAccount(model.BootstrapAccountID, admin, "", true); err == nil {
		t.Fatal("manager removed with subordinate")
	}
	if _, err = s.WriteAccount(model.BootstrapAccountID, user, "", true); err == nil {
		t.Fatal("device owner removed")
	}
	list, err := s.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), "password") || strings.Contains(string(b), "pbkdf2") {
		t.Fatal("account JSON leaked credential")
	}
	entries, err := s.Audit()
	if err != nil || len(entries) != 4 {
		t.Fatal("failed operation changed audit", len(entries), err)
	}
}

package store

import (
	"awg-panel/internal/model"
	"errors"
	"reflect"
	"testing"
)

func TestAddressesPersistWithoutRotatingDevices(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := model.Addresses{Revision: 1, VPNHost: "old.example", PanelOrigin: "https://panel.old.example"}
	if err = s.Initialize(testPassword, false, old); err != nil {
		t.Fatal(err)
	}
	before, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := model.Addresses{Revision: 2, VPNHost: "2001:db8::1", PanelOrigin: "https://[2001:db8::2]:8443"}
	if err = s.SaveAddresses(next, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveAddresses(next, 1); !errors.Is(err, ErrSettingsConflict) {
		t.Fatal("stale addresses accepted")
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	failed := next
	failed.Revision++
	failed.VPNHost = "not-saved.example"
	if err = s.SaveAddresses(failed, 2); err == nil {
		t.Fatal("read-only save accepted")
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Initialize(testPassword, false, old); err != nil {
		t.Fatal(err)
	}
	after, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if *after.Addresses != next || !reflect.DeepEqual(after.Peers, before.Peers) || after.PrivateKey != before.PrivateKey {
		t.Fatal("addresses reset or identity changed")
	}
}

package main

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"strings"
	"testing"
)

func TestOfflineAddressRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize("recovery-test-password", false, model.Addresses{Revision: 1, VPNHost: "old.invalid"}); err != nil {
		t.Fatal(err)
	}
	input := `{"vpnHost":"new.invalid","panelOrigin":"https://Panel.New.Invalid:443"}`
	if err = setAddresses(strings.NewReader(input), dir); err == nil {
		t.Fatal("recovery ignored daemon lock")
	}
	s.Close()
	if err = setAddresses(strings.NewReader(input), dir); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Addresses.VPNHost != "new.invalid" || state.Addresses.PanelOrigin != "https://panel.new.invalid" || state.Addresses.Revision != 2 {
		t.Fatal("offline recovery did not persist normalized addresses")
	}
}

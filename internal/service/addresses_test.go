package service

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddressApplyFailureStopsServiceWithDurableSettings(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Initialize("address-test-password", false, model.Addresses{Revision: 1, VPNHost: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, script := range map[string]string{"ip": "#!/bin/sh\nexit 1\n"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	c := config.Config{Host: "192.0.2.1", Port: 51820, PanelPort: 8881}
	s := &Service{Store: st, State: state, Config: c, Network: &network.Network{Config: c}, Fatal: make(chan error, 1)}
	// Fail before writing runtime files or touching any real network interface.
	_, err = s.UpdateAddresses(context.Background(), model.Addresses{Revision: 1, VPNHost: "192.0.2.2"})
	if err == nil || !strings.Contains(err.Error(), "network apply failed") || !s.failed {
		t.Fatal("apply failure reported success")
	}
	select {
	case <-s.Fatal:
	default:
		t.Fatal("failure did not request shutdown")
	}
	saved, err := st.Load()
	if err != nil || saved.Addresses.VPNHost != "192.0.2.2" || saved.Peers[0] != state.Peers[0] {
		t.Fatal("durable addresses or keys lost")
	}
}

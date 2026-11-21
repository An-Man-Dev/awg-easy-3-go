package service

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestImportFailureKeepsDurableInitialState(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Initialize("transfer-test-password", false, model.Addresses{Revision: 1, VPNHost: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Host: "192.0.2.1", Port: 51820, PanelPort: 8881}
	s := &Service{Store: st, State: state, Config: c, Network: &network.Network{Config: c}, Fatal: make(chan error, 1)}
	snapshot, err := st.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Requirements = s.requirements()
	fingerprint, err := s.CheckImport(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.State.Addresses.VPNHost = "192.0.2.2"
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err = s.ImportArchive(context.Background(), snapshot, fingerprint); err == nil || !s.failed {
		t.Fatal("failed network and rollback did not stop service", err)
	}
	after, err := st.ImportFingerprint()
	if err != nil || after != fingerprint {
		t.Fatal("database did not roll back", err)
	}
	select {
	case <-s.Fatal:
	default:
		t.Fatal("restart not requested")
	}
}

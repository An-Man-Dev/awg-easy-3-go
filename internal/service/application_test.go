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

func TestApplicationFailurePersistsWithoutSecrets(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Service{Store: st}
	s.InitializeApplicationStatus()
	s.ApplicationApplied()
	s.ApplicationFailed()
	status := s.ApplicationStatus()
	if status.State != "error" || !status.Restarting || status.CanRetry || status.LastFailure.IsZero() {
		t.Fatal("failure not shown")
	}
	data, err := os.ReadFile(s.applicationPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "privateKey") || strings.Contains(string(data), "state") {
		t.Fatal("unexpected operational persistence")
	}
	restarted := &Service{Store: st}
	restarted.InitializeApplicationStatus()
	restarted.ApplicationApplied()
	recovered := restarted.ApplicationStatus()
	if recovered.State != "applied" || !recovered.CanRetry || !recovered.LastFailure.Equal(status.LastFailure) {
		t.Fatal("failure history lost on recovery")
	}
}
func TestReapplyRejectsBusyAndFailureKeepsCommittedKeys(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Initialize("application-test-password", false, model.Addresses{Revision: 1, VPNHost: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Host: "192.0.2.1", Port: 51820, PanelPort: 8881}
	s := &Service{Store: st, State: state, Config: c, Network: &network.Network{Config: c}, Fatal: make(chan error, 1)}
	s.mu.Lock()
	if err = s.Reapply(context.Background()); err == nil {
		t.Fatal("busy service accepted retry")
	}
	s.mu.Unlock()
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "ip"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err = s.Reapply(context.Background()); err == nil {
		t.Fatal("failed apply reported success")
	}
	if status := s.ApplicationStatus(); status.State != "error" || !status.Restarting {
		t.Fatal("missing error status")
	}
	after, err := st.Load()
	if err != nil || after.PrivateKey != state.PrivateKey || after.Peers[0].PrivateKey != state.Peers[0].PrivateKey {
		t.Fatal("retry changed keys", err)
	}
	if err = s.Reapply(context.Background()); err == nil {
		t.Fatal("stopping service accepted retry")
	}
}

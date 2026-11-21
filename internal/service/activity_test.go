package service

import (
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
	"testing"
	"time"
)

func TestActivityLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Initialize("activity-test-password", false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st, State: state, Network: &network.Network{}}
	if err = s.LoadObservations(); err != nil {
		t.Fatal(err)
	}
	p := state.Peers[0]
	now := time.Now().UTC().Truncate(time.Second)
	check := func(want string, when time.Time) {
		t.Helper()
		if got := s.activity(p.ID, true, when).Status; got != want {
			t.Fatalf("got %s want %s", got, want)
		}
	}
	check("unavailable", now)
	if err = s.recordObservations(map[string]time.Time{p.PublicKey: {}}, now); err != nil {
		t.Fatal(err)
	}
	check("never", now)
	if err = s.recordObservations(map[string]time.Time{p.PublicKey: now}, now); err != nil {
		t.Fatal(err)
	}
	check("online", now)
	check("unavailable", now.Add(ActivityFreshness+time.Second))
	// Keepalive=0 has the same criterion: a quiet peer eventually has an old handshake.
	if err = s.recordObservations(map[string]time.Time{p.PublicKey: now}, now.Add(OnlineWindow+time.Second)); err != nil {
		t.Fatal(err)
	}
	check("offline", now.Add(OnlineWindow+time.Second))
	if a := s.activity(p.ID, false, now); a.Status != "disabled" || a.LastHandshake == nil {
		t.Fatal("disabled history lost")
	}
	// A restarted interface reports zero; persistent history must not become online or never.
	s2 := &Service{Store: st, State: state, Network: &network.Network{}}
	if err = s2.LoadObservations(); err != nil {
		t.Fatal(err)
	}
	if a := s2.activity(p.ID, true, now); a.Status != "unavailable" || a.LastHandshake == nil {
		t.Fatal("restart lost history")
	}
	if err = s2.recordObservations(map[string]time.Time{p.PublicKey: {}}, now); err != nil {
		t.Fatal(err)
	}
	if a := s2.activity(p.ID, true, now); a.Status != "offline" {
		t.Fatal("reset handshake misclassified")
	}
	if err = s2.recordObservations(map[string]time.Time{}, now); err == nil {
		t.Fatal("missing enabled peer accepted")
	}
	if a := s2.activity(p.ID, true, now); a.Status != "unavailable" || a.LastHandshake == nil {
		t.Fatal("failed poll erased history")
	}
	// Neither portable state nor client exports contain runtime observations.
	loaded, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Peers[0] != state.Peers[0] {
		t.Fatal("observations modified device config")
	}
}

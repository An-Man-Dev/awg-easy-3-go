package store

import (
	"awg-panel/internal/model"
	"testing"
	"time"
)

func TestObservationsPersistenceAndDeletion(t *testing.T) {
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
	guest, err := model.NewPeer("Guest", "guest", 3, model.BootstrapAccountID)
	if err != nil {
		t.Fatal(err)
	}
	state.Peers = append(state.Peers, guest)
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err = s.SaveObservations(map[string]time.Time{guest.ID: now}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveObservations(map[string]time.Time{guest.ID: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Observations()
	if err != nil || !got[guest.ID].Equal(now) {
		t.Fatal("history lost or moved backwards")
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveObservations(map[string]time.Time{guest.ID: now.Add(time.Hour)}); err == nil {
		t.Fatal("failed write accepted")
	}
	s.db.Exec("PRAGMA query_only=OFF")
	got, err = s.Observations()
	if err != nil || !got[guest.ID].Equal(now) {
		t.Fatal("failed write changed history")
	}
	state.Peers = state.Peers[:1]
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	got, err = s.Observations()
	if err != nil || len(got) != 0 {
		t.Fatal("deleted device history retained")
	}
}

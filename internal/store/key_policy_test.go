package store

import (
	"awg-panel/internal/model"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionDeletionAndReissuePersistence(t *testing.T) {
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
	home := state.Peers[0]
	if _, err = s.PurgeStoredKeys(1); err == nil {
		t.Fatal("purge allowed while retention enabled")
	}
	off := model.KeyPolicy{Revision: 2, Retain: false}
	if err = s.SaveKeyPolicy(off, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveKeyPolicy(off, 1); !errors.Is(err, ErrSettingsConflict) {
		t.Fatal("stale policy accepted")
	}
	// Existing keys remain usable and metadata updates do not silently delete them.
	state.Peers[0].Name = "Renamed home"
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil || loaded.Peers[0].PrivateKey != home.PrivateKey {
		t.Fatal("policy change deleted an existing key")
	}
	p, err := model.NewPeer("One-time", "guest", 3, model.BootstrapAccountID)
	if err != nil {
		t.Fatal(err)
	}
	state.Peers = append(state.Peers, p)
	if err = s.Save(state); err == nil {
		t.Fatal("database accepted new private key while retention off")
	}
	state.Peers[1].PrivateKey = ""
	if err = s.Save(state); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PurgeStoredKeys(2); err == nil {
		t.Fatal("read-only purge accepted")
	}
	s.db.Exec("PRAGMA query_only=OFF")
	count, err := s.PurgeStoredKeys(2)
	if err != nil || count != 1 {
		t.Fatal("purge failed")
	}
	loaded, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PrivateKey != state.PrivateKey || loaded.Peers[0].PublicKey != home.PublicKey || loaded.Peers[0].PresharedKey != home.PresharedKey || loaded.Peers[0].PrivateKey != "" {
		t.Fatal("purge damaged VPN identity")
	}
	if err = s.Save(state); err == nil {
		t.Fatal("stale state restored a deleted key")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(home.PrivateKey)) || bytes.Contains(raw, []byte(p.PrivateKey)) {
		t.Fatal("private key remains in SQLite content")
	}
	if _, err = os.Stat(filepath.Join(dir, "panel.db-journal")); !os.IsNotExist(err) {
		t.Fatal("rollback journal retained")
	}
	if err = s.SaveObservations(map[string]time.Time{p.ID: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_, loaded.Peers[1].PublicKey, err = model.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Save(loaded); err != nil {
		t.Fatal(err)
	}
	observations, err := s.Observations()
	if err != nil || !observations[p.ID].IsZero() {
		t.Fatal("reissued device retained old observations")
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, err = s.Load()
	if err != nil || loaded.KeyPolicy.Retain || loaded.Peers[0].PrivateKey != "" {
		t.Fatal("restart reset retention or restored secrets")
	}
	if err = s.SaveKeyPolicy(model.KeyPolicy{Revision: 3, Retain: true}, 2); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load()
	if err != nil || loaded.Peers[0].PrivateKey != "" {
		t.Fatal("re-enabling storage restored keys")
	}
}

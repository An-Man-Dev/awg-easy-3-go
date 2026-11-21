package service

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
	"errors"
	"strings"
	"testing"
)

func TestOneTimeIssuanceAndPurgeKeepOnlyRequiredSecrets(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.Initialize("key-policy-test-password", false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st, State: state, Network: &network.Network{}, Config: config.Config{Host: "vpn.example.com", Port: 51820}}
	preview := s.KeyPolicy()
	off, err := s.UpdateKeyPolicy(model.KeyPolicy{Revision: preview.Revision, Retain: false})
	if err != nil {
		t.Fatal(err)
	}
	if off.StoredKeys != 1 {
		t.Fatal("policy change deleted old keys")
	}
	next, p, err := s.prepareIssue("", "Transient", "guest", "")
	if err != nil {
		t.Fatal(err)
	}
	if next.Peers[1].PrivateKey != "" || p.PrivateKey == "" {
		t.Fatal("transient key entered durable state or was lost")
	}
	snapshot, err := s.snapshot(p)
	if err != nil || !strings.Contains(snapshot.Config, p.PrivateKey) {
		t.Fatal("transient export failed")
	}
	if err = st.Save(next); err != nil {
		t.Fatal(err)
	}
	s.State = next
	if _, err = s.ExportSnapshot(p.ID); err == nil {
		t.Fatal("transient profile re-exportable")
	}
	if _, err = s.PurgeKeys(preview.Revision, preview.DeleteVersion); !errors.Is(err, store.ErrSettingsConflict) {
		t.Fatal("stale deletion accepted")
	}
	if count, err := s.PurgeKeys(off.Revision, off.DeleteVersion); err != nil || count != 1 {
		t.Fatal("confirmed purge failed")
	}
	if _, err = s.ExportSnapshot(state.Peers[0].ID); err == nil {
		t.Fatal("deleted key still exportable from memory")
	}
	next, reissued, err := s.prepareIssue(p.ID, "", "", keyVersion(p))
	if err != nil {
		t.Fatal(err)
	}
	if reissued.ID != p.ID || reissued.Slot != p.Slot || reissued.Group != p.Group || reissued.Name != p.Name || reissued.PublicKey == p.PublicKey || reissued.PresharedKey == p.PresharedKey || next.Peers[1].PrivateKey != "" {
		t.Fatal("incorrect reissue identity")
	}
	if err = st.Save(next); err != nil {
		t.Fatal(err)
	}
	s.State = next
	if _, _, err = s.prepareIssue(p.ID, "", "", keyVersion(p)); !errors.Is(err, ErrKeyConflict) {
		t.Fatal("stale rotation accepted")
	}
	on, err := s.UpdateKeyPolicy(model.KeyPolicy{Revision: off.Revision, Retain: true})
	if err != nil || on.StoredKeys != 0 {
		t.Fatal("retention restored deleted keys")
	}
	next, p, err = s.prepareIssue("", "Stored", "guest", "")
	if err != nil {
		t.Fatal(err)
	}
	if next.Peers[2].PrivateKey != p.PrivateKey {
		t.Fatal("enabled retention did not keep new key")
	}
}

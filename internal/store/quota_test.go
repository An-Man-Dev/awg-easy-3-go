package store

import (
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"context"
	"errors"
	"testing"
)

func TestQuotaTransferAndTransactionalEnforcement(t *testing.T) {
	source := initialized(t)
	admin, err := source.WriteAccount(model.BootstrapAccountID, Account{Login: "quota-manager", Role: "admin", Enabled: true, DeviceLimit: 1}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	state, err := source.Load()
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.NewPeer("Guest", "guest", 3, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	state.Peers = append(state.Peers, p)
	if err = source.Save(state); err != nil {
		t.Fatal(err)
	}
	extra, err := model.NewPeer("Extra", "home", 4, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	attempted := state
	attempted.Peers = append(append([]model.Peer{}, state.Peers...), extra)
	if err = source.SaveAudited(attempted, AuditRecord{Actor: admin.ID, Action: "device.create", Target: extra.ID}); !errors.Is(err, ErrDeviceQuota) {
		t.Fatal("quota bypass", err)
	}
	after, err := source.ImportFingerprint()
	if err != nil || before != after {
		t.Fatal("rejected save mutated DB", err)
	}
	// A lowered quota is a valid export and full restore; it does not revoke devices.
	admin.DeviceLimit = 0
	if _, err = source.WriteAccount(model.BootstrapAccountID, admin, "", false); err != nil {
		t.Fatal(err)
	}
	snap := transferSnapshot(t, source)
	encrypted, err := portable.Encrypt(snap, "password", "quota-transfer-password")
	if err != nil {
		t.Fatal(err)
	}
	snap, err = portable.Decrypt(encrypted, "quota-transfer-password")
	if err != nil {
		t.Fatal(err)
	}
	dest := initialized(t)
	fingerprint, err := dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dest.Import(context.Background(), snap, fingerprint, func(model.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got, err := dest.Account(admin.ID)
	if err != nil || got.DeviceLimit != 0 || got.DeviceCount != 1 {
		t.Fatal("quota or devices lost", err)
	}
	if err = dest.Save(attempted); !errors.Is(err, ErrDeviceQuota) {
		t.Fatal("restored quota not enforced", err)
	}
	// Selective import enforces growth at the transaction boundary too.
	incoming := transferSnapshot(t, dest)
	incoming.State.Peers = append(incoming.State.Peers, extra)
	fingerprint, err = dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	if _, err = dest.ImportSelected(context.Background(), incoming, fingerprint, func(model.State) error { applied = true; return nil }); !errors.Is(err, ErrDeviceQuota) || applied {
		t.Fatal("selective quota bypass", err)
	}
}

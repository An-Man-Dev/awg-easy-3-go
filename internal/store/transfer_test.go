package store

import (
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func transferSnapshot(t *testing.T, s *Store) portable.Snapshot {
	t.Helper()
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap.Requirements = portable.Requirements{Protocol: "amneziawg3", UDPPort: 51820, PanelPort: 8881, Subnet4: "10.8.0.0/24", Subnet6: "fd42:8::/64"}
	if err = snap.Validate(); err != nil {
		t.Fatal(err)
	}
	return snap
}
func TestTransferPreservesIdentityAndMFA(t *testing.T) {
	source, account, codes := enrolled(t)
	if err := source.VerifyMFA(account.ID, account.Revision, codes[0], time.Unix(60, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.Exec("UPDATE key_policy SET retain=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.Exec("UPDATE accounts SET note=? WHERE id=?", "Portable private note", model.BootstrapAccountID); err != nil {
		t.Fatal(err)
	}
	snap := transferSnapshot(t, source)
	for _, include := range []bool{true, false} {
		t.Run(map[bool]string{true: "saved-keys", false: "without-keys"}[include], func(t *testing.T) {
			dest := initialized(t)
			if err := dest.ConfigureMFAKey(""); err != nil {
				t.Fatal(err)
			}
			input := snap
			input.State.Peers = append([]model.Peer{}, snap.State.Peers...)
			input.ClientKeysIncluded = include
			if !include {
				for i := range input.State.Peers {
					input.State.Peers[i].PrivateKey = ""
				}
			}
			fingerprint, err := dest.ImportFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			applied := false
			got, err := dest.Import(context.Background(), input, fingerprint, func(s model.State) error {
				applied = true
				if s.PublicKey != snap.State.PublicKey {
					t.Error("wrong server identity")
				}
				return nil
			})
			if err != nil || !applied {
				t.Fatal("import", err)
			}
			if got.KeyPolicy.Retain || got.Peers[0].PublicKey != snap.State.Peers[0].PublicKey || (got.Peers[0].PrivateKey != "") != include {
				t.Fatal("keys or policy lost")
			}
			if !dest.ImportAvailable() {
				t.Fatal("repeat import unavailable")
			}
			root, err := dest.Account(account.ID)
			if root.Note != "Portable private note" {
				t.Fatal("note lost on transfer")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = dest.VerifyMFA(root.ID, root.Revision, codes[0], time.Unix(60, 0)); !errors.Is(err, ErrMFAInvalid) {
				t.Fatal("spent recovery restored", err)
			}
			if err = dest.VerifyMFA(root.ID, root.Revision, codes[1], time.Unix(60, 0)); err != nil {
				t.Fatal("recovery unusable with destination key", err)
			}
			if err = dest.VerifyMFA(root.ID, root.Revision, "287082", time.Unix(59, 0)); !errors.Is(err, ErrMFAInvalid) {
				t.Fatal("TOTP replay state lost", err)
			}
			if err = dest.VerifyMFA(root.ID, root.Revision, "359152", time.Unix(89, 0)); err != nil {
				t.Fatal("TOTP unusable with destination key", err)
			}
			var n int
			if err = dest.db.QueryRow("SELECT count(*) FROM device_observations").Scan(&n); err != nil || n != 0 {
				t.Fatal("observations imported", err)
			}
		})
	}
}
func TestTransferRollbackAndStalePreview(t *testing.T) {
	source := initialized(t)
	snap := transferSnapshot(t, source)
	dest := initialized(t)
	before, err := dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("simulated network apply failure")
	if _, err = dest.Import(context.Background(), snap, before, func(model.State) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	after, err := dest.ImportFingerprint()
	if err != nil || before != after {
		t.Fatal("rollback changed initial state", err)
	}
	if _, err = dest.db.Exec("UPDATE app_settings SET server_name='Changed'"); err != nil {
		t.Fatal(err)
	}
	if _, err = dest.Import(context.Background(), snap, before, func(model.State) error { t.Fatal("stale preview reached network"); return nil }); !errors.Is(err, ErrSettingsConflict) {
		t.Fatal("stale preview", err)
	}
	state, err := dest.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = dest.Save(state); err != nil {
		t.Fatal(err)
	}
	if !dest.ImportAvailable() {
		t.Fatal("used installation cannot be imported")
	}
}

func TestTransferWriteFailureLeavesInitialState(t *testing.T) {
	source := initialized(t)
	snap := transferSnapshot(t, source)
	dest := initialized(t)
	fingerprint, err := dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dest.db.Exec(`CREATE TEMP TRIGGER reject_import BEFORE UPDATE ON app_settings BEGIN SELECT RAISE(ABORT,'simulated write failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err = dest.Import(context.Background(), snap, fingerprint, func(model.State) error { t.Fatal("failed database write reached network"); return nil }); err == nil {
		t.Fatal("write failure ignored")
	}
	after, err := dest.ImportFingerprint()
	if err != nil || after != fingerprint {
		t.Fatal("partial state persisted", err)
	}
}

func TestReplacePopulatedInstallationAndRollback(t *testing.T) {
	source := initialized(t)
	incoming := transferSnapshot(t, source)
	dest := initialized(t)
	admin, err := dest.WriteAccount(model.BootstrapAccountID, Account{Login: "oldmanager", Role: "admin", Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	user, err := dest.WriteAccount(admin.ID, Account{Login: "olduser", Role: "user", ManagerID: admin.ID, Enabled: true}, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	state, err := dest.Load()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := model.NewPeer("Old device", "guest", 3, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	state.Peers = append(state.Peers, peer)
	if err = dest.Save(state); err != nil {
		t.Fatal(err)
	}
	before, err := dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("apply failed")
	if _, err = dest.Import(context.Background(), incoming, before, func(model.State) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	after, err := dest.ImportFingerprint()
	if err != nil || after != before {
		t.Fatal("populated destination lost on rollback", err)
	}
	got, err := dest.Import(context.Background(), incoming, before, func(model.State) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != len(incoming.State.Peers) || got.PublicKey != incoming.State.PublicKey {
		t.Fatal("replacement incomplete")
	}
	for _, id := range []string{admin.ID, user.ID} {
		if _, err := dest.Account(id); err == nil {
			t.Fatal("old account survived")
		}
	}
	if _, err = dest.Import(context.Background(), incoming, before, func(model.State) error { t.Fatal("stale preview applied"); return nil }); !errors.Is(err, ErrSettingsConflict) {
		t.Fatal("stale replacement accepted", err)
	}
}

func TestImportCrashBeforeCommitRestoresDestination(t *testing.T) {
	if dir := os.Getenv("AWG_IMPORT_CRASH_DIR"); dir != "" {
		dest, err := Open(dir)
		if err != nil {
			os.Exit(2)
		}
		incoming := transferSnapshot(t, dest)
		incoming.State.Settings.ServerName = "Interrupted import"
		fingerprint, err := dest.ImportFingerprint()
		if err != nil {
			os.Exit(3)
		}
		_, _ = dest.Import(context.Background(), incoming, fingerprint, func(model.State) error { os.Exit(42); return nil })
		os.Exit(4)
	}
	dir := t.TempDir()
	dest, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = dest.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	before, err := dest.ImportFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	dest.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestImportCrashBeforeCommitRestoresDestination$")
	cmd.Env = append(os.Environ(), "AWG_IMPORT_CRASH_DIR="+dir)
	if err = cmd.Run(); err == nil {
		t.Fatal("child did not stop")
	} else if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 42 {
		t.Fatal("crash fixture failed", err)
	}
	dest, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	after, err := dest.ImportFingerprint()
	if err != nil || before != after {
		t.Fatal("interrupted import changed destination", err)
	}
}

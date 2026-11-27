package portable

import (
	"awg-panel/internal/model"
	"reflect"
	"testing"
)

func TestSelectionKeepsUnselectedDataAndSecrets(t *testing.T) {
	current := fixture(t)
	incoming := fixture(t)
	incoming.State.Settings.ServerName = "Imported name"
	current.Accounts[0].MFA = &MFA{Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", LastStep: 3, RecoveryHashes: []string{}}
	original := current.Accounts[0]
	merged, _, err := Merge(current, incoming, Selection{Settings: []string{"serverName"}})
	if err != nil {
		t.Fatal(err)
	}
	if merged.State.Settings.ServerName != "Imported name" || merged.State.Settings.Revision != current.State.Settings.Revision+1 {
		t.Fatal("setting not selected")
	}
	if !reflect.DeepEqual(merged.Accounts, current.Accounts) || !reflect.DeepEqual(merged.State.Peers, current.State.Peers) || merged.State.PrivateKey != current.State.PrivateKey {
		t.Fatal("unselected data changed")
	}
	incoming.Accounts[0].Note = "Imported note"
	merged, _, err = Merge(current, incoming, Selection{Accounts: []AccountChoice{{ID: model.BootstrapAccountID, Action: "replace"}}})
	if err != nil {
		t.Fatal(err)
	}
	if merged.Accounts[0].PasswordHash != original.PasswordHash || merged.Accounts[0].Note != "Imported note" {
		t.Fatal("credentials changed without selection")
	}
	if !reflect.DeepEqual(merged.Accounts[0].MFA, original.MFA) {
		t.Fatal("TOTP changed without selection")
	}
	cleared, _, err := Merge(current, incoming, Selection{Accounts: []AccountChoice{{ID: model.BootstrapAccountID, Action: "replace", TOTP: true}}})
	if err != nil || cleared.Accounts[0].MFA != nil {
		t.Fatal("explicit TOTP replacement failed", err)
	}
	if current.Accounts[0].Note != "" || current.State.Settings.ServerName == "Imported name" {
		t.Fatal("merge mutated input")
	}
}
func TestSelectionDeviceMappingConflictsAndKeyPreservation(t *testing.T) {
	current := fixture(t)
	incoming := fixture(t)
	a := incoming.Accounts[0]
	a.ID = "source-admin"
	a.Login = "manager"
	a.Role = "admin"
	incoming.Accounts = append(incoming.Accounts, a)
	p, err := model.NewPeer("Imported guest", "guest", 3, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	incoming.State.Peers = append(incoming.State.Peers, p)
	choice := Selection{Devices: []DeviceChoice{{ID: p.ID, Action: "add"}}}
	if _, _, err = Merge(current, incoming, choice); err == nil {
		t.Fatal("missing owner accepted")
	}
	choice.Accounts = []AccountChoice{{ID: a.ID, Action: "add", Password: true}}
	merged, plan, err := Merge(current, incoming, choice)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Accounts) != 2 || len(merged.State.Peers) != 2 || len(plan.Warnings) == 0 {
		t.Fatal("missing merge or compatibility warning")
	}
	if merged.State.Peers[1].PrivateKey != "" {
		t.Fatal("key imported without selection")
	}
	choice.Devices[0].Slot = 2
	if _, _, err = Merge(current, incoming, choice); err == nil {
		t.Fatal("conflicting address accepted")
	}
	// An archive without private keys must not erase the saved key of the same device.
	incoming = current
	incoming.State.Peers = append([]model.Peer{}, current.State.Peers...)
	incoming.State.Peers[0].PrivateKey = ""
	incoming.ClientKeysIncluded = false
	choice = Selection{Devices: []DeviceChoice{{ID: current.State.Peers[0].ID, Action: "replace"}}}
	merged, _, err = Merge(current, incoming, choice)
	if err != nil {
		t.Fatal(err)
	}
	if merged.State.Peers[0].PrivateKey != current.State.Peers[0].PrivateKey {
		t.Fatal("saved private key erased")
	}
	replacement, err := model.NewPeer("Replacement", "home", 2, model.BootstrapAccountID)
	if err != nil {
		t.Fatal(err)
	}
	replacement.ID = incoming.State.Peers[0].ID
	replacement.PrivateKey = ""
	incoming.State.Peers[0] = replacement
	if _, _, err = Merge(current, incoming, choice); err == nil {
		t.Fatal("incompatible saved key discarded silently")
	}
	choice.DropIncompatibleKeys = true
	if _, _, err = Merge(current, incoming, choice); err != nil {
		t.Fatal(err)
	}
}

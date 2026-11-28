package store

import (
	"awg-panel/internal/model"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSettingsAuditFieldsAndNoOps(t *testing.T) {
	s := initialized(t)
	state, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := *state.Settings
	next.Revision++
	next.ServerName = "Private deployment label"
	next.Client.MTU = 1400
	if err = s.SaveSettings(next, state.Settings.Revision); err != nil {
		t.Fatal(err)
	}
	entries, err := s.Audit()
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	if entries[0].Actor != model.BootstrapAccountID || entries[0].Action != "settings.update" || entries[0].Target != "serverName,mtu" || entries[0].At == "" {
		t.Fatal("missing audit metadata")
	}
	if err = s.SaveSettings(next, state.Settings.Revision); err == nil {
		t.Fatal("stale write accepted")
	}
	next.Revision++
	if err = s.SaveSettings(next, next.Revision-1); err != nil {
		t.Fatal(err)
	}
	entries, err = s.Audit()
	if err != nil || len(entries) != 1 {
		t.Fatal("no-op or conflict was logged", err)
	}
	addresses := *state.Addresses
	addresses.Revision++
	addresses.VPNHost = "private-vpn.example"
	if err = s.SaveAddresses(addresses, state.Addresses.Revision); err != nil {
		t.Fatal(err)
	}
	policy := *state.KeyPolicy
	policy.Revision++
	policy.Retain = false
	if err = s.SaveKeyPolicy(policy, state.KeyPolicy.Revision); err != nil {
		t.Fatal(err)
	}
	count, err := s.PurgeStoredKeys(policy.Revision)
	if err != nil || count != 1 {
		t.Fatal("purge", count, err)
	}
	entries, err = s.Audit()
	if err != nil || len(entries) != 4 {
		t.Fatal("audit missing", err)
	}
	if entries[0].Action != "keys.stored.purge" || entries[0].Target != "1" || entries[1].Action != "keys.retention.disable" || entries[2].Target != "vpnHost" {
		t.Fatal("wrong event metadata")
	}
	data, _ := json.Marshal(entries)
	for _, secret := range []string{next.ServerName, addresses.VPNHost, state.PrivateKey, state.Peers[0].PrivateKey, state.Peers[0].PresharedKey} {
		if strings.Contains(string(data), secret) {
			t.Fatal("value leaked into audit")
		}
	}
	if _, err = s.PurgeStoredKeys(policy.Revision); err != nil {
		t.Fatal(err)
	}
	after, err := s.Audit()
	if err != nil || len(after) != len(entries) {
		t.Fatal("empty purge was logged", err)
	}
}
func TestSettingsAuditFailureRollsBackMutation(t *testing.T) {
	for _, kind := range []string{"settings", "addresses", "policy", "purge"} {
		t.Run(kind, func(t *testing.T) {
			s := initialized(t)
			state, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "purge" {
				p := *state.KeyPolicy
				p.Revision++
				p.Retain = false
				if err = s.SaveKeyPolicy(p, state.KeyPolicy.Revision); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			events, err := s.Audit()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(`CREATE TEMP TRIGGER reject_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test audit failure'); END;`); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "settings":
				next := *before.Settings
				next.Revision++
				next.ServerName = "Rejected"
				err = s.SaveSettings(next, before.Settings.Revision)
			case "addresses":
				next := *before.Addresses
				next.Revision++
				next.VPNHost = "rejected.example"
				err = s.SaveAddresses(next, before.Addresses.Revision)
			case "policy":
				next := *before.KeyPolicy
				next.Revision++
				next.Retain = false
				err = s.SaveKeyPolicy(next, before.KeyPolicy.Revision)
			case "purge":
				_, err = s.PurgeStoredKeys(before.KeyPolicy.Revision)
			}
			if err == nil {
				t.Fatal("mutation succeeded without audit")
			}
			after, err := s.Load()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("audit failure did not roll back", err)
			}
			afterEvents, err := s.Audit()
			if err != nil || !reflect.DeepEqual(events, afterEvents) {
				t.Fatal("failed mutation left event", err)
			}
		})
	}
}

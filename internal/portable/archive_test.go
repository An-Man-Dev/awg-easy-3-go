package portable

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func fixture(t *testing.T) Snapshot {
	t.Helper()
	state, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	settings := model.DefaultSettings(false)
	state.Settings = &settings
	state.KeyPolicy = &model.KeyPolicy{Revision: 1, Retain: true}
	state.Addresses = &model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}
	hash, err := auth.HashPassword("test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{Version: 1, CreatedAt: time.Now().UTC(), ClientKeysIncluded: true, State: state,
		Requirements: Requirements{Protocol: "amneziawg3", UDPPort: 51820, PanelPort: 8881, Subnet4: "10.8.0.0/24", Subnet6: "fd42:8::/64"},
		Accounts:     []Account{{ID: model.BootstrapAccountID, Login: "admin", Role: "superadmin", Enabled: true, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), PasswordHash: hash}}}
}
func TestEncryptedArchive(t *testing.T) {
	s := fixture(t)
	for _, mode := range []string{"password", "key"} {
		t.Run(mode, func(t *testing.T) {
			secret := "archive-test-password"
			wrong := "another-test-password"
			if mode == "key" {
				secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
				wrong = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
			}
			data, err := Encrypt(s, mode, secret)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(s.State.PrivateKey)) || bytes.Contains(data, []byte(s.Accounts[0].PasswordHash)) {
				t.Fatal("plaintext in archive")
			}
			got, err := Decrypt(data, secret)
			if err != nil || got.State.PrivateKey != s.State.PrivateKey || got.Accounts[0].PasswordHash != s.Accounts[0].PasswordHash {
				t.Fatal("round trip", err)
			}
			if _, err = Decrypt(data, wrong); err == nil {
				t.Fatal("wrong credential accepted")
			}
			for _, offset := range []int{0, 8, 12, 27, len(data) - 1} {
				bad := bytes.Clone(data)
				bad[offset] ^= 1
				if _, err = Decrypt(bad, secret); err == nil {
					t.Fatal("tampering accepted", offset)
				}
			}
			other, err := Encrypt(s, mode, secret)
			if err != nil || bytes.Equal(data, other) {
				t.Fatal("archive randomness", err)
			}
		})
	}
}
func TestSnapshotValidation(t *testing.T) {
	s := fixture(t)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.ClientKeysIncluded = false
	if s.Validate() == nil {
		t.Fatal("private key in excluded archive")
	}
	s.State.Peers[0].PrivateKey = ""
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Accounts[0].Enabled = false
	if s.Validate() == nil {
		t.Fatal("disabled root")
	}
	s.Accounts[0].Enabled = true
	s.State.Peers[0].OwnerID = "missing"
	if s.Validate() == nil {
		t.Fatal("orphaned device")
	}
	if _, err := Decrypt(make([]byte, MaxSize+1), "archive-test-password"); err == nil {
		t.Fatal("oversized accepted")
	}
}

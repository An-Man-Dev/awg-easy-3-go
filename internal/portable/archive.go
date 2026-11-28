// Package portable defines a versioned, encrypted application snapshot, never a
// database dump. Only data is accepted: no commands, file paths or host settings.
package portable

import (
	"awg-panel/internal/auth"
	"awg-panel/internal/model"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const Version = 2

const MaxSize = 8 << 20
const magic = "AWGPACK1"
const headerSize = 8 + 1 + 16 + 12

type Requirements struct {
	Protocol  string `json:"protocol"`
	UDPPort   int    `json:"udpPort"`
	PanelPort int    `json:"panelPort"`
	IPv6      bool   `json:"ipv6"`
	Subnet4   string `json:"subnet4"`
	Subnet6   string `json:"subnet6"`
}
type MFA struct {
	Secret         string   `json:"secret"`
	LastStep       int64    `json:"lastStep"`
	RecoveryHashes []string `json:"recoveryHashes"`
}
type Account struct {
	DeviceLimit  int    `json:"deviceLimit"`
	Note         string `json:"note,omitempty"`
	ID           string `json:"id"`
	Login        string `json:"login"`
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
	ManagerID    string `json:"managerId"`
	CreatedAt    string `json:"createdAt"`
	PasswordHash string `json:"passwordHash"`
	MFA          *MFA   `json:"mfa,omitempty"`
}
type Snapshot struct {
	Version            int          `json:"version"`
	CreatedAt          time.Time    `json:"createdAt"`
	ClientKeysIncluded bool         `json:"clientKeysIncluded"`
	Requirements       Requirements `json:"requirements"`
	State              model.State  `json:"state"`
	Accounts           []Account    `json:"accounts"`
}
type Summary struct {
	CreatedAt          time.Time    `json:"createdAt"`
	ServerName         string       `json:"serverName"`
	VPNHost            string       `json:"vpnHost"`
	PanelOrigin        string       `json:"panelOrigin"`
	Accounts           int          `json:"accounts"`
	Devices            int          `json:"devices"`
	StoredKeys         int          `json:"storedKeys"`
	TOTPAccounts       int          `json:"totpAccounts"`
	ClientKeysIncluded bool         `json:"clientKeysIncluded"`
	RetainKeys         bool         `json:"retainKeys"`
	SuperadminLogin    string       `json:"superadminLogin"`
	Requirements       Requirements `json:"requirements"`
}

func (s Snapshot) Summary() Summary {
	r := Summary{CreatedAt: s.CreatedAt, ServerName: s.State.Settings.ServerName, VPNHost: s.State.Addresses.VPNHost, PanelOrigin: s.State.Addresses.PanelOrigin, Accounts: len(s.Accounts), Devices: len(s.State.Peers), ClientKeysIncluded: s.ClientKeysIncluded, RetainKeys: s.State.KeyPolicy.Retain, Requirements: s.Requirements}
	for _, p := range s.State.Peers {
		if p.PrivateKey != "" {
			r.StoredKeys++
		}
	}
	for _, a := range s.Accounts {
		if a.MFA != nil {
			r.TOTPAccounts++
		}
		if a.Role == "superadmin" {
			r.SuperadminLogin = a.Login
		}
	}
	return r
}
func (s Snapshot) RuntimeState() model.State {
	result := s.State
	result.Peers = append([]model.Peer{}, s.State.Peers...)
	accounts := map[string]Account{}
	for _, a := range s.Accounts {
		accounts[a.ID] = a
	}
	for i, p := range result.Peers {
		a := accounts[p.OwnerID]
		result.Peers[i].AccountBlocked = !a.Enabled || (a.ManagerID != "" && !accounts[a.ManagerID].Enabled)
	}
	return result
}
func (s Snapshot) Validate() error {
	invalid := func() error { return fmt.Errorf("archive contains invalid or unsupported configuration") }
	r := s.Requirements
	if s.Version != Version || s.CreatedAt.IsZero() || r.Protocol != "amneziawg3" || r.UDPPort < 1 || r.UDPPort > 65535 || r.PanelPort < 1 || r.PanelPort > 65535 || r.Subnet4 != "10.8.0.0/24" || r.Subnet6 != "fd42:8::/64" {
		return invalid()
	}
	if s.State.Settings == nil || s.State.Addresses == nil || s.State.KeyPolicy == nil || len(s.State.Peers) > 253 || len(s.Accounts) == 0 || len(s.Accounts) > 4096 {
		return invalid()
	}
	if err := model.Validate(s.State); err != nil {
		return invalid()
	}
	ids := map[string]Account{}
	logins := map[string]bool{}
	roots := 0
	idPattern := regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	loginPattern := regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	for _, a := range s.Accounts {
		if _, ok := ids[a.ID]; ok {
			return invalid()
		}
		if a.DeviceLimit < 0 || a.DeviceLimit > model.MaxDeviceLimit {
			return invalid()
		}
		if len(a.Note) > 2000 {
			return invalid()
		}
		if !idPattern.MatchString(a.ID) || !loginPattern.MatchString(a.Login) || logins[a.Login] || !auth.ValidPasswordHash(a.PasswordHash) {
			return invalid()
		}
		if _, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err != nil {
			return invalid()
		}
		switch a.Role {
		case "superadmin":
			roots++
			if a.ID != model.BootstrapAccountID || !a.Enabled || a.ManagerID != "" {
				return invalid()
			}
		case "admin":
			if a.ManagerID != "" {
				return invalid()
			}
		case "user":
			if a.ManagerID == "" || a.ManagerID == a.ID {
				return invalid()
			}
		default:
			return invalid()
		}
		if a.MFA != nil {
			key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.MFA.Secret)
			if err != nil || len(key) != 20 || a.MFA.LastStep < 0 || len(a.MFA.RecoveryHashes) > 10 {
				return invalid()
			}
			seen := map[string]bool{}
			for _, hash := range a.MFA.RecoveryHashes {
				b, e := base64.StdEncoding.Strict().DecodeString(hash)
				if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != hash || seen[hash] {
					return invalid()
				}
				seen[hash] = true
			}
		}
		ids[a.ID] = a
		logins[a.Login] = true
	}
	if roots != 1 {
		return invalid()
	}
	for _, a := range s.Accounts {
		if a.Role == "user" {
			m, ok := ids[a.ManagerID]
			if !ok || m.Role != "admin" {
				return invalid()
			}
		}
	}
	for _, p := range s.State.Peers {
		if _, ok := ids[p.OwnerID]; !ok {
			return invalid()
		}
		if p.CreatedAt.IsZero() || (!s.ClientKeysIncluded && p.PrivateKey != "") {
			return invalid()
		}
	}
	if err := model.Validate(s.RuntimeState().Runtime()); err != nil {
		return invalid()
	}
	return nil
}
func derive(mode byte, secret string, salt []byte) ([]byte, error) {
	if mode == 1 {
		if len(secret) < 12 || len(secret) > 256 {
			return nil, fmt.Errorf("archive password must contain 12–256 bytes")
		}
		return pbkdf2.Key(sha256.New, secret, salt, 600000, 32)
	}
	if mode == 2 {
		key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(secret))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("archive key must be a Base64-encoded 32-byte key")
		}
		return key, nil
	}
	return nil, fmt.Errorf("unsupported archive encryption mode")
}
func Encrypt(s Snapshot, mode, secret string) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	if len(plain) > MaxSize-headerSize-16 {
		return nil, fmt.Errorf("archive exceeds 8 MiB limit")
	}
	header := make([]byte, headerSize)
	copy(header, magic)
	switch mode {
	case "password":
		header[8] = 1
	case "key":
		header[8] = 2
	default:
		return nil, fmt.Errorf("choose password or key encryption")
	}
	if _, err = rand.Read(header[9:]); err != nil {
		return nil, err
	}
	key, err := derive(header[8], secret, header[9:25])
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(header, header[25:37], plain, header), nil
}
func Decrypt(data []byte, secret string) (Snapshot, error) {
	var s Snapshot
	if len(data) > MaxSize || len(data) < headerSize+16 || string(data[:8]) != magic {
		return s, fmt.Errorf("unsupported or oversized archive")
	}
	key, err := derive(data[8], secret, data[9:25])
	if err != nil {
		return s, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return s, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return s, err
	}
	plain, err := gcm.Open(nil, data[25:37], data[37:], data[:37])
	if err != nil {
		return s, fmt.Errorf("cannot decrypt archive: incorrect password/key or damaged file")
	}
	defer clear(plain)
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("invalid archive data")
	}
	if d.Decode(new(any)) != io.EOF {
		return Snapshot{}, fmt.Errorf("invalid archive data")
	}
	if err = s.Validate(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

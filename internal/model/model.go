package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Peer struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Group        string    `json:"group"`
	Slot         int       `json:"slot"`
	Enabled      bool      `json:"enabled"`
	PrivateKey   string    `json:"privateKey"`
	PublicKey    string    `json:"publicKey"`
	PresharedKey string    `json:"presharedKey"`
	CreatedAt    time.Time `json:"createdAt"`
}

type State struct {
	Version    int               `json:"version"`
	PrivateKey string            `json:"privateKey"`
	PublicKey  string            `json:"publicKey"`
	Profile    map[string]string `json:"profile"`
	Peers      []Peer            `json:"peers"`
}

var Fields = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}

func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func Keys() (string, string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	b := k.Bytes()
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return base64.StdEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func (p Peer) Address4() string { return fmt.Sprintf("10.8.0.%d", p.Slot) }
func (p Peer) Address6() string { return fmt.Sprintf("fd42:8::%x", p.Slot) }
func (p Peer) Addresses(v6 bool) string {
	s := p.Address4() + "/32"
	if v6 {
		s += ", " + p.Address6() + "/128"
	}
	return s
}
func NewPeer(name, group string, slot int) (Peer, error) {
	if err := ValidateNameGroup(name, group); err != nil {
		return Peer{}, err
	}
	priv, pub, err := Keys()
	return Peer{ID: Random(12), Name: name, Group: group, Slot: slot, Enabled: true, PrivateKey: priv, PublicKey: pub, PresharedKey: Secret(), CreatedAt: time.Now().UTC()}, err
}
func ValidateNameGroup(name, group string) error {
	if len(name) == 0 || len(name) > 64 || strings.TrimSpace(name) != name || strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("name must contain 1 to 64 bytes without control characters or surrounding spaces")
	}
	if group != "home" && group != "guest" {
		return fmt.Errorf("group must be home or guest")
	}
	return nil
}
func NewState() (State, error) {
	priv, pub, err := Keys()
	if err != nil {
		return State{}, err
	}
	p, err := NewPeer("First home device", "home", 2)
	if err != nil {
		return State{}, err
	}
	return State{Version: 1, PrivateKey: priv, PublicKey: pub, Peers: []Peer{p}, Profile: map[string]string{
		"Jc": "5", "Jmin": "40", "Jmax": "80", "S1": "64", "S2": "32", "S3": "24", "S4": "16",
		"H1": "1", "H2": "2", "H3": "3", "H4": "4", "I1": "<r 32>",
		"HeaderProtectionKey": Secret(), "ContentPaddingAddition": "10-64", "RekeyAfterTime": "100-120", "RekeyTimeout": "3-7", "RejectAfterTime": "160-180", "KeepaliveTimeout": "5-15", "MaxHandshakeAttempts": "15-20", "RandomTrailers": "off", "DisableCookies": "off",
	}}, nil
}
func keyOK(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == s
}
func pairOK(priv, pub string) bool {
	b, e := base64.StdEncoding.DecodeString(priv)
	if e != nil {
		return false
	}
	k, e := ecdh.X25519().NewPrivateKey(b)
	return e == nil && base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) == pub
}

func Validate(s State) error {
	if s.Version != 1 || !pairOK(s.PrivateKey, s.PublicKey) {
		return fmt.Errorf("invalid state version or server key pair")
	}
	if err := ValidateProfile(s.Profile); err != nil {
		return err
	}
	ids, slots, keys := map[string]bool{}, map[int]bool{}, map[string]bool{}
	homes := 0
	for _, p := range s.Peers {
		if err := ValidateNameGroup(p.Name, p.Group); err != nil {
			return err
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`).MatchString(p.ID) || p.Slot < 2 || p.Slot > 254 || ids[p.ID] || slots[p.Slot] || keys[p.PublicKey] || !pairOK(p.PrivateKey, p.PublicKey) || !keyOK(p.PresharedKey) {
			return fmt.Errorf("invalid or duplicate peer identity, address or keys")
		}
		ids[p.ID], slots[p.Slot], keys[p.PublicKey] = true, true, true
		if p.Enabled && p.Group == "home" {
			homes++
		}
	}
	if homes == 0 {
		return fmt.Errorf("at least one enabled home device is required")
	}
	return nil
}

func numberRange(s string, max uint64) (uint64, uint64, error) {
	if !regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`).MatchString(s) {
		return 0, 0, fmt.Errorf("invalid numeric range")
	}
	parts := strings.Split(s, "-")
	a, e := strconv.ParseUint(parts[0], 10, 64)
	if e != nil {
		return 0, 0, e
	}
	b := a
	if len(parts) == 2 {
		b, e = strconv.ParseUint(parts[1], 10, 64)
	}
	if e != nil || a > b || b > max {
		return 0, 0, fmt.Errorf("numeric range out of bounds")
	}
	return a, b, nil
}
func ValidateProfile(p map[string]string) error {
	known := map[string]bool{}
	for _, k := range Fields {
		known[k] = true
	}
	for k := range p {
		if !known[k] {
			return fmt.Errorf("unknown AWG field: %s", k)
		}
	}
	for _, k := range Fields {
		v := p[k]
		if strings.HasPrefix(k, "I") {
			if v == "" {
				continue
			}
			if err := validateSignature(v); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
			continue
		}
		if k == "HeaderProtectionKey" {
			if !keyOK(v) {
				return fmt.Errorf("HeaderProtectionKey must be a base64 32-byte key")
			}
			continue
		}
		if k == "RandomTrailers" || k == "DisableCookies" {
			if v != "on" && v != "off" {
				return fmt.Errorf("%s must be on or off", k)
			}
			continue
		}
		max := uint64(65535)
		if strings.HasPrefix(k, "H") {
			max = 4294967295
		}
		a, b, e := numberRange(v, max)
		if e != nil {
			return fmt.Errorf("invalid %s: %w", k, e)
		}
		if strings.HasPrefix(k, "S") && (a != b || a < 12 || b > 256) {
			return fmt.Errorf("%s must be a single integer between 12 and 256", k)
		}
		if strings.HasPrefix(k, "J") && (a != b || b > 1280 || (k == "Jc" && b > 32)) {
			return fmt.Errorf("%s exceeds safe packet bounds", k)
		}
		if k == "ContentPaddingAddition" && b > 256 {
			return fmt.Errorf("content padding exceeds 256 bytes")
		}
		if strings.Contains(k, "Time") || k == "MaxHandshakeAttempts" {
			if a == 0 {
				return fmt.Errorf("%s must be positive", k)
			}
		}
	}
	jmin, _, _ := numberRange(p["Jmin"], 65535)
	jmax, _, _ := numberRange(p["Jmax"], 65535)
	if jmin > jmax {
		return fmt.Errorf("Jmin must not exceed Jmax")
	}
	sizes := map[uint64]bool{}
	for i, base := range []uint64{148, 92, 64, 32} {
		n, _, _ := numberRange(p[fmt.Sprintf("S%d", i+1)], 65535)
		if sizes[base+n] {
			return fmt.Errorf("AWG packet sizes must be distinct")
		}
		sizes[base+n] = true
	}
	for i := 1; i <= 4; i++ {
		a, b, _ := numberRange(p[fmt.Sprintf("H%d", i)], 4294967295)
		for j := i + 1; j <= 4; j++ {
			c, d, _ := numberRange(p[fmt.Sprintf("H%d", j)], 4294967295)
			if a <= d && c <= b {
				return fmt.Errorf("header ranges must not overlap")
			}
		}
	}
	_, rekey, _ := numberRange(p["RekeyAfterTime"], 65535)
	reject, _, _ := numberRange(p["RejectAfterTime"], 65535)
	if rekey >= reject {
		return fmt.Errorf("RejectAfterTime must exceed RekeyAfterTime")
	}
	return nil
}

// Bound signature expansion before passing configuration to the native engine.
func validateSignature(s string) error {
	if len(s) > 4096 {
		return fmt.Errorf("signature is too long")
	}
	total := 0
	for s != "" {
		if !strings.HasPrefix(s, "<") {
			return fmt.Errorf("invalid signature tag")
		}
		i := strings.IndexByte(s, '>')
		if i < 0 {
			return fmt.Errorf("unterminated signature tag")
		}
		parts := strings.Fields(s[1:i])
		s = s[i+1:]
		if len(parts) != 2 {
			return fmt.Errorf("signature tags require a type and value")
		}
		switch parts[0] {
		case "b":
			b, e := hex.DecodeString(strings.TrimPrefix(parts[1], "0x"))
			if e != nil {
				return fmt.Errorf("invalid signature bytes")
			}
			total += len(b)
		case "r", "rc", "rd", "dz":
			n, e := strconv.Atoi(parts[1])
			if e != nil || n < 0 || n > 1280 {
				return fmt.Errorf("invalid signature length")
			}
			total += n
		default:
			return fmt.Errorf("unsupported signature tag")
		}
	}
	if total > 1280 {
		return fmt.Errorf("signature packet exceeds 1280 bytes")
	}
	return nil
}

func IsVPN(ip netip.Addr) bool {
	return netip.MustParsePrefix("10.8.0.0/24").Contains(ip) || netip.MustParsePrefix("fd42:8::/64").Contains(ip)
}

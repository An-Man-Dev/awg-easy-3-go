package artifact

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
)

func TestOfficialLinkEnvelope(t *testing.T) {
	s, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Host: "2001:db8::123", Port: 51820}
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "dual-stack"}[v6], func(t *testing.T) {
			uri, err := Link(s, s.Peers[0], c, v6)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(uri, "vpn://") || strings.Contains(uri, "=") {
				t.Fatal("invalid URI framing")
			}
			frame, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
			if err != nil {
				t.Fatal(err)
			}
			zr, err := zlib.NewReader(bytes.NewReader(frame[4:]))
			if err != nil {
				t.Fatal(err)
			}
			defer zr.Close()
			raw, err := io.ReadAll(zr)
			if err != nil {
				t.Fatal(err)
			}
			if uint32(len(raw)) != binary.BigEndian.Uint32(frame[:4]) {
				t.Fatal("Qt uncompressed length differs")
			}
			var envelope struct {
				Default    string `json:"defaultContainer"`
				DNS2       string `json:"dns2"`
				Containers []struct {
					Container string `json:"container"`
					AWG       struct {
						ThirdParty bool   `json:"isThirdPartyConfig"`
						Last       string `json:"last_config"`
					} `json:"awg"`
				} `json:"containers"`
			}
			if err = json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Default != "amnezia-awg" || len(envelope.Containers) != 1 || !envelope.Containers[0].AWG.ThirdParty {
				t.Fatal("invalid official container envelope")
			}
			var inner map[string]any
			if err = json.Unmarshal([]byte(envelope.Containers[0].AWG.Last), &inner); err != nil {
				t.Fatal(err)
			}
			conf := Client(s, s.Peers[0], c, v6)
			if inner["config"] != conf || inner["clientId"] != s.Peers[0].PublicKey || inner["psk_key"] != s.Peers[0].PresharedKey || inner["port"] != float64(51820) {
				t.Fatal("structured fields differ from configuration")
			}
			for key, value := range s.Profile {
				if inner[key] != value {
					t.Fatalf("AWG field %s lost", key)
				}
			}
			routes := inner["allowed_ips"].([]any)
			want := 1
			if v6 {
				want = 2
			}
			if len(routes) != want {
				t.Fatal("incorrect route count")
			}
			if !strings.Contains(conf, "Endpoint = [2001:db8::123]:51820") {
				t.Fatal("IPv6 endpoint is not bracketed")
			}
			for _, marker := range []string{"fd42:8::2/128", "::/0", "2606:4700:4700::1111"} {
				if strings.Contains(conf, marker) != v6 {
					t.Fatalf("incorrect family handling: %s", marker)
				}
			}
		})
	}
}
func TestServerExcludesDisabledPeersAndQuickFields(t *testing.T) {
	s, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	p, err := model.NewPeer("Disabled", "guest", 3)
	if err != nil {
		t.Fatal(err)
	}
	p.Enabled = false
	s.Peers = append(s.Peers, p)
	conf := Server(s, config.Config{Port: 51820}, true)
	if strings.Contains(conf, p.PublicKey) || strings.Contains(conf, "Address =") || strings.Contains(conf, "DNS =") {
		t.Fatal("server syncconf contains disabled peer or quick-only fields")
	}
	if !strings.Contains(conf, "AllowedIPs = 10.8.0.2/32, fd42:8::2/128") {
		t.Fatal("server peer routes are missing")
	}
}

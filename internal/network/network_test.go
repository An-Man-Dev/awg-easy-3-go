package network

import (
	"strings"
	"testing"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
)

func TestPolicyIsolationAndFamilies(t *testing.T) {
	s, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	guest, err := model.NewPeer("Guest", "guest", 3)
	if err != nil {
		t.Fatal(err)
	}
	s.Peers = append(s.Peers, guest)
	n := &Network{Config: config.Config{PanelPort: 8881, ExternalBind: "0.0.0.0:9991"}, WAN4: "enp1s0", WAN6: "ens6", protected4: []string{"192.0.2.1"}}
	for _, v6 := range []bool{false, true} {
		n.IPv6 = v6
		policy := n.render(s)
		for _, expected := range []string{`iifname "awg0" drop`, `ip saddr @guest4 ip daddr @private4 drop`, `ip saddr @guest4 ip daddr @protected4 drop`, `ip saddr @guest4 tcp dport { 8881, 9991 } drop`, `iifname "awg0" oifname "awg0" drop`, `oifname "enp1s0" ip saddr 10.8.0.0/24 masquerade`} {
			if !strings.Contains(policy, expected) {
				t.Errorf("missing isolation rule: %s", expected)
			}
		}
		if strings.Index(policy, "ip saddr @guest4") > strings.Index(policy, "ct state established,related") {
			t.Fatal("established flows bypass guest checks")
		}
		if strings.Contains(policy, "ip6 saddr") != v6 || strings.Contains(policy, "type ipv6_addr") != v6 {
			t.Fatal("IPv6 policy differs from effective mode")
		}
		if strings.Contains(policy, "flush ruleset") || strings.Contains(policy, "eth0") {
			t.Fatal("policy owns unrelated rules or hardcodes WAN")
		}
	}
}

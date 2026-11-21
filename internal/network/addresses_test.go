package network

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"context"
	"strings"
	"testing"
)

func TestPrepareAddressesReplacesProtectedHosts(t *testing.T) {
	n := &Network{IPv6: true, protected4: []string{"192.0.2.1"}, protected6: []string{"2001:db8::1"}}
	c := config.Config{Host: "192.0.2.2", PublicOrigin: "https://[2001:db8::2]", PanelPort: 8881, Port: 51820}
	next, err := n.PrepareAddresses(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if n.protected4[0] != "192.0.2.1" || n.protected6[0] != "2001:db8::1" {
		t.Fatal("prepare changed active policy")
	}
	state, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	rules := next.render(state)
	for _, host := range []string{"192.0.2.2", "2001:db8::2"} {
		if !strings.Contains(rules, host) {
			t.Fatal("new host missing from policy")
		}
	}
	if strings.Contains(rules, "192.0.2.1") || strings.Contains(rules, "2001:db8::1") {
		t.Fatal("old host retained")
	}
}

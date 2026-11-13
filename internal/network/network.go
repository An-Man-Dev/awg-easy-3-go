package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"awg-panel/internal/artifact"
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/store"
)

const Interface = "awg0"
const table = "awg_panel"

type Network struct {
	Config                 config.Config
	IPv6                   bool
	WAN4, WAN6             string
	protected4, protected6 []string
	policy                 string
	fingerprint            []byte
}

// Run never returns subprocess output on failure: awg diagnostics can include keys.
func Run(ctx context.Context, input string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s command failed: %w", name, err)
	}
	return b, nil
}
func route(ctx context.Context, v6 bool) (string, error) {
	family, dest := "-4", "1.1.1.1"
	if v6 {
		family, dest = "-6", "2606:4700:4700::1111"
	}
	b, err := Run(ctx, "", "ip", "-j", family, "route", "get", dest)
	if err != nil {
		return "", err
	}
	var rows []struct {
		Dev     string `json:"dev"`
		PrefSrc string `json:"prefsrc"`
		Src     string `json:"src"`
	}
	if err = json.Unmarshal(b, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 || !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`).MatchString(rows[0].Dev) || rows[0].Dev == Interface || rows[0].Dev == "lo" {
		return "", fmt.Errorf("no usable default route")
	}
	if v6 {
		src := rows[0].PrefSrc
		if src == "" {
			src = rows[0].Src
		}
		ip, e := netip.ParseAddr(src)
		if e != nil || !ip.Is6() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			return "", fmt.Errorf("no routed IPv6 source address")
		}
	}
	return rows[0].Dev, nil
}
func Detect(ctx context.Context, c config.Config) (*Network, error) {
	n := &Network{Config: c}
	var err error
	if n.WAN4, err = route(ctx, false); err != nil {
		return nil, fmt.Errorf("IPv4 route detection: %w", err)
	}
	if c.IPv6Mode != "disabled" {
		if n.WAN6, err = route(ctx, true); err == nil {
			n.IPv6 = true
		}
	}
	hosts := []string{c.Host}
	if c.PublicOrigin != "" {
		u, _ := url.Parse(c.PublicOrigin)
		hosts = append(hosts, u.Hostname())
	}
	for _, host := range hosts {
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, e := net.DefaultResolver.LookupNetIP(lookup, "ip", host)
		cancel()
		if e != nil {
			return nil, fmt.Errorf("cannot resolve protected server host %s", host)
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if ip.Is4() {
				n.protected4 = append(n.protected4, ip.String())
			} else if n.IPv6 {
				n.protected6 = append(n.protected6, ip.String())
			}
		}
	}
	return n, nil
}
func (n *Network) WaitInterface(ctx context.Context) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		if _, err := os.Stat("/run/amneziawg/awg0.sock"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("AWG control socket did not become ready")
		case <-t.C:
		}
	}
}
func (n *Network) Down(ctx context.Context) error {
	_, err := Run(ctx, "", "ip", "link", "set", "dev", Interface, "down")
	return err
}
func (n *Network) Up(ctx context.Context) error {
	// Linux may flush static IPv6 addresses on a down event. Restore addresses
	// before every activation, including peer changes and watchdog repairs.
	if _, err := Run(ctx, "", "ip", "address", "replace", "10.8.0.1/24", "dev", Interface); err != nil {
		return err
	}
	if n.IPv6 {
		if _, err := Run(ctx, "", "ip", "-6", "address", "replace", "fd42:8::1/64", "dev", Interface, "nodad"); err != nil {
			return err
		}
	}
	_, err := Run(ctx, "", "ip", "link", "set", "dev", Interface, "up")
	return err
}
func (n *Network) Configure(ctx context.Context, s model.State) error {
	if err := n.Down(ctx); err != nil {
		return err
	}
	if _, err := Run(ctx, "", "ip", "link", "set", "dev", Interface, "mtu", "1280"); err != nil {
		return err
	}
	return n.Apply(ctx, s)
}
func (n *Network) Apply(ctx context.Context, s model.State) error {
	if err := n.Down(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll("/run/awg-panel", 0700); err != nil {
		return err
	}
	path := "/run/awg-panel/server.conf"
	if err := store.AtomicWrite(path, []byte(artifact.Server(s, n.Config, n.IPv6)), 0600); err != nil {
		return err
	}
	defer os.Remove(path)
	if err := n.installPolicy(ctx, n.render(s)); err != nil {
		return err
	}
	if _, err := Run(ctx, "", "awg", "syncconf", Interface, path); err != nil {
		return err
	}
	return n.Up(ctx)
}
func (n *Network) snapshot(ctx context.Context) ([]byte, error) {
	b, err := Run(ctx, "", "nft", "-j", "list", "table", "inet", table)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err = json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	items, ok := doc["nftables"].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid nftables JSON")
	}
	var clean []any
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid nftables item")
		}
		if _, meta := m["metainfo"]; meta {
			continue
		}
		stripHandles(m)
		clean = append(clean, m)
	}
	return json.Marshal(clean)
}
func stripHandles(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "handle")
		for _, v := range x {
			stripHandles(v)
		}
	case []any:
		for _, v := range x {
			stripHandles(v)
		}
	}
}
func (n *Network) installPolicy(ctx context.Context, policy string) error {
	// One transaction replaces only our own table. add is idempotent for an existing table.
	batch := "add table inet " + table + "\ndelete table inet " + table + "\n" + policy
	if _, err := Run(ctx, batch, "nft", "-f", "-"); err != nil {
		return err
	}
	fp, err := n.snapshot(ctx)
	if err != nil {
		return err
	}
	n.policy, n.fingerprint = policy, fp
	return nil
}
func (n *Network) Reconcile(ctx context.Context, s model.State) (bool, error) {
	w4, err := route(ctx, false)
	if err != nil {
		return false, err
	}
	n.WAN4 = w4
	if n.IPv6 {
		w6, e := route(ctx, true)
		if e != nil {
			return false, fmt.Errorf("IPv6 route disappeared; restart to re-detect connectivity")
		}
		n.WAN6 = w6
	}
	want := n.render(s)
	fp, err := n.snapshot(ctx)
	if err == nil && want == n.policy && bytes.Equal(fp, n.fingerprint) {
		up, linkErr := n.linkUp(ctx)
		if linkErr != nil {
			return false, linkErr
		}
		if !up {
			return true, n.Up(ctx)
		}
		return false, nil
	}
	if err = n.Down(ctx); err != nil {
		return false, err
	}
	if err = n.installPolicy(ctx, want); err != nil {
		return false, err
	}
	return true, n.Up(ctx)
}
func (n *Network) Healthy(ctx context.Context) error {
	up, err := n.linkUp(ctx)
	if err != nil {
		return err
	}
	if !up {
		return fmt.Errorf("VPN interface is down")
	}
	if _, err := Run(ctx, "", "awg", "show", Interface, "public-key"); err != nil {
		return err
	}
	fp, err := n.snapshot(ctx)
	if err != nil {
		return err
	}
	if !bytes.Equal(fp, n.fingerprint) {
		return fmt.Errorf("firewall integrity check failed")
	}
	return nil
}
func (n *Network) linkUp(ctx context.Context) (bool, error) {
	b, err := Run(ctx, "", "ip", "-j", "link", "show", "dev", Interface)
	if err != nil {
		return false, err
	}
	var links []struct {
		Flags []string `json:"flags"`
	}
	if err = json.Unmarshal(b, &links); err != nil {
		return false, err
	}
	if len(links) != 1 {
		return false, fmt.Errorf("VPN interface is missing")
	}
	for _, flag := range links[0].Flags {
		if flag == "UP" {
			return true, nil
		}
	}
	return false, nil
}
func unique(v []string) []string {
	sort.Strings(v)
	out := []string{}
	for _, x := range v {
		if len(out) == 0 || out[len(out)-1] != x {
			out = append(out, x)
		}
	}
	return out
}
func nftSet(b *strings.Builder, name, typ string, values []string, interval bool) {
	fmt.Fprintf(b, " set %s { type %s;", name, typ)
	if interval {
		b.WriteString(" flags interval;")
	}
	values = unique(values)
	if len(values) > 0 {
		fmt.Fprintf(b, " elements = { %s };", strings.Join(values, ", "))
	}
	b.WriteString(" }\n")
}
func (n *Network) render(s model.State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	h4, g4, h6, g6 := []string{}, []string{}, []string{}, []string{}
	for _, p := range s.Peers {
		if !p.Enabled {
			continue
		}
		if p.Group == "home" {
			h4 = append(h4, p.Address4())
			h6 = append(h6, p.Address6())
		} else {
			g4 = append(g4, p.Address4())
			g6 = append(g6, p.Address6())
		}
	}
	nftSet(&b, "home4", "ipv4_addr", h4, false)
	nftSet(&b, "guest4", "ipv4_addr", g4, false)
	nftSet(&b, "active4", "ipv4_addr", append(append([]string{}, h4...), g4...), false)
	nftSet(&b, "protected4", "ipv4_addr", n.protected4, false)
	nftSet(&b, "private4", "ipv4_addr", []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}, true)
	if n.IPv6 {
		nftSet(&b, "home6", "ipv6_addr", h6, false)
		nftSet(&b, "guest6", "ipv6_addr", g6, false)
		nftSet(&b, "active6", "ipv6_addr", append(append([]string{}, h6...), g6...), false)
		nftSet(&b, "protected6", "ipv6_addr", n.protected6, false)
		nftSet(&b, "private6", "ipv6_addr", []string{"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}, true)
	}
	ports := []string{strconv.Itoa(n.Config.PanelPort)}
	if n.Config.ExternalBind != "" {
		_, p, _ := net.SplitHostPort(n.Config.ExternalBind)
		ports = append(ports, p)
	}
	portSet := "{ " + strings.Join(unique(ports), ", ") + " }"
	b.WriteString(" chain input { type filter hook input priority -20; policy accept;\n")
	// All traffic from guest/unknown tunnel addresses to any local socket is denied.
	b.WriteString("  iifname \"awg0\" ip saddr @home4 accept\n")
	if n.IPv6 {
		b.WriteString("  iifname \"awg0\" ip6 saddr @home6 accept\n")
	}
	b.WriteString("  iifname \"awg0\" drop\n  iifname \"lo\" accept\n")
	// The VPN address is never an external administration endpoint.
	fmt.Fprintf(&b, "  ip daddr 10.8.0.1 tcp dport %s drop\n", portSet)
	if n.IPv6 {
		fmt.Fprintf(&b, "  ip6 daddr fd42:8::1 tcp dport %s drop\n", portSet)
	}
	if n.Config.ExternalBind == "" {
		fmt.Fprintf(&b, "  tcp dport %s drop\n", portSet)
	} else {
		host, p, _ := net.SplitHostPort(n.Config.ExternalBind)
		match := "meta nfproto ipv4"
		if host != "0.0.0.0" {
			match = "ip daddr " + host
		}
		fmt.Fprintf(&b, "  iifname %q %s tcp dport %s accept\n  tcp dport %s drop\n", n.WAN4, match, p, portSet)
	}
	b.WriteString(" }\n chain forward { type filter hook forward priority -20; policy accept;\n")
	b.WriteString("  iifname \"awg0\" ip saddr != @active4 drop\n  oifname \"awg0\" ip daddr != @active4 drop\n")
	if n.IPv6 {
		b.WriteString("  iifname \"awg0\" ip6 saddr != @active6 drop\n  oifname \"awg0\" ip6 daddr != @active6 drop\n")
	} else {
		b.WriteString("  iifname \"awg0\" meta nfproto ipv6 drop\n  oifname \"awg0\" meta nfproto ipv6 drop\n")
	}
	b.WriteString("  iifname \"awg0\" ip saddr @guest4 ip daddr @private4 drop\n  iifname \"awg0\" ip saddr @guest4 ip daddr @protected4 drop\n")
	fmt.Fprintf(&b, "  iifname \"awg0\" ip saddr @guest4 tcp dport %s drop\n", portSet)
	if n.IPv6 {
		b.WriteString("  iifname \"awg0\" ip6 saddr @guest6 ip6 daddr @private6 drop\n  iifname \"awg0\" ip6 saddr @guest6 ip6 daddr @protected6 drop\n")
		fmt.Fprintf(&b, "  iifname \"awg0\" ip6 saddr @guest6 tcp dport %s drop\n", portSet)
	}
	b.WriteString("  iifname \"awg0\" oifname \"awg0\" ip saddr @home4 ip daddr @home4 accept\n")
	if n.IPv6 {
		b.WriteString("  iifname \"awg0\" oifname \"awg0\" ip6 saddr @home6 ip6 daddr @home6 accept\n")
	}
	b.WriteString("  iifname \"awg0\" oifname \"awg0\" drop\n")
	fmt.Fprintf(&b, "  iifname \"awg0\" oifname %q ip saddr @active4 accept\n  iifname %q oifname \"awg0\" ip daddr @active4 ct state established,related accept\n", n.WAN4, n.WAN4)
	if n.IPv6 {
		fmt.Fprintf(&b, "  iifname \"awg0\" oifname %q ip6 saddr @active6 accept\n  iifname %q oifname \"awg0\" ip6 daddr @active6 ct state established,related accept\n", n.WAN6, n.WAN6)
	}
	b.WriteString("  iifname \"awg0\" drop\n  oifname \"awg0\" drop\n }\n chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "  oifname %q ip saddr 10.8.0.0/24 masquerade\n", n.WAN4)
	if n.IPv6 {
		fmt.Fprintf(&b, "  oifname %q ip6 saddr fd42:8::/64 masquerade\n", n.WAN6)
	}
	b.WriteString(" }\n}\n")
	return b.String()
}

package model

import (
	"fmt"
	"net/netip"
)

type ClientSettings struct {
	DNS                 []string `json:"dns"`
	MTU                 int      `json:"mtu"`
	PersistentKeepalive int      `json:"persistentKeepalive"`
	AllowedIPs          []string `json:"allowedIPs"`
}

type Settings struct {
	Revision   int64          `json:"revision"`
	ServerName string         `json:"serverName"`
	Client     ClientSettings `json:"client"`
}

func DefaultSettings(ipv6 bool) Settings {
	c := ClientSettings{DNS: []string{"1.1.1.1", "9.9.9.9"}, MTU: 1280, PersistentKeepalive: 25, AllowedIPs: []string{"0.0.0.0/0"}}
	if ipv6 {
		c.DNS[1] = "2606:4700:4700::1111"
		c.AllowedIPs = append(c.AllowedIPs, "::/0")
	}
	return Settings{Revision: 1, ServerName: "AWG Panel", Client: c}
}
func (c ClientSettings) Clone() ClientSettings {
	c.DNS = append([]string{}, c.DNS...)
	c.AllowedIPs = append([]string{}, c.AllowedIPs...)
	return c
}
func (c ClientSettings) Validate() error {
	if len(c.DNS) < 1 || len(c.DNS) > 2 {
		return fmt.Errorf("provide one or two DNS IP addresses")
	}
	seen := map[netip.Addr]bool{}
	for _, value := range c.DNS {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || seen[ip] {
			return fmt.Errorf("DNS must contain distinct IPv4 or IPv6 addresses")
		}
		seen[ip] = true
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return fmt.Errorf("client MTU must be between 1280 and 9000")
	}
	if c.PersistentKeepalive < 0 || c.PersistentKeepalive > 65535 {
		return fmt.Errorf("keepalive must be between 0 and 65535 seconds")
	}
	if len(c.AllowedIPs) < 1 || len(c.AllowedIPs) > 64 {
		return fmt.Errorf("provide between 1 and 64 client routes")
	}
	routes := map[netip.Prefix]bool{}
	for _, value := range c.AllowedIPs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || routes[prefix] {
			return fmt.Errorf("routes must be distinct network CIDRs, for example 10.8.0.0/24")
		}
		routes[prefix] = true
	}
	return nil
}
func (s Settings) Validate() error {
	if s.Revision < 1 {
		return fmt.Errorf("invalid settings revision")
	}
	if err := ValidateNameGroup(s.ServerName, "home"); err != nil {
		return fmt.Errorf("server name: %w", err)
	}
	return s.Client.Validate()
}

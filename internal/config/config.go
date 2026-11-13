package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Host, Password, DataDir, WebDir, IPv6Mode, ExternalBind, PublicOrigin string
	Port, PanelPort                                                       int
	TrustedProxies                                                        []netip.Prefix
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	c := Config{Host: os.Getenv("AWG_HOST"), Password: os.Getenv("AWG_PASSWORD"), DataDir: env("AWG_DATA_DIR", "/data"), WebDir: env("AWG_WEB_DIR", "/app/web"), IPv6Mode: env("AWG_IPV6_MODE", "auto"), ExternalBind: os.Getenv("AWG_EXTERNAL_PANEL_BIND"), PublicOrigin: os.Getenv("AWG_PUBLIC_ORIGIN")}
	if path := os.Getenv("AWG_PASSWORD_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("cannot read AWG_PASSWORD_FILE: %w", err)
		}
		c.Password = strings.TrimSuffix(string(b), "\n")
	}
	var err error
	if c.Port, err = port(env("AWG_PORT", "51820")); err != nil {
		return c, err
	}
	if c.PanelPort, err = port(env("AWG_PANEL_PORT", "8881")); err != nil {
		return c, err
	}
	if len(c.Password) < 12 || len(c.Password) > 256 {
		return c, fmt.Errorf("AWG_PASSWORD must contain 12 to 256 bytes")
	}
	if !ValidHost(c.Host) {
		return c, fmt.Errorf("AWG_HOST must be a domain name or an IP address without a port")
	}
	if c.IPv6Mode != "auto" && c.IPv6Mode != "nat66" && c.IPv6Mode != "disabled" {
		return c, fmt.Errorf("AWG_IPV6_MODE must be auto, nat66 or disabled")
	}
	if c.ExternalBind != "" {
		h, p, e := net.SplitHostPort(c.ExternalBind)
		if e != nil {
			return c, fmt.Errorf("invalid AWG_EXTERNAL_PANEL_BIND")
		}
		ip, e := netip.ParseAddr(h)
		if e != nil || !ip.Is4() || ip.IsLoopback() || ip.IsMulticast() || netip.MustParsePrefix("10.8.0.0/24").Contains(ip) {
			return c, fmt.Errorf("external bind must use a bridge IPv4 address or 0.0.0.0")
		}
		parsedPort, e := port(p)
		if e != nil {
			return c, e
		}
		c.ExternalBind = net.JoinHostPort(h, strconv.Itoa(parsedPort))
	}
	if c.PublicOrigin != "" {
		if !regexp.MustCompile(`^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$`).MatchString(c.PublicOrigin) {
			return c, fmt.Errorf("AWG_PUBLIC_ORIGIN must be an HTTPS origin without a path")
		}
	}
	for _, v := range strings.Split(os.Getenv("AWG_TRUSTED_PROXIES"), ",") {
		if strings.TrimSpace(v) == "" {
			continue
		}
		p, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil {
			return c, fmt.Errorf("invalid AWG_TRUSTED_PROXIES CIDR")
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	return c, nil
}

func port(s string) (int, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return n, nil
}

func ValidHost(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast()
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`).MatchString(label) {
			return false
		}
	}
	return true
}

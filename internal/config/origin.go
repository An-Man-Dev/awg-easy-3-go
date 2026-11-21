package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Empty means VPN/loopback access only. Public panels must use HTTPS.
func PublicOrigin(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	bad := fmt.Errorf("panel address must be an HTTPS origin without credentials, path, query or fragment")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || !ValidHost(u.Hostname()) {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if u.Port() != "" {
		p, e := port(u.Port())
		if e != nil {
			return "", bad
		}
		if p != 443 {
			host = net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(p))
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", bad
	}
	return "https://" + host, nil
}

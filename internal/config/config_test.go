package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationValidationAndSecretFile(t *testing.T) {
	for _, key := range []string{"AWG_PASSWORD_FILE", "AWG_EXTERNAL_PANEL_BIND", "AWG_PUBLIC_ORIGIN", "AWG_TRUSTED_PROXIES"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWG_HOST", "vpn.example.com")
	t.Setenv("AWG_PASSWORD", "test-password-long-enough")
	t.Setenv("AWG_PORT", "51820")
	t.Setenv("AWG_PANEL_PORT", "8881")
	t.Setenv("AWG_IPV6_MODE", "disabled")
	t.Setenv("AWG_EXTERNAL_PANEL_BIND", "0.0.0.0:08881")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ExternalBind != "0.0.0.0:8881" {
		t.Fatal("bind port was not normalized")
	}
	secret := filepath.Join(t.TempDir(), "password")
	if err = os.WriteFile(secret, []byte("secret-from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWG_PASSWORD_FILE", secret)
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Password != "secret-from-file" {
		t.Fatal("secret file did not override environment")
	}
	t.Setenv("AWG_EXTERNAL_PANEL_BIND", "10.8.0.1:8881")
	if _, err = Load(); err == nil {
		t.Fatal("VPN address accepted as external bind")
	}
}
func TestHostValidation(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "192.0.2.1", "2001:db8::1"} {
		if !ValidHost(host) {
			t.Errorf("valid host rejected: %s", host)
		}
	}
	for _, host := range []string{"", "a\nPostUp=bad", "https://vpn.example.com", "foo:8881", "-bad.example", "fe80::1%eth0", "0.0.0.0"} {
		if ValidHost(host) {
			t.Errorf("invalid host accepted: %q", host)
		}
	}
}

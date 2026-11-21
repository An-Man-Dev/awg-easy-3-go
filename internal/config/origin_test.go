package config

import "testing"

func TestPublicOrigin(t *testing.T) {
	for raw, want := range map[string]string{"": "", "https://Panel.Example:443": "https://panel.example", "https://192.0.2.1:8443": "https://192.0.2.1:8443", "https://[2001:db8::1]:443": "https://[2001:db8::1]"} {
		got, err := PublicOrigin(raw)
		if err != nil || got != want {
			t.Fatalf("valid origin rejected: %s", raw)
		}
	}
	for _, raw := range []string{"http://panel.example", "https://panel.example/", "https://panel.example?", "https://panel.example#", "https://user@panel.example", "https://panel.example:0", "https://panel.example:65536", "https://panel.example:", "https://[fe80::1%25eth0]", "https://0.0.0.0", "https://panel.example/path", "https://panel.example?x=1", "https://panel.example\n"} {
		if _, err := PublicOrigin(raw); err == nil {
			t.Fatalf("invalid origin accepted: %q", raw)
		}
	}
}

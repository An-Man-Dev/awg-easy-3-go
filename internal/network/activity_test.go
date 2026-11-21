package network

import (
	"strings"
	"testing"
	"time"
)

func TestParseHandshakes(t *testing.T) {
	key := strings.Repeat("A", 43) + "="
	now := time.Unix(1000, 0)
	for _, value := range []string{key + "\t999\n", key + "\t0\n", ""} {
		if _, err := parseHandshakes(value, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{key + " -1", key + " 1006", key + " x", key + " 999 extra", "invalid 999", key + " 0\n" + key + " 1"} {
		if _, err := parseHandshakes(value, now); err == nil {
			t.Fatal("invalid sample accepted")
		}
	}
}

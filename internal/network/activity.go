package network

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Query only public keys and timestamps; never use `awg show ... dump`, which includes secrets.
func (n *Network) LatestHandshakes(ctx context.Context) (map[string]time.Time, error) {
	data, err := Run(ctx, "", "awg", "show", Interface, "latest-handshakes")
	if err != nil {
		return nil, err
	}
	return parseHandshakes(string(data), time.Now())
}
func parseHandshakes(data string, now time.Time) (map[string]time.Time, error) {
	result := map[string]time.Time{}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid handshake response")
		}
		key, err := base64.StdEncoding.DecodeString(fields[0])
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid handshake key")
		}
		if _, exists := result[fields[0]]; exists {
			return nil, fmt.Errorf("duplicate handshake key")
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || seconds < 0 || seconds > now.Unix()+5 {
			return nil, fmt.Errorf("invalid handshake time")
		}
		var last time.Time
		if seconds != 0 {
			last = time.Unix(seconds, 0).UTC()
		}
		result[fields[0]] = last
	}
	return result, nil
}

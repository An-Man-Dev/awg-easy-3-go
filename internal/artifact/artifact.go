package artifact

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
)

func Profile(p map[string]string) string {
	var b strings.Builder
	for _, k := range model.Fields {
		if v := p[k]; v != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	return b.String()
}
func Server(s model.State, c config.Config, v6 bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n%s", s.PrivateKey, c.Port, Profile(s.Profile))
	for _, p := range s.Peers {
		if p.Enabled {
			fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", p.PublicKey, p.PresharedKey, p.Addresses(v6))
		}
	}
	return b.String()
}
func routes(v6 bool) []string {
	if v6 {
		return []string{"0.0.0.0/0", "::/0"}
	}
	return []string{"0.0.0.0/0"}
}
func dns(v6 bool) []string {
	if v6 {
		return []string{"1.1.1.1", "2606:4700:4700::1111"}
	}
	return []string{"1.1.1.1", "9.9.9.9"}
}
func Client(s model.State, p model.Peer, c config.Config, v6 bool) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = 1280\n%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\nEndpoint = %s\n", p.PrivateKey, p.Addresses(v6), strings.Join(dns(v6), ", "), Profile(s.Profile), s.PublicKey, p.PresharedKey, strings.Join(routes(v6), ", "), net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
}
func Link(s model.State, p model.Peer, c config.Config, v6 bool) (string, error) {
	inner := map[string]any{"hostName": c.Host, "port": c.Port, "client_ip": p.Addresses(v6), "client_priv_key": p.PrivateKey, "client_pub_key": p.PublicKey, "server_pub_key": s.PublicKey, "clientId": p.PublicKey, "psk_key": p.PresharedKey, "allowed_ips": routes(v6), "persistent_keep_alive": "25", "mtu": "1280", "config": Client(s, p, c, v6), "transport_proto": "udp", "isObfuscationEnabled": true}
	for _, k := range model.Fields {
		if v := s.Profile[k]; v != "" {
			inner[k] = v
		}
	}
	ib, err := json.Marshal(inner)
	if err != nil {
		return "", err
	}
	protocol := map[string]any{"isThirdPartyConfig": true, "port": strconv.Itoa(c.Port), "protocol_version": "3.1", "transport_proto": "udp", "last_config": string(ib)}
	for _, k := range model.Fields {
		if v := s.Profile[k]; v != "" {
			protocol[k] = v
		}
	}
	payload := map[string]any{"description": p.Name, "hostName": c.Host, "defaultContainer": "amnezia-awg", "dns1": dns(v6)[0], "dns2": dns(v6)[1], "containers": []any{map[string]any{"container": "amnezia-awg", "awg": protocol}}}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err = binary.Write(&out, binary.BigEndian, uint32(len(b))); err != nil {
		return "", err
	}
	z, err := zlib.NewWriterLevel(&out, 8)
	if err != nil {
		return "", err
	}
	if _, err = z.Write(b); err != nil {
		return "", err
	}
	if err = z.Close(); err != nil {
		return "", err
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(out.Bytes()), nil
}

// QRChunks uses AmneziaVPN's QDataStream framing, which differs from a vpn://
// clipboard link: int16 magic, uint8 count, uint8 index, then QByteArray
// (uint32 length + bytes), all big-endian and base64url encoded without padding.
// The official exporter splits the Qt-compressed configuration every 850 bytes.
func QRChunks(link string) ([]string, error) {
	if !strings.HasPrefix(link, "vpn://") {
		return nil, fmt.Errorf("invalid connection link")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "vpn://"))
	if err != nil || len(data) < 5 {
		return nil, fmt.Errorf("invalid compressed connection data")
	}
	const chunkSize = 850
	count := (len(data) + chunkSize - 1) / chunkSize
	if count > 255 {
		return nil, fmt.Errorf("configuration is too large for QR export")
	}
	chunks := make([]string, 0, count)
	for start := 0; start < len(data); start += chunkSize {
		end := min(start+chunkSize, len(data))
		frame := make([]byte, 8+end-start)
		binary.BigEndian.PutUint16(frame[:2], 1984)
		frame[2], frame[3] = byte(count), byte(start/chunkSize)
		binary.BigEndian.PutUint32(frame[4:8], uint32(end-start))
		copy(frame[8:], data[start:end])
		chunks = append(chunks, base64.RawURLEncoding.EncodeToString(frame))
	}
	return chunks, nil
}

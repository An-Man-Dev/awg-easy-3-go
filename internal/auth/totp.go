package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 4226 / RFC 6238: SHA-1, six digits, 30-second periods. SHA-1 is
// required for authenticator interoperability here, not used as a password hash.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
func hotp(secret []byte, step int64, digits int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(b[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	number := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	divisor := uint32(1000000)
	if digits == 8 {
		divisor = 100000000
	}
	return fmt.Sprintf("%0*d", digits, number%divisor)
}
func MatchTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) != 20 {
		return 0, false
	}
	step := now.Unix() / 30
	match := int64(-1)
	for delta := int64(-1); delta <= 1; delta++ {
		candidate := step + delta
		if candidate >= 0 && candidate > last && subtle.ConstantTimeCompare([]byte(hotp(key, candidate, 6)), []byte(code)) == 1 {
			match = candidate
		}
	}
	return match, match >= 0
}
func TOTPURI(secret, login string) string {
	q := url.Values{"secret": {secret}, "issuer": {"AWG Panel"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("AWG Panel:"+login) + "?" + q.Encode()
}
func RecoveryCodes() (plain []string, err error) {
	for i := 0; i < 10; i++ {
		b := make([]byte, 16)
		if _, err = rand.Read(b); err != nil {
			return nil, err
		}
		v := hex.EncodeToString(b)
		plain = append(plain, v[:8]+"-"+v[8:16]+"-"+v[16:24]+"-"+v[24:])
	}
	return
}
func RecoveryHash(account, code string) ([]byte, bool) {
	value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(value) != 32 {
		return nil, false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte("awg-panel/recovery/v1:" + account + ":" + value))
	return sum[:], true
}

type SecretBox struct{ cipher.AEAD }

func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("TOTP encryption key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead}, nil
}
func (b *SecretBox) Encrypt(account, secret string) ([]byte, error) {
	nonce := make([]byte, b.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{1}, nonce...)
	return b.Seal(out, nonce, []byte(secret), []byte("awg-panel/totp/v1:"+account)), nil
}
func (b *SecretBox) Decrypt(account string, sealed []byte) (string, error) {
	if len(sealed) < 1+b.NonceSize()+b.Overhead() || sealed[0] != 1 {
		return "", fmt.Errorf("invalid encrypted TOTP secret")
	}
	plain, err := b.Open(nil, sealed[1:1+b.NonceSize()], sealed[1+b.NonceSize():], []byte("awg-panel/totp/v1:"+account))
	if err != nil {
		return "", fmt.Errorf("TOTP secret cannot be decrypted")
	}
	return string(plain), nil
}

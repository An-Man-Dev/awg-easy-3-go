// Package auth provides credentials independent of the VPN protocol.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

const passwordPrefix = "pbkdf2-sha256$600000$"

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", fmt.Errorf("password must contain 12 to 256 bytes")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return "", err
	}
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

func ValidPasswordHash(encoded string) bool {
	_, _, ok := decodeHash(encoded)
	return ok
}

func decodeHash(encoded string) ([]byte, []byte, bool) {
	if !strings.HasPrefix(encoded, passwordPrefix) {
		return nil, nil, false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if len(parts) != 2 {
		return nil, nil, false
	}
	salt, e1 := base64.RawStdEncoding.Strict().DecodeString(parts[0])
	hash, e2 := base64.RawStdEncoding.Strict().DecodeString(parts[1])
	return salt, hash, e1 == nil && e2 == nil && len(salt) == 32 && len(hash) == 32
}

func VerifyPassword(encoded, password string) bool {
	salt, expected, ok := decodeHash(encoded)
	if !ok || len(password) > 256 {
		return false
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	return err == nil && subtle.ConstantTimeCompare(hash, expected) == 1
}

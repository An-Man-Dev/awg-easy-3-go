package auth

import (
	"bytes"
	"encoding/base32"
	"testing"
	"time"
)

func TestRFC4226And6238Vectors(t *testing.T) {
	// Published vectors: https://www.rfc-editor.org/rfc/rfc4226#appendix-D
	// and https://www.rfc-editor.org/rfc/rfc6238#appendix-B .
	key := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(key, int64(i), 6); got != want {
			t.Fatalf("HOTP counter %d: %s", i, got)
		}
	}
	for _, v := range []struct {
		at   int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if hotp(key, v.at/30, 8) != v.code {
			t.Fatal("RFC TOTP vector failed", v.at)
		}
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	for _, at := range []int64{30, 59, 60, 89} {
		if _, ok := MatchTOTP(secret, "287082", time.Unix(at, 0), -1); !ok {
			t.Fatal("valid code rejected", at)
		}
	}
	for _, at := range []int64{90, 120} {
		if _, ok := MatchTOTP(secret, "287082", time.Unix(at, 0), -1); ok {
			t.Fatal("excess clock drift accepted")
		}
	}
	if _, ok := MatchTOTP(secret, "287082", time.Unix(59, 0), 1); ok {
		t.Fatal("replay accepted")
	}
	for _, bad := range []string{"28708", "2870820", "28x082", " 287082", "287082\n"} {
		if _, ok := MatchTOTP(secret, bad, time.Unix(59, 0), -1); ok {
			t.Fatal("malformed OTP accepted")
		}
	}
}
func TestSecretBoxAccountBindingAndRecoveryEntropy(t *testing.T) {
	box, err := NewSecretBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Encrypt("account-one", "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = box.Decrypt("account-two", sealed); err == nil {
		t.Fatal("secret transplanted across owners")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err = box.Decrypt("account-one", sealed); err == nil {
		t.Fatal("tamper accepted")
	}
	codes, err := RecoveryCodes()
	if err != nil || len(codes) != 10 {
		t.Fatal("code generation failed")
	}
	seen := map[string]bool{}
	for _, code := range codes {
		a, ok := RecoveryHash("one", code)
		b, _ := RecoveryHash("two", code)
		if !ok || len(a) != 32 || bytes.Equal(a, b) || seen[code] {
			t.Fatal("invalid recovery material")
		}
		seen[code] = true
	}
}

package auth

import "testing"

func TestPasswordVerification(t *testing.T) {
	password := "correct-horse-battery-staple"
	a, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("password salts reused")
	}
	if !VerifyPassword(a, password) || VerifyPassword(a, "incorrect") {
		t.Fatal("incorrect verification")
	}
	for _, bad := range []string{"", "pbkdf2-sha256$999999999999$bad$bad", a + "$extra"} {
		if VerifyPassword(bad, password) {
			t.Fatal("malformed hash accepted")
		}
	}
	if _, err = HashPassword("short"); err == nil {
		t.Fatal("short bootstrap password accepted")
	}
}

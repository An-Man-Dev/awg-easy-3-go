package model

import "testing"

func TestSettingsValidation(t *testing.T) {
	for _, change := range []func(*Settings){
		func(s *Settings) { s.ServerName = "bad\nname" },
		func(s *Settings) { s.Client.DNS = []string{"1.1.1.1\nPostUp=bad"} },
		func(s *Settings) { s.Client.DNS = []string{"1.1.1.1", "1.1.1.1"} },
		func(s *Settings) { s.Client.MTU = 1279 },
		func(s *Settings) { s.Client.PersistentKeepalive = -1 },
		func(s *Settings) { s.Client.AllowedIPs = []string{"10.8.0.2/24"} },
		func(s *Settings) { s.Client.AllowedIPs = nil },
	} {
		s := DefaultSettings(true)
		change(&s)
		if s.Validate() == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	s := DefaultSettings(false)
	s.Client.DNS = []string{"9.9.9.9"}
	s.Client.PersistentKeepalive = 0
	s.Client.AllowedIPs = []string{"10.8.0.0/24"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

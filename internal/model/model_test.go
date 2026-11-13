package model

import "testing"

func TestGeneratedStateAndValidation(t *testing.T) {
	s, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	if err = Validate(s); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*State){
		"unknown field":        func(s *State) { s.Profile["PostUp"] = "touch /tmp/unwanted" },
		"negative signature":   func(s *State) { s.Profile["I1"] = "<r -1>" },
		"oversized signature":  func(s *State) { s.Profile["I1"] = "<r 1280><r 1>" },
		"line injection":       func(s *State) { s.Profile["I1"] = "<r 32>\n[Peer]" },
		"overlapping headers":  func(s *State) { s.Profile["H2"] = s.Profile["H1"] },
		"short header padding": func(s *State) { s.Profile["S4"] = "8" },
		"reversed range":       func(s *State) { s.Profile["RekeyTimeout"] = "7-3" },
		"invalid header key":   func(s *State) { s.Profile["HeaderProtectionKey"] = "bad" },
		"no home":              func(s *State) { s.Peers[0].Group = "guest" },
		"duplicate IP":         func(s *State) { p, _ := NewPeer("Duplicate", "guest", 2); s.Peers = append(s.Peers, p) },
		"mismatched keys":      func(s *State) { s.Peers[0].PublicKey = s.PublicKey },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := NewState()
			if err != nil {
				t.Fatal(err)
			}
			change(&s)
			if Validate(s) == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
}

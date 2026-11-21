package service

import (
	"strings"
	"testing"

	"awg-panel/internal/artifact"
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
)

func TestDeviceWithoutStoredPrivateKeyStillRendersServer(t *testing.T) {
	state, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	private := state.Peers[0].PrivateKey
	state.Peers[0].PrivateKey = ""
	if err = model.Validate(state); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Host: "vpn.example.com", Port: 51820}
	server := artifact.Server(state, c, false)
	if strings.Contains(server, private) || !strings.Contains(server, state.Peers[0].PublicKey) || !strings.Contains(server, state.Peers[0].PresharedKey) {
		t.Fatal("server needs client secret or lost public credentials")
	}
	s := Service{State: state, Config: c, Network: &network.Network{}}
	for _, link := range []bool{false, true} {
		if _, err = s.Export(state.Peers[0].ID, link); err == nil {
			t.Fatal("incomplete client profile exported")
		}
	}
}

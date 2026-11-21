package service

import (
	"awg-panel/internal/model"
	"awg-panel/internal/portable"
	"awg-panel/internal/store"
	"context"
	"errors"
	"fmt"
	"time"
)

func (s *Service) requirements() portable.Requirements {
	return portable.Requirements{Protocol: "amneziawg3", UDPPort: s.Config.Port, PanelPort: s.Config.PanelPort, IPv6: s.Network.IPv6, Subnet4: "10.8.0.0/24", Subnet6: "fd42:8::/64"}
}
func (s *Service) ExportArchive(include bool, mode, secret string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return nil, fmt.Errorf("service is stopping")
	}
	snap, err := s.Store.Snapshot()
	if err != nil {
		return nil, err
	}
	snap.Requirements = s.requirements()
	snap.ClientKeysIncluded = include
	if !include {
		for i := range snap.State.Peers {
			snap.State.Peers[i].PrivateKey = ""
		}
	}
	return portable.Encrypt(snap, mode, secret)
}
func (s *Service) CheckImport(in portable.Snapshot) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return "", fmt.Errorf("service is stopping")
	}
	if err := in.Validate(); err != nil {
		return "", err
	}
	if in.Requirements != s.requirements() {
		return "", fmt.Errorf("protocol, UDP/panel ports, VPN subnets and effective IPv6 must match this server")
	}
	return s.Store.ImportFingerprint()
}
func (s *Service) ImportArchive(ctx context.Context, in portable.Snapshot, fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("service is stopping")
	}
	if in.Requirements != s.requirements() {
		return fmt.Errorf("server requirements changed; preview the archive again")
	}
	if err := in.Validate(); err != nil {
		return err
	}
	nextConfig := s.Config
	nextConfig.Host = in.State.Addresses.VPNHost
	nextConfig.PublicOrigin = in.State.Addresses.PanelOrigin
	apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	prepared, err := s.Network.PrepareAddresses(apply, nextConfig)
	if err != nil {
		return fmt.Errorf("cannot resolve imported server addresses; no data changed")
	}
	oldNetwork := *s.Network
	touched := false
	next, err := s.Store.Import(apply, in, fingerprint, func(state model.State) error { touched = true; return s.Network.ApplyAddresses(apply, state, prepared) })
	if err != nil {
		if errors.Is(err, store.ErrImportCommit) {
			s.fail(err)
			return err
		}
		if touched {
			restore, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			if e := s.Network.ApplyAddresses(restore, s.State, &oldNetwork); e != nil {
				s.fail(e)
				return fmt.Errorf("import failed; service is restarting with the previous database")
			}
			return fmt.Errorf("network apply failed; initial database and network restored")
		}
		return err
	}
	s.State = next
	s.Config = nextConfig
	s.observations = map[string]time.Time{}
	s.liveHandshakes = map[string]time.Time{}
	s.observedAt = time.Time{}
	s.observationOK = false
	return nil
}

func (s *Service) TransferInfo() (portable.Requirements, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requirements(), !s.failed && s.Store.ImportAvailable()
}

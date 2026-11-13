package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"awg-panel/internal/artifact"
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
)

type Service struct {
	mu      sync.Mutex
	State   model.State
	Store   *store.Store
	Network *network.Network
	Config  config.Config
	Fatal   chan error
	failed  bool
}
type View struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Group     string    `json:"group"`
	Enabled   bool      `json:"enabled"`
	Address4  string    `json:"address4"`
	Address6  string    `json:"address6,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Service) List() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.State.Peers))
	for _, p := range s.State.Peers {
		v := View{ID: p.ID, Name: p.Name, Group: p.Group, Enabled: p.Enabled, Address4: p.Address4(), CreatedAt: p.CreatedAt}
		if s.Network.IPv6 {
			v.Address6 = p.Address6()
		}
		out = append(out, v)
	}
	return out
}
func (s *Service) Home(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.State.Peers {
		if p.Enabled && p.Group == "home" && (ip.String() == p.Address4() || (s.Network.IPv6 && ip.String() == p.Address6())) {
			return true
		}
	}
	return false
}
func (s *Service) fail(err error) {
	s.failed = true
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = s.Network.Down(ctx)
	select {
	case s.Fatal <- err:
	default:
	}
}
func (s *Service) Change(ctx context.Context, id, name, group string, enabled *bool, remove bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("network is unavailable")
	}
	next := s.State
	next.Peers = append([]model.Peer{}, s.State.Peers...)
	if id == "" {
		used := map[int]bool{}
		for _, p := range next.Peers {
			used[p.Slot] = true
		}
		slot := 2
		for slot <= 254 && used[slot] {
			slot++
		}
		if slot > 254 {
			return fmt.Errorf("address pool is full")
		}
		p, err := model.NewPeer(name, group, slot)
		if err != nil {
			return err
		}
		next.Peers = append(next.Peers, p)
	} else {
		found := false
		for i, p := range next.Peers {
			if p.ID != id {
				continue
			}
			found = true
			if remove {
				next.Peers = append(next.Peers[:i], next.Peers[i+1:]...)
			} else {
				if name != "" {
					p.Name = name
				}
				if group != "" {
					p.Group = group
				}
				if enabled != nil {
					p.Enabled = *enabled
				}
				next.Peers[i] = p
			}
			break
		}
		if !found {
			return fmt.Errorf("device not found")
		}
	}
	if err := model.Validate(next); err != nil {
		return err
	}
	// The durable state is authoritative. An ambiguous disk/apply failure stops VPN forwarding.
	if err := s.Store.Save(next); err != nil {
		s.fail(err)
		return fmt.Errorf("state could not be committed; service is stopping")
	}
	s.State = next
	apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.Network.Apply(apply, next); err != nil {
		s.fail(err)
		return fmt.Errorf("state was saved, but network apply failed; service is restarting")
	}
	return nil
}
func (s *Service) Export(id string, link bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.State.Peers {
		if p.ID == id {
			if link {
				return artifact.Link(s.State, p, s.Config, s.Network.IPv6)
			}
			return artifact.Client(s.State, p, s.Config, s.Network.IPv6), nil
		}
	}
	return "", fmt.Errorf("device not found")
}
func (s *Service) Healthy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("service is stopping")
	}
	return s.Network.Healthy(ctx)
}
func (s *Service) Watch(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			repaired, err := s.Network.Reconcile(ctx, s.State)
			if err != nil {
				s.fail(err)
			}
			s.mu.Unlock()
			if err != nil {
				return
			}
			if repaired {
				slog.Warn("Network policy restored")
			}
		}
	}
}

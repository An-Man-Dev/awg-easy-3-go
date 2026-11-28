package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/network"
	"awg-panel/internal/store"
)

type Service struct {
	mu             sync.Mutex
	applicationMu  sync.Mutex
	application    ApplicationStatus
	State          model.State
	Store          *store.Store
	Network        *network.Network
	Config         config.Config
	Fatal          chan error
	failed         bool
	observations   map[string]time.Time
	liveHandshakes map[string]time.Time
	observedAt     time.Time
	observationOK  bool
}
type View struct {
	OwnerID          string    `json:"ownerId"`
	AccountBlocked   bool      `json:"accountBlocked"`
	StoredPrivateKey bool      `json:"storedPrivateKey"`
	KeyVersion       string    `json:"keyVersion"`
	Activity         Activity  `json:"activity"`
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Group            string    `json:"group"`
	Enabled          bool      `json:"enabled"`
	Address4         string    `json:"address4"`
	Address6         string    `json:"address6,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
}

func (s *Service) List() []View {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]View, 0, len(s.State.Peers))
	for _, p := range s.State.Peers {
		v := View{OwnerID: p.OwnerID, AccountBlocked: p.AccountBlocked, ID: p.ID, Name: p.Name, Group: p.Group, Enabled: p.Enabled, Address4: p.Address4(), CreatedAt: p.CreatedAt, StoredPrivateKey: p.PrivateKey != "", KeyVersion: keyVersion(p), Activity: s.activity(p.ID, p.Enabled && !p.AccountBlocked, time.Now())}
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
		if p.Enabled && !p.AccountBlocked && p.Group == "home" && (ip.String() == p.Address4() || (s.Network.IPv6 && ip.String() == p.Address6())) {
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
	s.ApplicationFailed()
	select {
	case s.Fatal <- err:
	default:
	}
}
func (s *Service) Change(ctx context.Context, id, name, group string, enabled *bool, remove bool) error {
	return s.ChangeFor(ctx, model.BootstrapAccountID, id, name, group, enabled, remove)
}
func (s *Service) ChangeFor(ctx context.Context, actor, id, name, group string, enabled *bool, remove bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("network is unavailable")
	}
	if !s.canAccessDevice(actor, id) {
		return ErrAccess
	}
	next := s.State
	next.Peers = append([]model.Peer{}, s.State.Peers...)
	if id == "" {
		return fmt.Errorf("use device issuance to create a device")
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
	action := "device.update"
	if remove {
		action = "device.delete"
	}
	return s.commitPeers(ctx, next, store.AuditRecord{Actor: actor, Action: action, Target: id})
}

// Caller holds mu. Device identity and secret removal are one SQLite transaction.
func (s *Service) commitPeers(ctx context.Context, next model.State, audit store.AuditRecord) error {
	if err := model.Validate(next); err != nil {
		return err
	}
	if err := reachableHome(next); err != nil {
		return err
	}
	s.ApplicationStarted()
	if err := s.Store.SaveAudited(next, audit); err != nil {
		s.fail(err)
		return fmt.Errorf("state could not be committed; service is stopping")
	}
	for _, old := range s.State.Peers {
		unchanged := false
		for _, p := range next.Peers {
			if p.ID == old.ID && p.PublicKey == old.PublicKey {
				unchanged = true
				break
			}
		}
		if !unchanged {
			delete(s.observations, old.ID)
			delete(s.liveHandshakes, old.ID)
		}
	}
	s.State = next
	s.observationOK = false
	apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.Network.Apply(apply, next); err != nil {
		s.fail(err)
		return fmt.Errorf("state saved but network apply failed; service is restarting")
	}
	s.ApplicationApplied()
	return nil
}

type ExportSnapshot struct {
	Config  string `json:"config"`
	Link    string `json:"link"`
	Version string `json:"version"`
}

func (s *Service) ExportSnapshot(id string) (ExportSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ExportSnapshot{}, fmt.Errorf("service is stopping")
	}
	for _, p := range s.State.Peers {
		if p.ID != id {
			continue
		}
		if p.PrivateKey == "" {
			return ExportSnapshot{}, fmt.Errorf("client private key is not stored; configuration cannot be exported")
		}
		return s.snapshot(p)
	}
	return ExportSnapshot{}, fmt.Errorf("device not found")
}
func (s *Service) Export(id string, link bool) (string, error) {
	snapshot, err := s.ExportSnapshot(id)
	if err != nil {
		return "", err
	}
	if link {
		return snapshot.Link, nil
	}
	return snapshot.Config, nil
}
func (s *Service) Settings() model.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State.Settings == nil {
		return model.DefaultSettings(s.Network.IPv6)
	}
	result := *s.State.Settings
	result.Client = result.Client.Clone()
	return result
}
func (s *Service) UpdateSettings(next model.Settings) (model.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return model.Settings{}, fmt.Errorf("service is stopping")
	}
	if s.State.Settings == nil || next.Revision != s.State.Settings.Revision {
		return model.Settings{}, store.ErrSettingsConflict
	}
	if err := next.Validate(); err != nil {
		return model.Settings{}, err
	}
	expected := next.Revision
	next.Revision++
	next.Client = next.Client.Clone()
	if err := s.Store.SaveSettings(next, expected); err != nil {
		return model.Settings{}, err
	}
	s.State.Settings = &next
	result := next
	result.Client = result.Client.Clone()
	return result, nil
}
func (s *Service) Healthy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("service is stopping")
	}
	err := s.Network.Healthy(ctx)
	if err != nil {
		s.setApplication("error", false)
	} else if status := s.ApplicationStatus(); status.State == "error" && !status.Restarting {
		s.ApplicationApplied()
	}
	return err
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
			} else if repaired {
				s.ApplicationApplied()
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

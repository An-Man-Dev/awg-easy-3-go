package service

import (
	"awg-panel/internal/config"
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"context"
	"fmt"
	"time"
)

func (s *Service) Addresses() model.Addresses {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.State.Addresses
}
func (s *Service) UpdateAddresses(ctx context.Context, next model.Addresses) (model.Addresses, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return model.Addresses{}, fmt.Errorf("service is stopping")
	}
	if err := next.Validate(); err != nil {
		return model.Addresses{}, err
	}
	if next.Revision != s.State.Addresses.Revision {
		return model.Addresses{}, store.ErrSettingsConflict
	}
	next.PanelOrigin, _ = config.PublicOrigin(next.PanelOrigin)
	proposed := s.Config
	proposed.Host = next.VPNHost
	proposed.PublicOrigin = next.PanelOrigin
	apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	prepared, err := s.Network.PrepareAddresses(apply, proposed)
	if err != nil {
		return model.Addresses{}, fmt.Errorf("addresses could not be resolved; no changes saved")
	}
	s.ApplicationStarted()
	expected := next.Revision
	next.Revision++
	if err = s.Store.SaveAddresses(next, expected); err != nil {
		s.fail(err)
		return model.Addresses{}, fmt.Errorf("addresses could not be committed; service is stopping")
	}
	s.State.Addresses = &next
	s.Config = proposed
	s.observationOK = false
	if err = s.Network.ApplyAddresses(apply, s.State, prepared); err != nil {
		s.fail(err)
		return model.Addresses{}, fmt.Errorf("addresses saved but network apply failed; service is restarting")
	}
	s.ApplicationApplied()
	return next, nil
}

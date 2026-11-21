package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const ActivityInterval = 15 * time.Second
const ActivityFreshness = 45 * time.Second
const OnlineWindow = 3 * time.Minute

type Activity struct {
	Status        string     `json:"status"`
	LastHandshake *time.Time `json:"lastHandshake,omitempty"`
	ObservedAt    *time.Time `json:"observedAt,omitempty"`
}

func (s *Service) LoadObservations() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	s.observations, err = s.Store.Observations()
	return err
}
func (s *Service) activity(id string, enabled bool, now time.Time) Activity {
	a := Activity{Status: "unavailable"}
	if last := s.observations[id]; !last.IsZero() {
		a.LastHandshake = &last
	}
	if !s.observedAt.IsZero() {
		last := s.observedAt
		a.ObservedAt = &last
	}
	if !enabled {
		a.Status = "disabled"
		return a
	}
	if !s.observationOK || s.failed || now.Before(s.observedAt) || now.Sub(s.observedAt) > ActivityFreshness {
		return a
	}
	a.Status = "never"
	if a.LastHandshake != nil {
		a.Status = "offline"
	}
	last := s.liveHandshakes[id]
	if !last.IsZero() && !last.After(now.Add(5*time.Second)) && now.Sub(last) <= OnlineWindow {
		a.Status = "online"
	}
	return a
}

// Called under the service lock, so peer changes cannot race a sample or its persistence.
func (s *Service) recordObservations(sample map[string]time.Time, now time.Time) error {
	s.observationOK = false
	changed := map[string]time.Time{}
	live := map[string]time.Time{}
	for _, p := range s.State.Peers {
		if !p.Enabled || p.AccountBlocked {
			continue
		}
		last, ok := sample[p.PublicKey]
		if !ok {
			return fmt.Errorf("handshake response is missing an enabled device")
		}
		live[p.ID] = last
		if last.After(s.observations[p.ID]) {
			changed[p.ID] = last
		}
	}
	if err := s.Store.SaveObservations(changed); err != nil {
		return err
	}
	if s.observations == nil {
		s.observations = map[string]time.Time{}
	}
	for id, last := range changed {
		s.observations[id] = last
	}
	s.liveHandshakes = live
	s.observedAt = now
	s.observationOK = true
	return nil
}
func (s *Service) Observe(ctx context.Context) {
	poll := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.failed {
			s.observationOK = false
			return
		}
		wasAvailable := s.observationOK
		sample, err := s.Network.LatestHandshakes(ctx)
		if err == nil {
			err = s.recordObservations(sample, time.Now().UTC())
		}
		if err != nil {
			// Observation failure does not stop VPN forwarding or erase historical dates.
			if wasAvailable {
				slog.Warn("Device activity is unavailable")
			}
			s.observationOK = false
		}
	}
	poll()
	ticker := time.NewTicker(ActivityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

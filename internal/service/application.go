package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"awg-panel/internal/store"
)

// Operational state is not configuration and is excluded from transfer archives.
// Persist only timestamps, never command output, addresses, or credentials.
type ApplicationStatus struct {
	State       string    `json:"state"`
	UpdatedAt   time.Time `json:"updatedAt"`
	LastApplied time.Time `json:"lastApplied"`
	LastFailure time.Time `json:"lastFailure"`
	Restarting  bool      `json:"restarting"`
	CanRetry    bool      `json:"canRetry"`
}

func (s *Service) ApplicationStatus() ApplicationStatus {
	s.applicationMu.Lock()
	defer s.applicationMu.Unlock()
	result := s.application
	if result.State == "" {
		result.State = "unknown"
	}
	result.CanRetry = result.State != "applying" && !result.Restarting
	return result
}
func (s *Service) applicationPath() string {
	if s.Store == nil || s.Store.Path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.Store.Path), "network-status.json")
}
func (s *Service) InitializeApplicationStatus() {
	s.applicationMu.Lock()
	if path := s.applicationPath(); path != "" {
		if f, err := os.Open(path); err == nil {
			var saved struct {
				LastFailure time.Time `json:"lastFailure"`
			}
			if json.NewDecoder(io.LimitReader(f, 4096)).Decode(&saved) == nil {
				s.application.LastFailure = saved.LastFailure
			}
			f.Close()
		}
	}
	s.applicationMu.Unlock()
	s.ApplicationStarted()
}
func (s *Service) setApplication(state string, restarting bool) {
	s.applicationMu.Lock()
	defer s.applicationMu.Unlock()
	now := time.Now().UTC()
	s.application.State = state
	s.application.UpdatedAt = now
	s.application.Restarting = restarting
	if state == "applied" {
		s.application.LastApplied = now
	}
	if state == "error" {
		s.application.LastFailure = now
		if path := s.applicationPath(); path != "" {
			data, _ := json.Marshal(struct {
				LastFailure time.Time `json:"lastFailure"`
			}{now})
			if store.AtomicWrite(path, data, 0600) != nil {
				slog.Warn("Could not persist network failure timestamp")
			}
		}
	}
}
func (s *Service) ApplicationStarted() { s.setApplication("applying", false) }
func (s *Service) ApplicationApplied() { s.setApplication("applied", false) }
func (s *Service) ApplicationFailed()  { s.setApplication("error", true) }

// Reapply reads committed state; it never writes configuration or rotates keys.
// A service stopping after an uncertain commit must restart, not reuse its memory.
func (s *Service) Reapply(ctx context.Context) error {
	if !s.mu.TryLock() {
		return fmt.Errorf("another operation is in progress; try again shortly")
	}
	defer s.mu.Unlock()
	if s.failed {
		return fmt.Errorf("service is restarting; wait for recovery")
	}
	state, err := s.Store.Load()
	if err != nil {
		s.fail(err)
		return fmt.Errorf("saved configuration could not be read; service is restarting")
	}
	if *state.Addresses != *s.State.Addresses {
		s.fail(fmt.Errorf("saved addresses changed"))
		return fmt.Errorf("saved addresses changed; service is restarting")
	}
	s.ApplicationStarted()
	apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	prepared, err := s.Network.PrepareAddresses(apply, s.Config)
	if err == nil {
		err = s.Network.ApplyAddresses(apply, state, prepared)
	}
	if err != nil {
		s.fail(err)
		return fmt.Errorf("network could not be applied; service is restarting")
	}
	s.State = state
	s.observationOK = false
	s.ApplicationApplied()
	return nil
}

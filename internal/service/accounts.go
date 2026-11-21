package service

import (
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrAccess = errors.New("object not found or access denied")

// HTTP serializes account mutations against all authenticated requests. These
// service checks also guard mutations under mu, alongside device state changes.
func (s *Service) canManageOwner(actor, owner string) bool {
	a, err := s.Store.Account(actor)
	if err != nil {
		return false
	}
	o, err := s.Store.Account(owner)
	return err == nil && a.CanManage(o)
}
func (s *Service) canAccessDevice(actor, id string) bool {
	for _, p := range s.State.Peers {
		if p.ID == id {
			return s.canManageOwner(actor, p.OwnerID)
		}
	}
	return false
}
func (s *Service) CanAccessDevice(actor, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canAccessDevice(actor, id)
}
func (s *Service) AccountsFor(actor string) ([]store.Account, error) {
	a, err := s.Store.Account(actor)
	if err != nil || !a.Active {
		return nil, ErrAccess
	}
	all, err := s.Store.Accounts()
	if err != nil {
		return nil, err
	}
	out := []store.Account{}
	for _, o := range all {
		if a.CanManage(o) {
			out = append(out, o)
		}
	}
	return out, nil
}
func (s *Service) ListFor(actor string) ([]View, error) {
	accounts, err := s.AccountsFor(actor)
	if err != nil {
		return nil, err
	}
	owners := map[string]bool{}
	for _, a := range accounts {
		owners[a.ID] = true
	}
	out := []View{}
	for _, v := range s.List() {
		if owners[v.OwnerID] {
			out = append(out, v)
		}
	}
	return out, nil
}
func reachableHome(state model.State) error {
	for _, p := range state.Peers {
		if p.Enabled && !p.AccountBlocked && p.Group == "home" {
			return nil
		}
	}
	return fmt.Errorf("keep at least one home device enabled under an active account")
}

// Account roles cannot be changed through this operation. Only the bootstrap
// superadministrator can change its own login, using the dedicated password flow.
func (s *Service) WriteAccount(ctx context.Context, actor string, next store.Account, password string, remove bool) (store.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return store.Account{}, fmt.Errorf("service is stopping")
	}
	if !store.ValidLogin(next.Login) {
		return store.Account{}, fmt.Errorf("login must use 1-64 lowercase letters, digits, dots, underscores or hyphens")
	}
	if next.Role != "admin" && next.Role != "user" && next.Role != "superadmin" {
		return store.Account{}, fmt.Errorf("invalid role")
	}
	if (next.ID == "" || password != "") && (len(password) < 12 || len(password) > 256) {
		return store.Account{}, fmt.Errorf("password must contain 12 to 256 bytes")
	}
	a, err := s.Store.Account(actor)
	if err != nil || !a.Active || a.Role == "user" {
		return store.Account{}, ErrAccess
	}
	if next.ID == "" {
		if remove || next.Role == "superadmin" || (next.Role == "admin" && a.Role != "superadmin") {
			return store.Account{}, ErrAccess
		}
	} else {
		old, e := s.Store.Account(next.ID)
		if e != nil || !a.CanManage(old) {
			return store.Account{}, ErrAccess
		}
		if old.Role != next.Role {
			return store.Account{}, fmt.Errorf("account role cannot be changed")
		}
		if old.Revision != next.Revision {
			return store.Account{}, store.ErrSettingsConflict
		}
		if old.ID == a.ID && (remove || !next.Enabled || password != "") {
			return store.Account{}, fmt.Errorf("use your own password form; self-blocking and self-deletion are not allowed")
		}
		if old.Role == "superadmin" && (remove || !next.Enabled || password != "") {
			return store.Account{}, fmt.Errorf("superadministrator cannot be disabled, deleted or reset here")
		}
	}
	if next.Role == "user" {
		if a.Role == "admin" {
			if next.ManagerID != "" && next.ManagerID != a.ID {
				return store.Account{}, ErrAccess
			}
			next.ManagerID = a.ID
		}
		manager, e := s.Store.Account(next.ManagerID)
		if e != nil || manager.Role != "admin" {
			return store.Account{}, fmt.Errorf("select an administrator for this user")
		}
	} else if next.ManagerID != "" {
		return store.Account{}, fmt.Errorf("only users have a managing administrator")
	}
	// Preserve an independent route into the panel before committing a suspension.
	all, err := s.Store.Accounts()
	if err != nil {
		return store.Account{}, err
	}
	enabled := map[string]bool{}
	managers := map[string]string{}
	for _, v := range all {
		enabled[v.ID] = v.Enabled
		managers[v.ID] = v.ManagerID
	}
	if next.ID != "" {
		enabled[next.ID] = next.Enabled && !remove
		managers[next.ID] = next.ManagerID
	}
	preview := s.State
	preview.Peers = append([]model.Peer{}, s.State.Peers...)
	for i, p := range preview.Peers {
		m := managers[p.OwnerID]
		preview.Peers[i].AccountBlocked = !enabled[p.OwnerID] || (m != "" && !enabled[m])
	}
	if err = reachableHome(preview); err != nil {
		return store.Account{}, err
	}
	result, err := s.Store.WriteAccount(actor, next, password, remove)
	if err != nil {
		if errors.Is(err, store.ErrSettingsConflict) || errors.Is(err, store.ErrAccountInUse) || errors.Is(err, store.ErrLoginInUse) {
			return store.Account{}, err
		}
		s.fail(err)
		return store.Account{}, fmt.Errorf("account could not be committed; service is restarting")
	}
	// Reload derived account blocking, never overwrite user device switches.
	state, err := s.Store.Load()
	if err != nil {
		s.fail(err)
		return store.Account{}, fmt.Errorf("account saved but state reload failed; service is restarting")
	}
	changed := false
	previous := map[string]bool{}
	for _, p := range s.State.Peers {
		previous[p.ID] = p.AccountBlocked
	}
	for _, p := range state.Peers {
		if p.AccountBlocked != previous[p.ID] {
			changed = true
			break
		}
	}
	s.State = state
	if changed {
		s.observationOK = false
		apply, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err = s.Network.Apply(apply, state); err != nil {
			s.fail(err)
			return store.Account{}, fmt.Errorf("account saved but VPN update failed; service is restarting")
		}
	}
	if !remove {
		return s.Store.Account(result.ID)
	}
	return result, nil
}

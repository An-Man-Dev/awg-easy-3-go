package service

import (
	"awg-panel/internal/artifact"
	"awg-panel/internal/model"
	"awg-panel/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrKeyConflict = errors.New("device keys changed; reload before reissuing")

type KeyPolicyView struct {
	model.KeyPolicy
	StoredKeys    int    `json:"storedKeys"`
	DeleteVersion string `json:"deleteVersion"`
}
type Issuance struct {
	KeyVersion       string `json:"keyVersion"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	StoredPrivateKey bool   `json:"storedPrivateKey"`
	ExportSnapshot
}

func keyVersion(p model.Peer) string {
	hash := sha256.Sum256([]byte(p.PublicKey))
	return hex.EncodeToString(hash[:])
}
func (s *Service) snapshot(p model.Peer) (ExportSnapshot, error) {
	link, err := artifact.Link(s.State, p, s.Config, s.Network.IPv6)
	if err != nil {
		return ExportSnapshot{}, err
	}
	hash := sha256.Sum256([]byte(link))
	return ExportSnapshot{Config: artifact.Client(s.State, p, s.Config, s.Network.IPv6), Link: link, Version: hex.EncodeToString(hash[:])}, nil
}
func (s *Service) keyPolicy() KeyPolicyView {
	v := KeyPolicyView{KeyPolicy: model.KeyPolicy{Revision: 1, Retain: true}}
	if s.State.KeyPolicy != nil {
		v.KeyPolicy = *s.State.KeyPolicy
	}
	ids := []string{}
	for _, p := range s.State.Peers {
		if p.PrivateKey != "" {
			v.StoredKeys++
			ids = append(ids, p.ID+":"+keyVersion(p))
		}
	}
	sort.Strings(ids)
	hash := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	v.DeleteVersion = hex.EncodeToString(hash[:])
	return v
}
func (s *Service) KeyPolicy() KeyPolicyView { s.mu.Lock(); defer s.mu.Unlock(); return s.keyPolicy() }
func (s *Service) UpdateKeyPolicy(next model.KeyPolicy) (KeyPolicyView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return KeyPolicyView{}, fmt.Errorf("service is stopping")
	}
	if next.Revision != s.keyPolicy().Revision {
		return KeyPolicyView{}, store.ErrSettingsConflict
	}
	expected := next.Revision
	next.Revision++
	if err := s.Store.SaveKeyPolicy(next, expected); err != nil {
		return KeyPolicyView{}, err
	}
	s.State.KeyPolicy = &next
	return s.keyPolicy(), nil
}
func (s *Service) PurgeKeys(revision int64, version string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return 0, fmt.Errorf("service is stopping")
	}
	current := s.keyPolicy()
	if current.Revision != revision || current.DeleteVersion != version {
		return 0, store.ErrSettingsConflict
	}
	if current.Retain {
		return 0, fmt.Errorf("disable key retention before deleting stored keys")
	}
	count, err := s.Store.PurgeStoredKeys(revision)
	if err != nil {
		s.fail(err)
		return 0, fmt.Errorf("key deletion failed; service is restarting")
	}
	// Replace the slice so no subsequent device mutation can write the old keys back.
	next := append([]model.Peer{}, s.State.Peers...)
	for i := range next {
		next[i].PrivateKey = ""
	}
	s.State.Peers = next
	return count, nil
}

// The transient key is used only to build this response. It never enters durable
// state when retention is off. No response cache, retry token, or temporary file.
func (s *Service) Issue(ctx context.Context, id, name, group, expected string) (Issuance, error) {
	return s.IssueFor(ctx, model.BootstrapAccountID, model.BootstrapAccountID, id, name, group, expected)
}
func (s *Service) IssueFor(ctx context.Context, actor, owner, id, name, group, expected string) (Issuance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return Issuance{}, fmt.Errorf("service is stopping")
	}
	if owner == "" {
		owner = actor
	}
	if id == "" {
		if !s.canManageOwner(actor, owner) {
			return Issuance{}, ErrAccess
		}
	} else if !s.canAccessDevice(actor, id) {
		return Issuance{}, ErrAccess
	}
	next, p, err := s.prepareIssue(id, name, group, expected, owner)
	if err != nil {
		return Issuance{}, err
	}
	snapshot, err := s.snapshot(p)
	if err != nil {
		return Issuance{}, err
	}
	action := "device.create"
	if id != "" {
		action = "device.reissue"
	}
	if err = s.commitPeers(ctx, next, store.AuditRecord{Actor: actor, Action: action, Target: p.ID}); err != nil {
		return Issuance{}, err
	}
	return Issuance{KeyVersion: keyVersion(p), ID: p.ID, Name: p.Name, StoredPrivateKey: s.keyPolicy().Retain, ExportSnapshot: snapshot}, nil
}
func (s *Service) prepareIssue(id, name, group, expected string, owners ...string) (model.State, model.Peer, error) {
	next := s.State
	next.Peers = append([]model.Peer{}, s.State.Peers...)
	var p model.Peer
	index := -1
	if id == "" {
		used := map[int]bool{}
		for _, old := range next.Peers {
			used[old.Slot] = true
		}
		slot := 2
		for slot <= 254 && used[slot] {
			slot++
		}
		if slot > 254 {
			return next, p, fmt.Errorf("address pool is full")
		}
		var err error
		owner := model.BootstrapAccountID
		if len(owners) > 0 {
			owner = owners[0]
		}
		p, err = model.NewPeer(name, group, slot, owner)
		if err == nil && s.Store != nil {
			account, e := s.Store.Account(owner)
			if e != nil {
				return next, p, e
			}
			p.AccountBlocked = !account.Active
		}
		if err != nil {
			return next, p, err
		}
	} else {
		for i, old := range next.Peers {
			if old.ID == id {
				p = old
				index = i
				break
			}
		}
		if index < 0 {
			return next, p, fmt.Errorf("device not found")
		}
		if expected != keyVersion(p) {
			return next, p, ErrKeyConflict
		}
		var err error
		p.PrivateKey, p.PublicKey, err = model.Keys()
		if err != nil {
			return next, p, err
		}
		p.PresharedKey = model.Secret()
	}
	stored := p
	if !s.keyPolicy().Retain {
		stored.PrivateKey = ""
	}
	if index < 0 {
		next.Peers = append(next.Peers, stored)
	} else {
		next.Peers[index] = stored
	}
	return next, p, model.Validate(next)
}

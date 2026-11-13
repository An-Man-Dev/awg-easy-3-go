package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"awg-panel/internal/model"
)

type Store struct {
	Path string
	lock *os.File
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another panel instance owns the state: %w", err)
	}
	return &Store{Path: filepath.Join(dir, "state.json"), lock: f}, nil
}
func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) Load() (model.State, error) {
	var state model.State
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		state, err = model.NewState()
		if err != nil {
			return state, err
		}
		return state, s.Save(state)
	}
	if err != nil {
		return state, err
	}
	if len(b) > 2<<20 {
		return state, fmt.Errorf("state file exceeds size limit")
	}
	if err = json.Unmarshal(b, &state); err != nil {
		return state, fmt.Errorf("invalid state JSON: %w", err)
	}
	return state, model.Validate(state)
}
func (s *Store) Save(state model.State) error {
	if err := model.Validate(state); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(s.Path, append(b, '\n'), 0600)
}

// AtomicWrite also syncs the parent directory to persist the rename across power loss.
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

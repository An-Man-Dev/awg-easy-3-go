package store

import (
	"os"
	"path/filepath"
)

// AtomicWrite also syncs the parent directory to persist the rename across power loss.
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	return atomicWrite(path, b, mode, false)
}

// AtomicCreate publishes a fully synced file without replacing an existing path.
func AtomicCreate(path string, b []byte, mode os.FileMode) error {
	return atomicWrite(path, b, mode, true)
}

func atomicWrite(path string, b []byte, mode os.FileMode, exclusive bool) error {
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
	if exclusive {
		err = os.Link(name, path)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

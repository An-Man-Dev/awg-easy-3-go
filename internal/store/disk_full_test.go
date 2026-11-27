package store

import (
	"awg-panel/internal/model"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// Run only on an explicitly provisioned, disposable small filesystem.
func TestRealFilesystemFull(t *testing.T) {
	root := os.Getenv("AWG_TEST_FULL_FS")
	if root == "" {
		t.Skip("requires a disposable bounded filesystem")
	}
	dir, err := os.MkdirTemp(root, "store-full-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	filler := filepath.Join(dir, "filler")
	f, err := os.Create(filler)
	if err != nil {
		t.Fatal(err)
	}
	block := bytes.Repeat([]byte{1}, 4096)
	for i := 0; i < 16384; i++ {
		_, err = f.Write(block)
		if err != nil {
			break
		}
	}
	f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("expected real ENOSPC on bounded filesystem", err)
	}
	keyPath := filepath.Join(dir, "new.key")
	if err = AtomicCreate(keyPath, block[:32], 0600); err == nil {
		t.Fatal("key creation succeeded on full filesystem")
	}
	if _, err = os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("partial key published", err)
	}
	next := before
	next.Peers = append(next.Peers[:0:0], before.Peers...)
	next.Peers[0].Name = "Must not commit"
	if err = s.Save(next); err == nil {
		t.Fatal("write succeeded on full filesystem")
	}
	if err = os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.Load()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("full disk changed committed state", err)
	}
	if err = AtomicCreate(keyPath, block[:32], 0600); err != nil {
		t.Fatal("retry after freeing space", err)
	}
}

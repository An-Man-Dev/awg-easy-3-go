package store

import (
	"awg-panel/internal/model"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicReadersNeverObservePartialJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := model.NewState()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if err = AtomicWrite(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	errs := make(chan error, 1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			s.Peers[0].Name = "Updated"
			data, _ := json.Marshal(s)
			if err := AtomicWrite(path, data, 0600); err != nil {
				errs <- err
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got model.State
		if err = json.Unmarshal(data, &got); err != nil {
			t.Fatal("partial JSON observed:", err)
		}
		if got.PrivateKey != s.PrivateKey {
			t.Fatal("key changed")
		}
	}
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	pending, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".pending-*"))
	if len(pending) != 0 {
		t.Fatal("temporary files leaked")
	}
}

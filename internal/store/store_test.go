package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"awg-panel/internal/model"
)

func TestStateSurvivesReopenAndRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("concurrent state writer accepted")
	}
	state.Peers[0].Name = "Saved name"
	if err = st.Save(state); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey != state.PrivateKey || got.Peers[0].Name != "Saved name" {
		t.Fatal("state was regenerated or lost")
	}
	info, err := os.Stat(st.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("state is not private")
	}
	if err = os.WriteFile(st.Path, []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Load(); err == nil {
		t.Fatal("corrupt state silently accepted")
	}
	b, _ := os.ReadFile(st.Path)
	if string(b) != `{"version":` {
		t.Fatal("corrupt state overwritten")
	}
}
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

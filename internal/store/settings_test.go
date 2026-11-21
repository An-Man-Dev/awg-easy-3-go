package store

import (
	"awg-panel/internal/model"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGlobalSettingsPersistWithoutChangingDevices(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, true, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := *before.Settings
	next.Client = next.Client.Clone()
	next.Revision++
	next.ServerName = "Private lab"
	next.Client.MTU = 1380
	next.Client.PersistentKeepalive = 0
	next.Client.DNS = []string{"9.9.9.9"}
	next.Client.AllowedIPs = []string{"10.8.0.0/24", "fd42:8::/64"}
	if err = s.SaveSettings(next, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSettings(next, 1); !errors.Is(err, ErrSettingsConflict) {
		t.Fatal("stale settings replaced newer values")
	}
	s.Close()
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Initialize("ignored", false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*after.Settings, next) || !reflect.DeepEqual(after.Peers, before.Peers) || after.PrivateKey != before.PrivateKey || !reflect.DeepEqual(after.Profile, before.Profile) {
		t.Fatal("settings reset or device identity changed")
	}
	if _, err = s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	failed := next
	failed.Revision++
	failed.ServerName = "Must not persist"
	if err = s.SaveSettings(failed, next.Revision); err == nil {
		t.Fatal("read-only settings write accepted")
	}
	s.db.Exec("PRAGMA query_only=OFF")
	after, err = s.Load()
	if err != nil || !reflect.DeepEqual(*after.Settings, next) {
		t.Fatal("failed save changed settings")
	}
}

func TestPreviousSQLiteSchemaRequiresCleanInstall(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Initialize(testPassword, false, model.Addresses{Revision: 1, VPNHost: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP TABLE app_settings; PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	path := filepath.Join(dir, "panel.db")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err = Open(dir); err == nil {
		s.Close()
		t.Fatal("previous schema was migrated or accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("old database was modified")
	}
}

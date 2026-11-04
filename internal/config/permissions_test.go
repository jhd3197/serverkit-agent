package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/permissions"
)

func loadYAML(t *testing.T, yaml string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLegacyConfigDefaultsToFull(t *testing.T) {
	cfg := loadYAML(t, "agent:\n  id: abc\n")
	l, err := cfg.PermissionLevel()
	if err != nil || l != permissions.Full {
		t.Fatalf("legacy config => %q, %v; want full", l, err)
	}
	if l, _ := Default().PermissionLevel(); l != permissions.Full {
		t.Fatalf("Default() => %q, want full", l)
	}
}

func TestConfiguredLevels(t *testing.T) {
	for _, want := range []permissions.Level{permissions.Monitor, permissions.Protect, permissions.Full} {
		cfg := loadYAML(t, "permissions:\n  level: "+string(want)+"\n")
		if l, err := cfg.PermissionLevel(); err != nil || l != want {
			t.Errorf("level %s => %q, %v", want, l, err)
		}
	}
}

func TestInvalidLevelFailsClosed(t *testing.T) {
	cfg := loadYAML(t, "permissions:\n  level: superuser\n")
	if _, err := cfg.PermissionLevel(); err == nil {
		t.Fatal("unknown level must be an error, not silently full")
	}
}

func TestLevelSurvivesSave(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	cfg := Default()
	cfg.Permissions.Level = "monitor"
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	got, _ := Load(p)
	if l, _ := got.PermissionLevel(); l != permissions.Monitor {
		t.Fatalf("round trip => %q", l)
	}
}

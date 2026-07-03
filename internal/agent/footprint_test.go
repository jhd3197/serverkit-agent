package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

// The agent self-reports its footprint (install dir + config dir) in
// system_info so the panel's target-aware UIs (File Manager quick links)
// never have to assume installer defaults.

func TestConfigDirFromLoadedPath(t *testing.T) {
	src := filepath.Join("/etc", "serverkit-agent", "config.yaml")
	a := &Agent{cfg: &config.Config{SourcePath: src}}
	if got, want := a.configDir(), filepath.Dir(src); got != want {
		t.Errorf("configDir() = %q, want %q", got, want)
	}
}

func TestConfigDirFallsBackToPlatformDefault(t *testing.T) {
	a := &Agent{cfg: &config.Config{}} // no SourcePath (programmatic config)
	want := filepath.Dir(config.DefaultConfigPath())
	if got := a.configDir(); got != want {
		t.Errorf("configDir() fallback = %q, want %q", got, want)
	}
	nilCfg := &Agent{}
	if got := nilCfg.configDir(); got != want {
		t.Errorf("configDir() with nil cfg = %q, want %q", got, want)
	}
}

func TestInstallDirIsExecutableDir(t *testing.T) {
	a := &Agent{}
	// Under `go test` the executable is the test binary — the contract is
	// simply "the directory of the running binary, never an error".
	if got := a.installDir(); got == "" {
		t.Error("installDir() = \"\", want the running binary's directory")
	}
}

func TestConfigLoadRecordsSourcePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "server:\n  url: https://panel.example.com\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%q): %v", path, err)
	}
	if cfg.SourcePath != path {
		t.Errorf("SourcePath = %q, want %q", cfg.SourcePath, path)
	}
}

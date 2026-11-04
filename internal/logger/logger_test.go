package logger

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

func TestLogFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	file := filepath.Join(t.TempDir(), "logs", "agent.log")
	New(config.LoggingConfig{File: file, MaxSize: 1})
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("new file: %v %v", fi, err)
	}
	if fi, _ := os.Stat(filepath.Dir(file)); fi.Mode().Perm() != 0750 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	New(config.LoggingConfig{File: file, MaxSize: 1})
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0600 {
		t.Fatalf("existing file not tightened: %v", fi.Mode().Perm())
	}
}

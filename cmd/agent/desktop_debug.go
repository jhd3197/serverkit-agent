package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// desktopLog is a small file-backed log used by runDesktop / runSetup so a
// failed launch is never invisible. We deliberately live alongside the agent's
// other state in %LOCALAPPDATA%\ServerKit\Agent rather than next to the exe
// (Program Files needs admin to write into).
type desktopLog struct {
	mu sync.Mutex
	f  *os.File
	p  string
}

func (d *desktopLog) Path() string { return d.p }

// File exposes the underlying append-only handle so callers can redirect
// other writers (stdlib log, slog handlers) into the same file. Returns
// nil if the desktop log couldn't be opened — callers must guard.
func (d *desktopLog) File() *os.File {
	if d == nil {
		return nil
	}
	return d.f
}

func (d *desktopLog) Logf(format string, args ...interface{}) {
	if d == nil || d.f == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), fmt.Sprintf(format, args...))
	_, _ = d.f.WriteString(line)
	_ = d.f.Sync()
}

func (d *desktopLog) Close() {
	if d == nil || d.f == nil {
		return
	}
	_ = d.f.Close()
}

func openDesktopLog() *desktopLog {
	candidates := []string{}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		candidates = append(candidates, filepath.Join(v, "ServerKit", "Agent"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "AppData", "Local", "ServerKit", "Agent"))
	}
	candidates = append(candidates, os.TempDir())

	for _, dir := range candidates {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		p := filepath.Join(dir, "desktop.log")
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			continue
		}
		return &desktopLog{f: f, p: p}
	}
	return &desktopLog{}
}

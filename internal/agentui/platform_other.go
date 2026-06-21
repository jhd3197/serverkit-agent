//go:build !windows

package agentui

import (
	"fmt"
	"time"
)

// runServiceCmd is a stub on non-Windows: the console window is Windows-only
// for now, and the platform-specific service controls land alongside the
// cross-platform webview wrapper later.
func runServiceCmd(verb string) error {
	return fmt.Errorf("service control not implemented on this platform")
}

func waitForServiceRunning(timeout time.Duration) error {
	return fmt.Errorf("service control not implemented on this platform")
}

// isServiceInstalled reports false on non-Windows so the pairing flow skips
// the SCM stop/start dance entirely (there is no service manager to drive;
// systemd integration lands with the cross-platform service controls).
func isServiceInstalled() bool {
	return false
}

func waitForServiceStopped(timeout time.Duration) error {
	return fmt.Errorf("service control not implemented on this platform")
}

func openTarget(target string) error {
	return fmt.Errorf("open not implemented on this platform")
}

func exeForSpawn() (string, error) {
	return "", fmt.Errorf("not implemented on this platform")
}

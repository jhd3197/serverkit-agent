//go:build windows

package agentui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// runServiceCmd issues sc.exe verb against ServerKitAgent. The MSI grants
// BUILTIN\Users start/stop/configure rights so this works as the regular
// user with no UAC prompt.
func runServiceCmd(verb string) error {
	cmd := exec.Command("sc.exe", verb, "ServerKitAgent")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc %s: %w (output: %s)", verb, err, string(out))
	}
	return nil
}

// isServiceInstalled reports whether ServerKitAgent is registered with
// Windows SCM. Used to skip the post-pair stop/start dance when the user
// is running the standalone exe without the MSI install — there's no
// service to control, and `sc start` would fail with error 1060
// ("service does not exist") and surface as a fake pairing failure.
func isServiceInstalled() bool {
	cmd := exec.Command("sc.exe", "query", "ServerKitAgent")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}
	// sc.exe sets exit status 1060 (and prints that code) when the
	// service is unknown. Any other error (access denied, SCM down) we
	// optimistically treat as "service exists, just couldn't query it"
	// — the subsequent stop/start will surface the real problem with
	// better context than the query would.
	return !strings.Contains(string(out), "1060")
}

// waitForServiceRunning polls `sc query` until the service reports state
// 4 (RUNNING) or the deadline passes. Returns nil when running, or a
// descriptive error including the most recent state output. Used to
// verify the post-pair sc start actually took — otherwise the wizard
// silently shows "claimed" while the service quietly failed to start.
func waitForServiceRunning(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastOut string
	for time.Now().Before(deadline) {
		cmd := exec.Command("sc.exe", "query", "ServerKitAgent")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		lastOut = string(out)
		if err == nil && strings.Contains(lastOut, "RUNNING") {
			return nil
		}
		// STATE = 2 (START_PENDING) and 3 (STOP_PENDING) are transients —
		// just wait. STATE = 1 (STOPPED) means the service either died or
		// never came up; we'll catch it after the deadline.
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach RUNNING within %s (last sc query: %s)",
		timeout, strings.TrimSpace(lastOut))
}

// waitForServiceStopped polls `sc query` until the service reports state
// 1 (STOPPED) or the deadline passes. `sc stop` returns as soon as SCM
// accepts the stop request — issuing `sc start` while the service is
// still STOP_PENDING returns error 1056 ("instance already running"),
// which is exactly what users hit on the post-pair restart.
func waitForServiceStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastOut string
	for time.Now().Before(deadline) {
		cmd := exec.Command("sc.exe", "query", "ServerKitAgent")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, err := cmd.CombinedOutput()
		lastOut = string(out)
		if err == nil && strings.Contains(lastOut, "STOPPED") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach STOPPED within %s (last sc query: %s)",
		timeout, strings.TrimSpace(lastOut))
}

// openTarget hands a path or URL to Explorer / the default browser via
// rundll32 + url.dll, which is the canonical "open this thing" entry point
// on Windows. Faster than shelling out to cmd /c start.
func openTarget(target string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

// exeForSpawn returns the path to the currently running agent binary so the
// wizard re-launch can spawn another instance of the same exe.
func exeForSpawn() (string, error) {
	return os.Executable()
}

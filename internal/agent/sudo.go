package agent

// Privilege escalation helpers. The agent's install script lays down a
// dedicated `serverkit-agent` user, so handlers that touch system state
// (systemctl, apt, dnf, journalctl on system journals) need to escalate
// when the agent isn't running as root. We use passwordless sudo (-n)
// so a hung password prompt can't tie up a request.
//
// The decision is made once at startup: probe whether `sudo -n true`
// succeeds, cache the result, and surface it on the capabilities
// payload as one of "root", "passwordless", or "unavailable" so the
// panel can warn users *before* they try to install something.
//
// When the mode is "unavailable", privileged handlers fail fast with a
// "sudo_required" error instead of spawning a subprocess that would
// deadlock waiting for a password.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// SudoMode describes how the agent escalates privileges.
type SudoMode string

const (
	SudoRoot         SudoMode = "root"         // EUID == 0
	SudoPasswordless SudoMode = "passwordless" // sudo -n works
	SudoUnavailable  SudoMode = "unavailable"  // no escalation possible
)

// errSudoRequired is returned by privileged handlers when escalation
// isn't available. Wrapped with extra context by the calling handler.
var errSudoRequired = errors.New("sudo required: agent is running as a non-root user and passwordless sudo is not configured")

// probeSudoMode determines the agent's escalation capability. Called
// once at startup; the result is cached in Agent.sudoMode.
func probeSudoMode(ctx context.Context) SudoMode {
	if runtime.GOOS != "linux" {
		// Non-linux hosts don't run the privileged handlers anyway —
		// systemd/packages capabilities are gated off on those.
		if isAdminWindows() {
			return SudoRoot
		}
		return SudoUnavailable
	}
	if os.Geteuid() == 0 {
		return SudoRoot
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		return SudoUnavailable
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sudo", "-n", "true")
	if err := cmd.Run(); err != nil {
		return SudoUnavailable
	}
	return SudoPasswordless
}

// isAdminWindows is a placeholder: the privileged handlers are gated by
// runtime.GOOS == "linux" anyway, so the only effect is the value
// surfaced on the capabilities payload. Returning false everywhere on
// Windows is safe.
func isAdminWindows() bool { return false }

// sudoCommandContext returns an exec.Cmd that runs `name args...` with
// privilege escalation according to the agent's sudo mode. When the
// mode is "unavailable", it returns nil and a sudo_required error —
// callers must check both.
//
// The returned Cmd has DEBIAN_FRONTEND=noninteractive in its env so
// dpkg conffile prompts don't hang installs in production. Callers
// that need additional env should append to cmd.Env after the call.
func sudoCommandContext(ctx context.Context, mode SudoMode, name string, args ...string) (*exec.Cmd, error) {
	switch mode {
	case SudoRoot:
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = privilegedEnv()
		return cmd, nil
	case SudoPasswordless:
		full := append([]string{"-n", name}, args...)
		cmd := exec.CommandContext(ctx, "sudo", full...)
		cmd.Env = privilegedEnv()
		return cmd, nil
	default:
		return nil, errSudoRequired
	}
}

// privilegedEnv builds the env block used for privileged commands.
// Inherits the parent process env and adds DEBIAN_FRONTEND so apt
// upgrades don't stop on conffile prompts.
func privilegedEnv() []string {
	out := append([]string{}, os.Environ()...)
	out = append(out, "DEBIAN_FRONTEND=noninteractive")
	return out
}

// classifySudoError matches stderr text from a failed escalation
// attempt and returns true when sudo specifically refused (password
// required, terminal required, no permission). Used to wrap downstream
// errors with a clean "sudo_required" code instead of leaking the raw
// sudo banner to the panel.
func classifySudoError(stderr string) bool {
	low := strings.ToLower(stderr)
	for _, marker := range []string{
		"a password is required",
		"a terminal is required",
		"sudo: not allowed",
		"sudo: must be setuid root",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

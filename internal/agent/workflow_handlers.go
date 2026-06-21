package agent

// Phase 4 primitive handlers — package install/remove/list, systemd
// unit control, and bounded shell exec. The workflow engine on the
// panel sequences these to drive playbooks like "install Docker" or
// "install LAMP" against any agent-managed server.
//
// All handlers are Linux-only. The capability probe advertises
// "packages" / "systemd" only on Linux hosts where the relevant tooling
// is present, so the panel won't normally call these on Windows/macOS;
// the runtime guard here is belt-and-suspenders.
//
// Idempotency is the contract: re-running an install on a host where
// the package is already there returns success with installed=true and
// no side effects. Same for systemd start on a unit already active.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// Package install can be slow on a fresh host (apt update + index
	// + downloads). Bound at 5 minutes — longer than any single
	// install we've seen, short enough to surface a hung mirror.
	packageOpTimeout = 5 * time.Minute
	// systemctl operations are quick; if one hangs longer than 30s
	// something is wrong (mount-blocked unit, hung shutdown).
	systemdOpTimeout = 30 * time.Second
	// Hard ceiling on exec timeouts when the operator hasn't set
	// Security.MaxExecTimeout. The configured value, if any, wins —
	// this is just the safety net so a misconfigured agent can't run
	// arbitrary commands forever.
	defaultMaxExecTimeout = 10 * time.Minute
)

// ───── packages ────────────────────────────────────────────────────

type packageManager struct {
	bin       string   // "apt-get", "dnf", "apk", "pacman", "zypper"
	install   []string // args before package name(s)
	remove    []string
	list      []string
	queryFlag string // arg pattern for "is X installed"
}

// detectPackageManager returns the active manager on PATH or an error
// if none is recognised. Order matters — apt-get is preferred over apt
// for non-interactive use.
func detectPackageManager() (*packageManager, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("packages:* is Linux-only")
	}
	candidates := []*packageManager{
		{bin: "apt-get", install: []string{"install", "-y"}, remove: []string{"remove", "-y"}, list: []string{"list", "--installed"}, queryFlag: "dpkg"},
		{bin: "dnf", install: []string{"install", "-y"}, remove: []string{"remove", "-y"}, list: []string{"list", "installed"}, queryFlag: "rpm"},
		{bin: "yum", install: []string{"install", "-y"}, remove: []string{"remove", "-y"}, list: []string{"list", "installed"}, queryFlag: "rpm"},
		{bin: "apk", install: []string{"add"}, remove: []string{"del"}, list: []string{"info"}, queryFlag: "apk"},
		{bin: "pacman", install: []string{"-S", "--noconfirm"}, remove: []string{"-R", "--noconfirm"}, list: []string{"-Q"}, queryFlag: "pacman"},
		{bin: "zypper", install: []string{"install", "-y"}, remove: []string{"remove", "-y"}, list: []string{"se", "--installed-only"}, queryFlag: "rpm"},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err == nil {
			return c, nil
		}
	}
	return nil, errors.New("no recognised package manager on PATH")
}

// isInstalled checks the package database directly so install/remove
// can short-circuit when there's nothing to do. Avoids re-running the
// full manager (which on apt would otherwise refresh sources first).
func (pm *packageManager) isInstalled(ctx context.Context, name string) (bool, error) {
	switch pm.queryFlag {
	case "dpkg":
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", name).Output()
		if err != nil {
			return false, nil // not installed
		}
		return strings.Contains(string(out), "install ok installed"), nil
	case "rpm":
		err := exec.CommandContext(ctx, "rpm", "-q", name).Run()
		return err == nil, nil
	case "apk":
		err := exec.CommandContext(ctx, "apk", "info", "-e", name).Run()
		return err == nil, nil
	case "pacman":
		err := exec.CommandContext(ctx, "pacman", "-Q", name).Run()
		return err == nil, nil
	}
	return false, fmt.Errorf("unsupported query flag: %s", pm.queryFlag)
}

func validatePackageName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name is required")
	}
	// Reject shell metacharacters — the package name goes straight
	// into argv but we still don't want to explain to a user why
	// `apt-get install "foo; rm -rf /"` worked.
	if strings.ContainsAny(name, ";&|`$<>\n\r\"'\\") {
		return fmt.Errorf("invalid package name: %q", name)
	}
	return nil
}

func (a *Agent) handlePackagesInstall(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validatePackageName(p.Name); err != nil {
		return nil, err
	}
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}

	// Idempotency: check first so a re-run is cheap and obvious.
	if installed, _ := pm.isInstalled(ctx, p.Name); installed {
		return map[string]interface{}{
			"package":   p.Name,
			"installed": true,
			"action":    "noop",
			"manager":   pm.bin,
		}, nil
	}

	cctx, cancel := context.WithTimeout(ctx, packageOpTimeout)
	defer cancel()
	args := append(append([]string{}, pm.install...), p.Name)
	out, err := exec.CommandContext(cctx, pm.bin, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", pm.bin, strings.Join(args, " "), err, truncate(string(out), 1024))
	}
	return map[string]interface{}{
		"package":   p.Name,
		"installed": true,
		"action":    "installed",
		"manager":   pm.bin,
		"output":    truncate(string(out), 4096),
	}, nil
}

func (a *Agent) handlePackagesRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validatePackageName(p.Name); err != nil {
		return nil, err
	}
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}

	if installed, _ := pm.isInstalled(ctx, p.Name); !installed {
		return map[string]interface{}{
			"package":   p.Name,
			"installed": false,
			"action":    "noop",
			"manager":   pm.bin,
		}, nil
	}

	cctx, cancel := context.WithTimeout(ctx, packageOpTimeout)
	defer cancel()
	args := append(append([]string{}, pm.remove...), p.Name)
	out, err := exec.CommandContext(cctx, pm.bin, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (%s)", pm.bin, strings.Join(args, " "), err, truncate(string(out), 1024))
	}
	return map[string]interface{}{
		"package":   p.Name,
		"installed": false,
		"action":    "removed",
		"manager":   pm.bin,
		"output":    truncate(string(out), 4096),
	}, nil
}

func (a *Agent) handlePackagesListInstalled(ctx context.Context, params json.RawMessage) (interface{}, error) {
	pm, err := detectPackageManager()
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, packageOpTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, pm.bin, pm.list...).Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", pm.bin, strings.Join(pm.list, " "), err)
	}
	// Don't try to parse — formats vary too much. Ship the raw output
	// and let downstream tooling pick what it cares about.
	return map[string]interface{}{
		"manager": pm.bin,
		"output":  truncate(string(out), 1024*256),
	}, nil
}

// ───── systemd ─────────────────────────────────────────────────────

func validateUnitName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("unit is required")
	}
	if strings.ContainsAny(name, ";&|`$<>\n\r\"'\\ ") {
		return fmt.Errorf("invalid unit name: %q", name)
	}
	return nil
}

func systemctlAvailable() error {
	if runtime.GOOS != "linux" {
		return errors.New("systemd:* is Linux-only")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not on PATH")
	}
	return nil
}

func runSystemctl(ctx context.Context, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, systemdOpTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func parseUnitParam(params json.RawMessage) (string, error) {
	var p struct {
		Unit string `json:"unit"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", fmt.Errorf("invalid params: %w", err)
	}
	if err := validateUnitName(p.Unit); err != nil {
		return "", err
	}
	return p.Unit, nil
}

func (a *Agent) handleSystemdStatus(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	// is-active exits non-zero for inactive — that's expected, capture it.
	active, _ := runSystemctl(ctx, "is-active", unit)
	enabled, _ := runSystemctl(ctx, "is-enabled", unit)
	return map[string]interface{}{
		"unit":    unit,
		"active":  active,
		"enabled": enabled,
	}, nil
}

// systemdMutateTimeout is the per-action timeout for state-changing
// systemctl calls (start/stop/restart/enable/disable). Cold service
// starts (postgresql, mongodb) routinely take 30-90s, so the original
// 30s ceiling was too tight; bump to 2 minutes.
const systemdMutateTimeout = 2 * time.Minute

func (a *Agent) handleSystemdStart(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	if out, err := a.runSystemctlPrivileged(ctx, systemdMutateTimeout, "start", unit); err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl start %s: %w (%s)", unit, err, out)
	}
	return map[string]interface{}{"unit": unit, "action": "started"}, nil
}

func (a *Agent) handleSystemdStop(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	if out, err := a.runSystemctlPrivileged(ctx, systemdMutateTimeout, "stop", unit); err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl stop %s: %w (%s)", unit, err, out)
	}
	return map[string]interface{}{"unit": unit, "action": "stopped"}, nil
}

func (a *Agent) handleSystemdRestart(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	if out, err := a.runSystemctlPrivileged(ctx, systemdMutateTimeout, "restart", unit); err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl restart %s: %w (%s)", unit, err, out)
	}
	return map[string]interface{}{"unit": unit, "action": "restarted"}, nil
}

func (a *Agent) handleSystemdEnable(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	if out, err := a.runSystemctlPrivileged(ctx, systemdMutateTimeout, "enable", unit); err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl enable %s: %w (%s)", unit, err, out)
	}
	return map[string]interface{}{"unit": unit, "action": "enabled"}, nil
}

func (a *Agent) handleSystemdDisable(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	unit, err := parseUnitParam(params)
	if err != nil {
		return nil, err
	}
	if out, err := a.runSystemctlPrivileged(ctx, systemdMutateTimeout, "disable", unit); err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl disable %s: %w (%s)", unit, err, out)
	}
	return map[string]interface{}{"unit": unit, "action": "disabled"}, nil
}

// ───── system:exec ─────────────────────────────────────────────────

// commandBlocked reports whether cmd matches one of the operator's
// configured BlockedCommands entries. Comparison is exact-match against
// either the full path or the basename, after both sides are
// normalised — operators tend to write either "/usr/bin/rm" or just
// "rm" and we want to honour both. Empty entries are ignored so a
// stray newline in YAML doesn't deny everything.
func commandBlocked(blocked []string, cmd string) bool {
	if len(blocked) == 0 {
		return false
	}
	cmdAbs := strings.TrimSpace(cmd)
	cmdBase := filepath.Base(cmdAbs)
	for _, raw := range blocked {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if entry == cmdAbs || entry == cmdBase {
			return true
		}
		if filepath.Base(entry) == cmdBase {
			return true
		}
	}
	return false
}

// resolveMaxExecTimeout honours the operator's Security.MaxExecTimeout
// when set (any positive duration), otherwise falls back to the
// hardcoded ceiling. Negative or zero values are treated as "unset"
// rather than "no timeout"; the agent never runs an unbounded
// subprocess.
func (a *Agent) resolveMaxExecTimeout() time.Duration {
	if a.cfg != nil && a.cfg.Security.MaxExecTimeout > 0 {
		return a.cfg.Security.MaxExecTimeout
	}
	return defaultMaxExecTimeout
}

// handleSystemExec runs an arbitrary command, captures stdout/stderr,
// and returns the exit code. The first token must be an absolute path
// (same rule as cron commands) so a misconfigured caller can't depend
// on $PATH state of the agent process. Output is truncated to keep the
// command envelope reasonable; the runner can poll a file if it needs
// the full output of a chatty install.
//
// This handler is only registered when cfg.Features.Exec is true (see
// agent.go:registerHandlers). When Exec is disabled, the panel sees an
// "unknown action" error rather than the command silently running.
func (a *Agent) handleSystemExec(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if a.cfg == nil || !a.cfg.Features.Exec {
		return nil, errors.New("system:exec is disabled by agent config (features.exec=false)")
	}

	var p struct {
		Command        string   `json:"command"`
		Args           []string `json:"args"`
		WorkingDir     string   `json:"working_dir"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	cmd := strings.TrimSpace(p.Command)
	if cmd == "" {
		return nil, errors.New("command is required")
	}
	if !strings.HasPrefix(cmd, "/") {
		return nil, errors.New("command must be an absolute path")
	}
	if strings.ContainsAny(cmd, ";&|`$<>\n\r") {
		return nil, errors.New("command contains shell metacharacters; pass arguments via args[]")
	}
	if commandBlocked(a.cfg.Security.BlockedCommands, cmd) {
		return nil, fmt.Errorf("command %q is blocked by agent security config", cmd)
	}

	maxTimeout := a.resolveMaxExecTimeout()
	timeout := time.Duration(p.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > maxTimeout {
		timeout = maxTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := exec.CommandContext(cctx, cmd, p.Args...)
	if p.WorkingDir != "" {
		c.Dir = p.WorkingDir
	}
	out, err := c.CombinedOutput()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, fmt.Errorf("exec %s: %w", cmd, err)
		}
	}
	return map[string]interface{}{
		"command":   cmd,
		"args":      p.Args,
		"exit_code": exitCode,
		"output":    truncate(string(out), 1024*32),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated]"
}

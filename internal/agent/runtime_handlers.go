package agent

// Phase 5 — runtime version managers (pyenv on Linux, pyenv-win on
// Windows). The agent already ships a Python version via the
// capability probe; these handlers add install / uninstall / select-
// version flows so users can pick a Python without SSHing in.
//
// Bootstrap and install actions stream on a job channel because they
// take minutes — pyenv compiles CPython from source on Linux and
// downloads + extracts MSI installers on Windows.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/jobs"
)

// pyenvLock serializes pyenv mutations on a single agent. pyenv's
// shim management is not safe under concurrent installs.
var pyenvLock sync.Mutex

// pyenvBin returns the path to the pyenv binary the agent should use,
// or "" if pyenv isn't installed. On Linux we look at $HOME/.pyenv/bin
// and PATH; on Windows we look at %USERPROFILE%\.pyenv\pyenv-win\bin.
func pyenvBin() string {
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		if home != "" {
			candidate := filepath.Join(home, ".pyenv", "pyenv-win", "bin", "pyenv.bat")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		if p, err := exec.LookPath("pyenv"); err == nil {
			return p
		}
		return ""
	}
	// Linux/macOS
	home, _ := os.UserHomeDir()
	if home != "" {
		candidate := filepath.Join(home, ".pyenv", "bin", "pyenv")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if p, err := exec.LookPath("pyenv"); err == nil {
		return p
	}
	return ""
}

// pyenvManagerKind returns "pyenv", "pyenv-win", or "" for absent.
// Surfaced as RuntimeManagers["python"] in the capabilities payload.
func pyenvManagerKind() string {
	if pyenvBin() == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		return "pyenv-win"
	}
	return "pyenv"
}

// runPyenv runs the pyenv binary with the given args and returns the
// trimmed stdout/stderr. Used by the read-only handlers.
func runPyenv(ctx context.Context, args ...string) (string, error) {
	bin := pyenvBin()
	if bin == "" {
		return "", errors.New("pyenv not installed (run runtimes:pyenv:bootstrap first)")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ───── runtimes:list ──────────────────────────────────────────────

func (a *Agent) handleRuntimesList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	out := map[string]interface{}{
		"managers": map[string]string{
			"python": pyenvManagerKind(),
		},
		"runtimes": a.capabilities.Runtimes,
	}
	if pyenvManagerKind() != "" {
		current, _ := runPyenv(ctx, "version")
		installed, _ := runPyenv(ctx, "versions", "--bare")
		out["python"] = map[string]interface{}{
			"current":   strings.SplitN(current, " ", 2)[0],
			"installed": splitNonEmptyLines(installed),
		}
	}
	return out, nil
}

// ───── runtimes:python:installed ─────────────────────────────────

func (a *Agent) handleRuntimesPythonInstalled(ctx context.Context, params json.RawMessage) (interface{}, error) {
	out, err := runPyenv(ctx, "versions", "--bare")
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"versions": splitNonEmptyLines(out),
		"manager":  pyenvManagerKind(),
	}, nil
}

// ───── runtimes:python:available ─────────────────────────────────

func (a *Agent) handleRuntimesPythonAvailable(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// `pyenv install --list` on Linux and `pyenv install -l` on
	// pyenv-win both work, but pyenv-win prints them with leading
	// whitespace. Normalize.
	out, err := runPyenv(ctx, "install", "--list")
	if err != nil && pyenvManagerKind() == "pyenv-win" {
		out, err = runPyenv(ctx, "install", "-l")
	}
	if err != nil {
		return nil, err
	}
	versions := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Available") || strings.HasPrefix(line, ":") {
			continue
		}
		versions = append(versions, line)
	}
	return map[string]interface{}{
		"versions": versions,
		"manager":  pyenvManagerKind(),
	}, nil
}

// ───── runtimes:python:current ───────────────────────────────────

func (a *Agent) handleRuntimesPythonCurrent(ctx context.Context, params json.RawMessage) (interface{}, error) {
	out, err := runPyenv(ctx, "version")
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(out, " ", 2)
	return map[string]interface{}{
		"version": parts[0],
		"raw":     out,
	}, nil
}

// ───── runtimes:python:set_global ────────────────────────────────

func (a *Agent) handleRuntimesPythonSetGlobal(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if err := validateVersion(p.Version); err != nil {
		return nil, err
	}
	out, err := runPyenv(ctx, "global", p.Version)
	if err != nil {
		return nil, fmt.Errorf("pyenv global %s: %w (%s)", p.Version, err, out)
	}
	return map[string]interface{}{"global": p.Version}, nil
}

// ───── runtimes:python:set_local ─────────────────────────────────

func (a *Agent) handleRuntimesPythonSetLocal(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Version string `json:"version"`
		Dir     string `json:"dir"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if err := validateVersion(p.Version); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(p.Dir)
	if err != nil {
		return nil, fmt.Errorf("dir: %w", err)
	}
	if !a.contextPathAllowed(abs) {
		return nil, fmt.Errorf("dir %q is not under any allowed root", abs)
	}
	bin := pyenvBin()
	if bin == "" {
		return nil, errors.New("pyenv not installed")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "local", p.Version)
	cmd.Dir = abs
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pyenv local %s in %s: %w (%s)", p.Version, abs, err, string(out))
	}
	return map[string]interface{}{"local": p.Version, "dir": abs}, nil
}

// ───── runtimes:python:uninstall ─────────────────────────────────

func (a *Agent) handleRuntimesPythonUninstall(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if err := validateVersion(p.Version); err != nil {
		return nil, err
	}
	pyenvLock.Lock()
	defer pyenvLock.Unlock()
	out, err := runPyenv(ctx, "uninstall", "-f", p.Version)
	if err != nil {
		return nil, fmt.Errorf("pyenv uninstall %s: %w (%s)", p.Version, err, out)
	}
	return map[string]interface{}{"uninstalled": p.Version}, nil
}

// ───── runtimes:python:install (streaming) ───────────────────────

func (a *Agent) handleRuntimesPythonInstall(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if err := validateVersion(p.Version); err != nil {
		return nil, err
	}
	if pyenvBin() == "" {
		return nil, errors.New("pyenv not installed (run runtimes:pyenv:bootstrap first)")
	}
	job := a.jobs.New(500)
	go a.runPyenvInstallJob(job, p.Version)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
		"version": p.Version,
	}, nil
}

func (a *Agent) runPyenvInstallJob(job *jobs.Job, version string) {
	pyenvLock.Lock()
	defer pyenvLock.Unlock()

	exit := 0
	emitDone := func(errStr string) {
		_ = job.Push(a.ws, jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra:    map[string]interface{}{"version": version, "manager": pyenvManagerKind()},
		})
	}

	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, pyenvBin(), "install", "-s", version)
	_ = job.Push(a.ws, jobs.Event{Phase: jobs.PhaseStart, Message: fmt.Sprintf("pyenv install %s", version)})
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOfCmd(cerr)
		if exit == 0 {
			exit = -1
		}
		emitDone(cerr.Error())
		return
	}
	emitDone("")
}

// ───── runtimes:pyenv:bootstrap (streaming) ──────────────────────
//
// Linux: clones pyenv to ~/.pyenv. Does NOT touch ~/.bashrc — most
// agents run as a non-login systemd unit and the user already has
// shell init from their interactive sessions; we don't want to
// duplicate it. Clone path matches the upstream installer.
//
// Windows: clones pyenv-win to %USERPROFILE%\.pyenv\pyenv-win.

func (a *Agent) handleRuntimesPyenvBootstrap(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if pyenvBin() != "" {
		return map[string]interface{}{
			"status":  "already_installed",
			"manager": pyenvManagerKind(),
		}, nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, errors.New("git is required to install pyenv (please install git first)")
	}
	job := a.jobs.New(200)
	go a.runPyenvBootstrapJob(job)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
	}, nil
}

func (a *Agent) runPyenvBootstrapJob(job *jobs.Job) {
	exit := 0
	emitDone := func(errStr string) {
		_ = job.Push(a.ws, jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra:    map[string]interface{}{"manager": pyenvManagerKind()},
		})
	}

	home, _ := os.UserHomeDir()
	if home == "" && runtime.GOOS == "windows" {
		home = os.Getenv("USERPROFILE")
	}
	if home == "" {
		exit = -1
		emitDone("could not determine user home directory")
		return
	}

	var repo, dest string
	if runtime.GOOS == "windows" {
		repo = "https://github.com/pyenv-win/pyenv-win.git"
		dest = filepath.Join(home, ".pyenv")
	} else {
		repo = "https://github.com/pyenv/pyenv.git"
		dest = filepath.Join(home, ".pyenv")
	}

	_ = job.Push(a.ws, jobs.Event{Phase: jobs.PhaseStart, Message: fmt.Sprintf("git clone %s %s", repo, dest)})

	cctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", repo, dest)
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOfCmd(cerr)
		if exit == 0 {
			exit = -1
		}
		emitDone(cerr.Error())
		return
	}
	emitDone("")
}

// validateVersion rejects shell metacharacters in the user-supplied
// pyenv version reference. pyenv tags are dotted-version strings ("3.12.0",
// "3.13.0a4") so the allow-list is conservative.
func validateVersion(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("version is required")
	}
	for _, r := range v {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '.' || r == '-' || r == '_' || r == '+' {
			continue
		}
		return fmt.Errorf("invalid version: %q", v)
	}
	return nil
}

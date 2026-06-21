package agent

// Phase 1c additions — systemd actions beyond status/start/stop/restart/
// enable/disable: daemon-reload, list-units, journal logs (bounded fetch
// and follow-stream variants).
//
// list-units prefers `systemctl --output=json` (systemd 244+) for clean
// parsing and falls back to plain text on older systems. The choice is
// probed once and cached on the agent so we don't pay the fork cost on
// every list call.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/jobs"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// runSystemctlPrivileged is the sudo-aware variant of runSystemctl. It
// preserves the existing 30-second timeout for read operations; long
// operations (start/stop/restart/daemon-reload) override via timeout
// param.
func (a *Agent) runSystemctlPrivileged(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd, err := sudoCommandContext(cctx, a.sudoMode, "systemctl", args...)
	if err != nil {
		return "", err
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ───── systemd:daemon_reload ──────────────────────────────────────

func (a *Agent) handleSystemdDaemonReload(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	out, err := a.runSystemctlPrivileged(ctx, 5*time.Minute, "daemon-reload")
	if err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl daemon-reload: %w (%s)", err, out)
	}
	return map[string]interface{}{
		"action": "daemon_reloaded",
		"output": out,
	}, nil
}

// ───── systemd:list_units ─────────────────────────────────────────

// systemctlUnit is the canonical row shape returned by list_units
// regardless of whether we got JSON or plain text from systemctl.
type systemctlUnit struct {
	Unit        string `json:"unit"`
	Load        string `json:"load,omitempty"`
	Active      string `json:"active,omitempty"`
	Sub         string `json:"sub,omitempty"`
	Description string `json:"description,omitempty"`
}

func (a *Agent) handleSystemdListUnits(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	var p struct {
		State string `json:"state"` // optional filter: failed, active, inactive…
		Type  string `json:"type"`  // unit type: service (default), socket, timer…
	}
	_ = json.Unmarshal(params, &p)
	if p.Type == "" {
		p.Type = "service"
	}
	if err := validateUnitName(p.Type); err != nil {
		return nil, fmt.Errorf("type: %w", err)
	}
	if p.State != "" {
		if err := validateUnitName(p.State); err != nil {
			return nil, fmt.Errorf("state: %w", err)
		}
	}

	args := []string{"list-units", "--all", "--no-legend", "--no-pager", "--type=" + p.Type}
	if p.State != "" {
		args = append(args, "--state="+p.State)
	}

	useJSON := a.detectSystemctlJSON(ctx)
	if useJSON {
		jsonArgs := append(append([]string{}, args...), "--output=json")
		out, err := a.runSystemctlPrivileged(ctx, 30*time.Second, jsonArgs...)
		if err == nil {
			var rows []map[string]interface{}
			if jerr := json.Unmarshal([]byte(out), &rows); jerr == nil {
				units := make([]systemctlUnit, 0, len(rows))
				for _, r := range rows {
					u := systemctlUnit{}
					if v, ok := r["unit"].(string); ok {
						u.Unit = v
					}
					if v, ok := r["load"].(string); ok {
						u.Load = v
					}
					if v, ok := r["active"].(string); ok {
						u.Active = v
					}
					if v, ok := r["sub"].(string); ok {
						u.Sub = v
					}
					if v, ok := r["description"].(string); ok {
						u.Description = v
					}
					units = append(units, u)
				}
				return map[string]interface{}{"units": units, "format": "json"}, nil
			}
		}
		// JSON failed (older systemd, malformed output) — fall through
		// to plain text and remember the choice.
		a.capMu.Lock()
		a.capabilities.SystemdJSON = false
		a.systemdJSON = false
		a.capMu.Unlock()
	}

	// Plain text fallback. Columns: UNIT LOAD ACTIVE SUB DESCRIPTION.
	out, err := a.runSystemctlPrivileged(ctx, 30*time.Second, args...)
	if err != nil {
		if classifySudoError(out) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("systemctl list-units: %w (%s)", err, truncate(out, 1024))
	}
	units := parsePlainListUnits(out)
	return map[string]interface{}{"units": units, "format": "plain"}, nil
}

// detectSystemctlJSON probes once whether `systemctl --output=json` is
// supported. Caches the result on the agent + advertises via the
// capabilities payload so the panel can show an "older systemd" hint.
func (a *Agent) detectSystemctlJSON(ctx context.Context) bool {
	a.systemdJSONOnce.Do(func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := exec.CommandContext(cctx, "systemctl", "list-units", "--no-legend", "--no-pager", "--output=json", "--type=service").Run()
		ok := err == nil
		a.capMu.Lock()
		a.systemdJSON = ok
		a.capabilities.SystemdJSON = ok
		a.capMu.Unlock()
	})
	a.capMu.Lock()
	defer a.capMu.Unlock()
	return a.systemdJSON
}

func parsePlainListUnits(out string) []systemctlUnit {
	units := []systemctlUnit{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "●") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		u := systemctlUnit{
			Unit:   fields[0],
			Load:   fields[1],
			Active: fields[2],
			Sub:    fields[3],
		}
		if len(fields) > 4 {
			u.Description = strings.Join(fields[4:], " ")
		}
		units = append(units, u)
	}
	return units
}

// ───── systemd:logs (bounded fetch) ──────────────────────────────

func (a *Agent) handleSystemdLogs(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	var p struct {
		Unit  string `json:"unit"`
		Lines int    `json:"lines"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validateUnitName(p.Unit); err != nil {
		return nil, err
	}
	if p.Lines <= 0 {
		p.Lines = 200
	}
	if p.Lines > 5000 {
		p.Lines = 5000
	}

	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, errors.New("journalctl not on PATH")
	}

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd, err := sudoCommandContext(cctx, a.sudoMode, "journalctl",
		"-u", p.Unit, "--no-pager", "-n", fmt.Sprintf("%d", p.Lines), "-o", "json")
	if err != nil {
		return nil, err
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if classifySudoError(string(out)) {
			return nil, fmt.Errorf("sudo refused: %w", errSudoRequired)
		}
		return nil, fmt.Errorf("journalctl -u %s: %w (%s)", p.Unit, err, truncate(string(out), 1024))
	}

	// journalctl -o json prints one JSON object per line. Parse each
	// into a flat shape the panel can render directly.
	type entry struct {
		Time     string `json:"time"`
		Priority string `json:"priority"`
		PID      string `json:"pid"`
		Message  string `json:"message"`
	}
	var entries []entry
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		e := entry{
			Time:     stringField(raw, "__REALTIME_TIMESTAMP"),
			Priority: stringField(raw, "PRIORITY"),
			PID:      stringField(raw, "_PID"),
			Message:  stringField(raw, "MESSAGE"),
		}
		entries = append(entries, e)
	}
	return map[string]interface{}{
		"unit":    p.Unit,
		"lines":   p.Lines,
		"entries": entries,
	}, nil
}

func stringField(m map[string]interface{}, k string) string {
	v, ok := m[k]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// ───── systemd:logs_follow (streaming) ───────────────────────────

// handleSystemdLogsFollow returns a job channel and starts streaming
// `journalctl -fu <unit>` lines on it. The job ends when either the
// caller unsubscribes (which we detect by closing job.Done) or a fixed
// 1-hour cap elapses to prevent runaway logs.
//
// The pattern mirrors handlePackagesInstallAsync: hand back
// {job_id, channel} immediately, work happens in a goroutine.
func (a *Agent) handleSystemdLogsFollow(ctx context.Context, params json.RawMessage) (interface{}, error) {
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}
	var p struct {
		Unit string `json:"unit"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := validateUnitName(p.Unit); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, errors.New("journalctl not on PATH")
	}

	job := a.jobs.New(500)
	// The protocol channel format is documented but we override to use
	// the job: namespace so the panel's existing job-channel
	// infrastructure handles it. The systemd:<unit>:logs format is
	// reserved for a future multi-subscriber broadcast variant.
	_ = protocol.ChannelSystemdLogs
	go a.runSystemdLogsFollowJob(job, p.Unit)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
		"unit":    p.Unit,
	}, nil
}

func (a *Agent) runSystemdLogsFollowJob(job *jobs.Job, unit string) {
	exit := 0
	emitDone := func(errStr string) {
		_ = job.Push(a.ws, jobs.Event{
			Phase:    jobs.PhaseDone,
			ExitCode: &exit,
			Error:    errStr,
			Extra:    map[string]interface{}{"unit": unit},
		})
	}

	// Cap any single follow at 1 hour. Panel can re-subscribe.
	cctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()
	cmd, err := sudoCommandContext(cctx, a.sudoMode, "journalctl",
		"-fu", unit, "--no-pager", "-o", "short-iso")
	if err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	_ = job.Push(a.ws, jobs.Event{
		Phase:   jobs.PhaseStart,
		Message: fmt.Sprintf("following journal for %s", unit),
	})
	if err := streamCmdOutput(cmd, job, a.ws); err != nil {
		exit = -1
		emitDone(err.Error())
		return
	}
	if cerr := cmd.Wait(); cerr != nil {
		exit = exitCodeOf(cerr)
		// journalctl returns non-zero when killed by the deadline; that's
		// a graceful end, not an error.
		if cctx.Err() == context.DeadlineExceeded {
			emitDone("")
			return
		}
		emitDone(cerr.Error())
		return
	}
	emitDone("")
}

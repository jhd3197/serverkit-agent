package agent

// Fleet doctor v2 batched probe (plan 28 Phase 2). One round trip that
// returns the health facts the panel's fleet doctor needs — per-unit
// active state + root-fs disk percent — so a sweep is a single call per
// box instead of N systemd:status calls + system:metrics.
//
// Read-only: nothing here escalates or mutates. `systemctl is-active` is
// unprivileged. The response conforms to docs/AGENT_DOCTOR_PROBE_SPEC.md
// in the panel repo; the panel's _service_state() parser keys off the
// per-unit `active` boolean, so unknown units are reported absent
// (active:false) rather than erroring the whole probe.

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	gopsutildisk "github.com/shirou/gopsutil/v3/disk"
)

// doctorProbeParams is the request body: the systemd unit names to report.
type doctorProbeParams struct {
	Units []string `json:"units"`
}

func (a *Agent) handleDoctorProbe(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Linux + systemd gate, matching the systemd family (the capability is
	// only advertised there, but register + guard so a stray call off a
	// non-Linux box gets a clean error instead of a panic).
	if err := systemctlAvailable(); err != nil {
		return nil, err
	}

	var p doctorProbeParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
	}

	units := map[string]interface{}{}
	for _, unit := range p.Units {
		// Silently skip malformed unit names rather than error the whole
		// probe — the panel sends its fixed CORE_SERVICES allowlist, but
		// be defensive.
		if validateUnitName(unit) != nil {
			continue
		}
		active, state := probeUnitActive(ctx, unit)
		units[unit] = map[string]interface{}{
			"active": active,
			"state":  state,
		}
	}

	// Root-filesystem used-percent. The panel computes headroom as
	// 100 - percent (fleet_doctor_service._disk_check). Best-effort: a
	// probe failure degrades this field, never the whole probe.
	disk := map[string]interface{}{"path": "/"}
	if u, err := gopsutildisk.UsageWithContext(ctx, "/"); err == nil {
		disk["percent"] = u.UsedPercent
	}

	// `listening` is spec-reserved (the panel doesn't read it in v1); omit
	// it rather than invent payload — see AGENT_DOCTOR_PROBE_SPEC.md.
	return map[string]interface{}{
		"units": units,
		"disk":  disk,
	}, nil
}

// probeUnitActive runs the unprivileged `systemctl is-active <unit>` and
// returns (active, state). Unknown units are reported absent: state
// "not-found", active false — never an error (spec requirement). stderr
// is discarded because is-active writes "Unit … could not be found" there
// for unknown units, which we translate to "not-found" from the empty /
// "unknown" stdout instead.
func probeUnitActive(ctx context.Context, unit string) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, systemdOpTimeout)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(cctx, "systemctl", "is-active", unit)
	cmd.Stdout = &stdout
	// is-active exits non-zero for inactive/failed — expected; ignore err.
	_ = cmd.Run()
	state := strings.TrimSpace(stdout.String())
	if i := strings.IndexAny(state, "\r\n"); i >= 0 {
		state = state[:i]
	}
	if state == "" || state == "unknown" {
		state = "not-found"
	}
	return unitActiveFromState(state), state
}

// unitActiveFromState maps a systemctl is-active word to the boolean the
// panel keys off. "activating" is treated as up by the panel's own string
// parser (fleet_doctor_service._service_state), so mirror that here — a
// service mid-start must not be flagged failed/repairable. Split out so it
// is unit-testable without a live systemd host.
func unitActiveFromState(state string) bool {
	return state == "active" || state == "activating"
}

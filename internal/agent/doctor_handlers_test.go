package agent

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// TestUnitActiveFromState locks the systemctl-word → boolean mapping the
// panel keys off. active/activating are "up"; everything else is down.
func TestUnitActiveFromState(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		{"active", true},
		{"activating", true},
		{"inactive", false},
		{"failed", false},
		{"deactivating", false},
		{"not-found", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := unitActiveFromState(tc.state); got != tc.want {
			t.Errorf("unitActiveFromState(%q) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

// panelServiceState is a faithful port of the panel's
// FleetDoctorService._service_state so the golden payloads below are
// asserted against the exact classifier that consumes them. Returns
// "active" / "inactive" / "unknown".
func panelServiceState(unit interface{}) string {
	var val string
	switch d := unit.(type) {
	case string:
		val = d
	case map[string]interface{}:
		for _, k := range []string{"active", "is_active", "running"} {
			if b, ok := d[k].(bool); ok {
				if b {
					return "active"
				}
				return "inactive"
			}
		}
		for _, k := range []string{"ActiveState", "active_state", "activeState", "state", "status", "SubState", "sub_state"} {
			if s, ok := d[k].(string); ok {
				val = s
				break
			}
		}
	}
	if val == "" {
		return "unknown"
	}
	v := strings.ToLower(strings.TrimSpace(val))
	switch v {
	case "active", "running", "activating":
		return "active"
	case "inactive", "dead", "failed", "deactivating", "not-found":
		return "inactive"
	}
	return "unknown"
}

// TestDoctorProbeResponseShapeGolden asserts that the per-unit shape the
// handler emits ({active: bool, state: string}) is classified correctly
// by the panel parser — the bool drives it, the state string is display
// only. This is the cross-repo contract for #5.
func TestDoctorProbeResponseShapeGolden(t *testing.T) {
	// A golden doctor:probe `data` payload as the handler builds it.
	golden := map[string]interface{}{
		"units": map[string]interface{}{
			"nginx":  map[string]interface{}{"active": true, "state": "active"},
			"docker": map[string]interface{}{"active": false, "state": "inactive"},
			"ghost":  map[string]interface{}{"active": false, "state": "not-found"},
		},
		"disk": map[string]interface{}{"percent": 61.0, "path": "/"},
	}

	// Round-trip through JSON to prove it serializes to the wire shape the
	// panel unmarshals.
	raw, err := json.Marshal(golden)
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	units := back["units"].(map[string]interface{})
	if got := panelServiceState(units["nginx"]); got != "active" {
		t.Errorf("nginx: panel classified %q, want active", got)
	}
	if got := panelServiceState(units["docker"]); got != "inactive" {
		t.Errorf("docker: panel classified %q, want inactive", got)
	}
	// Unknown unit reported absent still classifies inactive (bool false) —
	// never errors the probe.
	if got := panelServiceState(units["ghost"]); got != "inactive" {
		t.Errorf("ghost: panel classified %q, want inactive", got)
	}

	// Disk headroom the way the panel computes it: 100 - percent.
	disk := back["disk"].(map[string]interface{})
	if free := 100.0 - disk["percent"].(float64); free != 39.0 {
		t.Errorf("disk headroom = %v, want 39.0", free)
	}
}

// TestHandleDoctorProbeOffLinux documents the fallback contract: on a
// non-systemd box the handler returns a clean error, which the panel maps
// to success:false → composed-v1 fallback (fleet_doctor_service falls back
// per _probe_checks returning None). On Linux CI this runs the real path.
func TestHandleDoctorProbeOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this asserts the off-Linux error path; on Linux the handler runs for real")
	}
	a := &Agent{}
	_, err := a.handleDoctorProbe(context.Background(), json.RawMessage(`{"units":["nginx"]}`))
	if err == nil {
		t.Fatal("expected a Linux-only error off-Linux, got nil")
	}
	if !strings.Contains(err.Error(), "Linux-only") {
		t.Fatalf("expected Linux-only error, got %v", err)
	}
}

// TestHandleDoctorProbeEmptyUnits verifies an empty-units request never
// errors and returns an empty units map plus the disk block. Linux-only
// (needs systemctl on PATH); documents the shape elsewhere.
func TestHandleDoctorProbeEmptyUnits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs systemctl; shape covered by the golden test")
	}
	a := &Agent{}
	res, err := a.handleDoctorProbe(context.Background(), json.RawMessage(`{"units":[]}`))
	if err != nil {
		t.Fatalf("empty-units probe errored: %v", err)
	}
	m := res.(map[string]interface{})
	units := m["units"].(map[string]interface{})
	if len(units) != 0 {
		t.Fatalf("expected empty units map, got %v", units)
	}
	if _, ok := m["disk"]; !ok {
		t.Fatal("expected a disk block even with no units")
	}
}

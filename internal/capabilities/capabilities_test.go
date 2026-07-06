package capabilities

import (
	"context"
	"runtime"
	"testing"
)

// TestSystemdRestartCapable locks Decision 2: the write-shaped
// systemd.restart capability is honest only when systemd is present AND
// the agent can escalate. A NoNewPrivileges deb install (sudo
// "unavailable") must never advertise it.
func TestSystemdRestartCapable(t *testing.T) {
	cases := []struct {
		name     string
		systemd  bool
		sudoMode string
		want     bool
	}{
		{"root + systemd", true, "root", true},
		{"passwordless + systemd", true, "passwordless", true},
		{"unavailable + systemd", true, "unavailable", false},
		{"empty sudo + systemd", true, "", false},
		{"root but no systemd", false, "root", false},
		{"passwordless but no systemd", false, "passwordless", false},
		{"unavailable + no systemd", false, "unavailable", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := systemdRestartCapable(tc.systemd, tc.sudoMode); got != tc.want {
				t.Fatalf("systemdRestartCapable(%v, %q) = %v, want %v",
					tc.systemd, tc.sudoMode, got, tc.want)
			}
		})
	}
}

// TestProbeV2CapabilitiesOffLinux verifies the verification requirement
// that NO v2 capability is advertised on a GOOS≠linux build — every v2
// key gates on a Linux-only probe (systemd/cron), so on Windows/macOS
// they must all be false regardless of the sudo mode we pass in.
func TestProbeV2CapabilitiesOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this guard is about non-Linux builds; on Linux the probes may legitimately be true")
	}
	for _, mode := range []string{"root", "passwordless", "unavailable"} {
		msg := Probe(context.Background(), nil, false, false, nil, mode)
		for _, key := range []string{"doctor.probe", "survey", "systemd.restart", "cron.update"} {
			if msg.Capabilities[key] {
				t.Errorf("sudoMode=%q: capability %q must be false on %s, got true",
					mode, key, runtime.GOOS)
			}
		}
	}
}

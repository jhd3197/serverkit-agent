package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestSudoCommandContext locks the three escalation modes the fleet
// repair path depends on (plan 28, Decision 2). "unavailable" must fail
// fast with errSudoRequired rather than spawning a subprocess that would
// hang on a password prompt; root runs the command directly; passwordless
// prepends `sudo -n`.
func TestSudoCommandContext(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		mode        SudoMode
		wantErr     bool
		wantPath    string   // expected cmd.Path basename fragment
		wantContain []string // args that must appear
	}{
		{
			name:        "root runs the command directly",
			mode:        SudoRoot,
			wantPath:    "systemctl",
			wantContain: []string{"restart", "nginx"},
		},
		{
			name:        "passwordless prepends sudo -n",
			mode:        SudoPasswordless,
			wantPath:    "sudo",
			wantContain: []string{"-n", "systemctl", "restart", "nginx"},
		},
		{
			name:    "unavailable fails fast",
			mode:    SudoUnavailable,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := sudoCommandContext(ctx, tc.mode, "systemctl", "restart", "nginx")
			if tc.wantErr {
				if !errors.Is(err, errSudoRequired) {
					t.Fatalf("expected errSudoRequired, got %v", err)
				}
				if cmd != nil {
					t.Fatalf("expected nil cmd on unavailable, got %v", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(cmd.Path, tc.wantPath) && !strings.Contains(cmd.Args[0], tc.wantPath) {
				t.Fatalf("expected path/arg0 to contain %q, got path=%q args=%v", tc.wantPath, cmd.Path, cmd.Args)
			}
			joined := strings.Join(cmd.Args, " ")
			for _, want := range tc.wantContain {
				if !strings.Contains(joined, want) {
					t.Fatalf("expected args %v to contain %q", cmd.Args, want)
				}
			}
		})
	}
}

// TestValidateUnitNameForRestart covers the unit-name validation that
// guards systemd:restart (and the whole systemd family) against shell
// injection — the allowlisted repair path relies on it.
func TestValidateUnitNameForRestart(t *testing.T) {
	cases := []struct {
		name    string
		unit    string
		wantErr bool
	}{
		{"plain unit", "nginx", false},
		{"unit with suffix", "docker.service", false},
		{"instance unit", "getty@tty1.service", false},
		{"empty", "", true},
		{"blank", "   ", true},
		{"semicolon injection", "nginx; rm -rf /", true},
		{"pipe injection", "nginx | cat", true},
		{"command substitution", "nginx$(id)", true},
		{"space", "nginx foo", true},
		{"newline", "nginx\nrestart docker", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUnitName(tc.unit)
			if tc.wantErr && err == nil {
				t.Fatalf("validateUnitName(%q) = nil, want error", tc.unit)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateUnitName(%q) = %v, want nil", tc.unit, err)
			}
		})
	}
}

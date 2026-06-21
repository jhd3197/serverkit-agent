package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

func TestCommandBlocked(t *testing.T) {
	cases := []struct {
		name    string
		blocked []string
		cmd     string
		want    bool
	}{
		{"empty list allows everything", nil, "/bin/ls", false},
		{"absolute path match", []string{"/usr/bin/rm"}, "/usr/bin/rm", true},
		{"basename match against absolute path", []string{"rm"}, "/usr/bin/rm", true},
		{"absolute-to-basename match", []string{"/sbin/shutdown"}, "/usr/local/sbin/shutdown", true},
		{"unrelated command not blocked", []string{"/usr/bin/rm"}, "/usr/bin/ls", false},
		{"blank entries ignored", []string{"", "  ", "/usr/bin/rm"}, "/usr/bin/rm", true},
		{"blank entries don't deny everything", []string{"", "  "}, "/bin/ls", false},
		{"whitespace trimmed on entries", []string{"  /bin/dd  "}, "/bin/dd", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandBlocked(tc.blocked, tc.cmd); got != tc.want {
				t.Fatalf("commandBlocked(%v, %q) = %v, want %v", tc.blocked, tc.cmd, got, tc.want)
			}
		})
	}
}

func TestResolveMaxExecTimeout(t *testing.T) {
	a := &Agent{cfg: &config.Config{}}
	got := a.resolveMaxExecTimeout()
	if got != defaultMaxExecTimeout {
		t.Fatalf("default fallback: got %s, want %s", got, defaultMaxExecTimeout)
	}

	a.cfg.Security.MaxExecTimeout = defaultMaxExecTimeout / 2
	if got := a.resolveMaxExecTimeout(); got != defaultMaxExecTimeout/2 {
		t.Fatalf("operator override: got %s, want %s", got, defaultMaxExecTimeout/2)
	}

	a.cfg.Security.MaxExecTimeout = -1
	if got := a.resolveMaxExecTimeout(); got != defaultMaxExecTimeout {
		t.Fatalf("negative ignored: got %s, want %s", got, defaultMaxExecTimeout)
	}
}

func TestValidateFileAccessAllowsConfiguredRoot(t *testing.T) {
	root := t.TempDir()
	a := &Agent{cfg: &config.Config{
		Security: config.SecurityConfig{AllowedPaths: []string{root}},
	}}
	target := filepath.Join(root, "sub", "file.txt")
	// Create the parent so EvalSymlinks succeeds for the parent walk.
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.validateFileAccess(target); err != nil {
		t.Fatalf("expected access allowed for %s: %v", target, err)
	}
}

func TestValidateFileAccessDeniesOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	a := &Agent{cfg: &config.Config{
		Security: config.SecurityConfig{AllowedPaths: []string{root}},
	}}
	if err := a.validateFileAccess(filepath.Join(other, "file.txt")); err == nil {
		t.Fatalf("expected access denied for path outside allowed root")
	}
}

func TestValidateFileAccessDeniesSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows symlink creation requires elevated privileges or
		// SeCreateSymbolicLinkPrivilege in CI; skip rather than make
		// the test environmentally fragile.
		t.Skip("symlink test requires non-Windows environment")
	}
	root := t.TempDir()
	secret := t.TempDir()
	a := &Agent{cfg: &config.Config{
		Security: config.SecurityConfig{AllowedPaths: []string{root}},
	}}
	// Drop a symlink inside the allowed root that points outside it.
	// The pre-fix validateFileAccess would let the escape through
	// because filepath.Clean doesn't resolve symlinks.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	target := filepath.Join(link, "file.txt")
	if err := a.validateFileAccess(target); err == nil {
		t.Fatalf("expected symlink escape to be denied; %s resolved past allowed root", target)
	}
}

func TestValidateFileAccessNoAllowedPaths(t *testing.T) {
	a := &Agent{cfg: &config.Config{}}
	if err := a.validateFileAccess("/anything"); err == nil {
		t.Fatalf("expected denial when AllowedPaths is empty")
	}
}

func TestVerifyCredentialRotation(t *testing.T) {
	currentSecret := "current-secret-value"
	rotationID := "rot-123"
	agentID := "agent-uuid"
	newKey := "sk_newkey"
	newSecret := "new-secret-value"

	a := &Agent{
		cfg:  &config.Config{Agent: config.AgentConfig{ID: agentID}},
		auth: auth.New(agentID, "sk_oldkey", currentSecret),
	}

	sign := func(secret string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", rotationID, agentID, newKey, newSecret)))
		return hex.EncodeToString(mac.Sum(nil))
	}

	t.Run("valid signature accepted", func(t *testing.T) {
		msg := protocol.CredentialUpdateMessage{
			RotationID: rotationID,
			APIKey:     newKey,
			APISecret:  newSecret,
			HMACSig:    sign(currentSecret),
		}
		if err := a.verifyCredentialRotation(msg); err != nil {
			t.Fatalf("expected valid rotation accepted, got: %v", err)
		}
	})

	t.Run("missing signature rejected", func(t *testing.T) {
		msg := protocol.CredentialUpdateMessage{
			RotationID: rotationID,
			APIKey:     newKey,
			APISecret:  newSecret,
		}
		if err := a.verifyCredentialRotation(msg); err == nil {
			t.Fatalf("expected rejection for missing signature")
		}
	})

	t.Run("wrong-secret signature rejected", func(t *testing.T) {
		msg := protocol.CredentialUpdateMessage{
			RotationID: rotationID,
			APIKey:     newKey,
			APISecret:  newSecret,
			HMACSig:    sign("attacker-guessed-secret"),
		}
		if err := a.verifyCredentialRotation(msg); err == nil {
			t.Fatalf("expected rejection when HMAC computed with wrong secret")
		}
	})

	t.Run("missing required field rejected", func(t *testing.T) {
		msg := protocol.CredentialUpdateMessage{
			RotationID: "",
			APIKey:     newKey,
			APISecret:  newSecret,
			HMACSig:    sign(currentSecret),
		}
		if err := a.verifyCredentialRotation(msg); err == nil {
			t.Fatalf("expected rejection for missing rotation_id")
		}
	})

	t.Run("agent without secret refuses rotation", func(t *testing.T) {
		empty := &Agent{
			cfg:  &config.Config{Agent: config.AgentConfig{ID: agentID}},
			auth: auth.New(agentID, "", ""),
		}
		msg := protocol.CredentialUpdateMessage{
			RotationID: rotationID,
			APIKey:     newKey,
			APISecret:  newSecret,
			HMACSig:    sign(""),
		}
		if err := empty.verifyCredentialRotation(msg); err == nil {
			t.Fatalf("expected rejection when agent has no current secret")
		}
	})
}

package agent

// Handlers for ssh:keys:* — manage one key line in a local user's
// authorized_keys. Linux-only; needs root or passwordless sudo (the keys
// live in other users' homes, which the agent's own user can't touch).
//
// Safety rules:
//   - For any user other than root, every read and write runs AS THAT
//     USER (runuser -u <user> --). Their ~/.ssh is theirs to plant
//     symlinks in, so a root-run tee/cat there could be tricked into
//     reading or clobbering arbitrary files. Running as the user means
//     the handler can only ever do what the user could do themselves.
//   - "File missing" is the only read failure treated as empty. Any other
//     failure aborts, so a flaky read can never turn into a write that
//     drops the keys already in the file.
//   - One mutex serializes all ssh:keys work on this host, so two
//     concurrent installs can't read-modify-write over each other.
//   - Writes go to a mktemp file in ~/.ssh and are renamed into place.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"
)

var sshKeysMu sync.Mutex

type sshKeysParams struct {
	User string `json:"user"`
	Key  string `json:"key"`
	// Options are authorized_keys options for add (e.g. "no-pty",
	// `permitopen="10.0.0.5:22"`). expiry-time is added by the agent
	// from ExpiresAt, never passed here.
	Options []string `json:"options"`
	// ExpiresAt (unix seconds) adds expiry-time= when the host's OpenSSH
	// supports it, so sshd itself stops accepting the key at that time.
	ExpiresAt int64 `json:"expires_at"`
	// EnsureUser creates the user (useradd -m) when it doesn't exist.
	EnsureUser bool `json:"ensure_user"`
}

func (a *Agent) handleSSHKeysAdd(ctx context.Context, params json.RawMessage) (interface{}, error) {
	p, key, err := parseSSHKeysParams(params, true)
	if err != nil {
		return nil, err
	}
	if err := validateSSHOptions(p.Options); err != nil {
		return nil, err
	}
	for _, opt := range p.Options {
		if strings.HasPrefix(opt, "expiry-time") {
			return nil, fmt.Errorf("pass expires_at instead of an expiry-time option")
		}
	}

	sshKeysMu.Lock()
	defer sshKeysMu.Unlock()

	io, err := a.newSSHKeysIO(ctx, p.User, p.EnsureUser)
	if err != nil {
		return nil, err
	}
	options := append([]string{}, p.Options...)
	expiryApplied := false
	if p.ExpiresAt > 0 {
		if major, minor, ok := io.openSSHVersion(); ok && supportsExpiryTime(major, minor) {
			options = append(options, expiryTimeOption(time.Unix(p.ExpiresAt, 0)))
			expiryApplied = true
		}
	}

	content, err := io.read()
	if err != nil {
		return nil, err
	}
	updated, changed := authorizedKeysUpsert(content, key, formatAuthorizedKeysLine(key, options))
	if changed {
		if err := io.write(updated); err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{
		"success":        true,
		"user":           p.User,
		"path":           io.path,
		"changed":        changed,
		"fingerprint":    key.fingerprint(),
		"expiry_applied": expiryApplied,
	}, nil
}

func (a *Agent) handleSSHKeysRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	p, key, err := parseSSHKeysParams(params, true)
	if err != nil {
		return nil, err
	}
	sshKeysMu.Lock()
	defer sshKeysMu.Unlock()

	io, err := a.newSSHKeysIO(ctx, p.User, false)
	if errors.Is(err, errSSHUserMissing) {
		// No user, no authorized_keys: the key is already gone.
		return map[string]interface{}{"success": true, "user": p.User, "changed": false}, nil
	}
	if err != nil {
		return nil, err
	}
	content, err := io.read()
	if err != nil {
		return nil, err
	}
	updated, changed := authorizedKeysRemove(content, key)
	if changed {
		if err := io.write(updated); err != nil {
			return nil, err
		}
	}
	return map[string]interface{}{"success": true, "user": p.User, "path": io.path, "changed": changed}, nil
}

func (a *Agent) handleSSHKeysList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	p, _, err := parseSSHKeysParams(params, false)
	if err != nil {
		return nil, err
	}
	sshKeysMu.Lock()
	defer sshKeysMu.Unlock()

	io, err := a.newSSHKeysIO(ctx, p.User, false)
	if err != nil {
		return nil, err
	}
	content, err := io.read()
	if err != nil {
		return nil, err
	}
	keys := []map[string]interface{}{}
	for _, line := range splitLines(content) {
		k, opts, ok := parseAuthorizedKeysLine(line)
		if !ok {
			continue
		}
		keys = append(keys, map[string]interface{}{
			"type":        k.Type,
			"fingerprint": k.fingerprint(),
			"comment":     k.Comment,
			"options":     opts,
		})
	}
	return map[string]interface{}{"success": true, "user": p.User, "path": io.path, "keys": keys}, nil
}

func parseSSHKeysParams(params json.RawMessage, needKey bool) (sshKeysParams, sshKey, error) {
	var p sshKeysParams
	if err := json.Unmarshal(params, &p); err != nil {
		return p, sshKey{}, fmt.Errorf("invalid params: %w", err)
	}
	if runtime.GOOS != "linux" {
		return p, sshKey{}, fmt.Errorf("ssh key management is only supported on Linux agents")
	}
	if err := validateSSHUsername(p.User); err != nil {
		return p, sshKey{}, err
	}
	if !needKey {
		return p, sshKey{}, nil
	}
	key, err := parsePublicKey(p.Key)
	if err != nil {
		return p, sshKey{}, err
	}
	if !sshCommentRe.MatchString(key.Comment) {
		return p, sshKey{}, fmt.Errorf("key comment is too long")
	}
	return p, key, nil
}

var errSSHUserMissing = errors.New("user does not exist")

// sshKeysIO runs the privileged file operations for one user's
// authorized_keys.
type sshKeysIO struct {
	ctx  context.Context
	mode SudoMode
	user string
	dir  string
	path string
}

func (a *Agent) newSSHKeysIO(ctx context.Context, username string, ensure bool) (*sshKeysIO, error) {
	if a.sudoMode != SudoRoot && a.sudoMode != SudoPasswordless {
		return nil, errSudoRequired
	}
	u, err := user.Lookup(username)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) && ensure {
		if _, cerr := runPrivileged(ctx, a.sudoMode, nil, "useradd", "-m", "-s", "/bin/bash", username); cerr != nil {
			return nil, fmt.Errorf("create user %s: %w", username, cerr)
		}
		u, err = user.Lookup(username)
	}
	if errors.As(err, &unknown) {
		return nil, fmt.Errorf("%w: %s", errSSHUserMissing, username)
	}
	if err != nil {
		return nil, fmt.Errorf("look up user %s: %w", username, err)
	}
	if u.HomeDir == "" || u.HomeDir == "/" || !path.IsAbs(u.HomeDir) {
		return nil, fmt.Errorf("user %s has no usable home directory (%q)", username, u.HomeDir)
	}
	dir := path.Join(u.HomeDir, ".ssh")
	return &sshKeysIO{ctx: ctx, mode: a.sudoMode, user: username, dir: dir,
		path: path.Join(dir, "authorized_keys")}, nil
}

// run executes a command as the target user (root runs directly).
func (s *sshKeysIO) run(stdin []byte, name string, args ...string) ([]byte, error) {
	if s.user != "root" {
		args = append([]string{"-u", s.user, "--", name}, args...)
		name = "runuser"
	}
	return runPrivileged(s.ctx, s.mode, stdin, name, args...)
}

func (s *sshKeysIO) read() (string, error) {
	if _, err := s.run(nil, "test", "-e", s.path); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return "", nil // missing file: start empty
		}
		return "", fmt.Errorf("check %s: %w", s.path, err)
	}
	out, err := s.run(nil, "cat", s.path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", s.path, err)
	}
	return string(out), nil
}

func (s *sshKeysIO) write(content string) error {
	if _, err := s.run(nil, "mkdir", "-p", "-m", "700", s.dir); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	if _, err := s.run(nil, "chmod", "700", s.dir); err != nil {
		return fmt.Errorf("chmod %s: %w", s.dir, err)
	}
	out, err := s.run(nil, "mktemp", path.Join(s.dir, ".authorized_keys.XXXXXX"))
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := strings.TrimSpace(string(out))
	if !strings.HasPrefix(tmp, s.dir+"/") {
		return fmt.Errorf("unexpected temp path %q", tmp)
	}
	cleanup := func() { _, _ = s.run(nil, "rm", "-f", tmp) }
	if _, err := s.run([]byte(content), "tee", tmp); err != nil {
		cleanup()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if _, err := s.run(nil, "chmod", "600", tmp); err != nil {
		cleanup()
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if _, err := s.run(nil, "mv", "-f", tmp, s.path); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", s.path, err)
	}
	return nil
}

func (s *sshKeysIO) openSSHVersion() (int, int, bool) {
	cmd := exec.CommandContext(s.ctx, "ssh", "-V")
	out, _ := cmd.CombinedOutput() // ssh -V prints to stderr, exits 0
	return parseOpenSSHVersion(string(out))
}

// runPrivileged runs a command through the agent's escalation mode and
// returns stdout. Errors carry trimmed stderr and keep the *exec.ExitError
// wrapped so callers can inspect the exit code.
func runPrivileged(ctx context.Context, mode SudoMode, stdin []byte, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd, err := sudoCommandContext(cctx, mode, name, args...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if classifySudoError(msg) {
			return nil, errSudoRequired
		}
		if msg != "" {
			return nil, fmt.Errorf("%s: %w (%s)", name, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

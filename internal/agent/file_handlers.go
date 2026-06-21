package agent

// File-access handlers (file:read, file:write, file:list) and the
// allowlist-aware path validator they share. Lives separately from
// agent.go so the security-sensitive path-resolution logic is easy to
// find and review without scrolling through 2000 lines of unrelated
// command handlers.
//
// Every handler in this file goes through validateFileAccess, which
// resolves symlinks before comparing against AllowedPaths — without
// that, an operator-allowed root containing a symlink to /etc would
// let the panel read or write arbitrary files. handleFileWrite also
// re-validates the parent directory before MkdirAll so CreateDirs
// can't escape via a not-yet-existing path that crosses a symlink
// boundary.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (a *Agent) handleFileRead(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := a.validateFileAccess(p.Path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return map[string]interface{}{
		"path":    p.Path,
		"content": base64.StdEncoding.EncodeToString(data),
		"size":    len(data),
	}, nil
}

func (a *Agent) handleFileWrite(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path       string `json:"path"`
		Content    string `json:"content"` // base64 encoded
		Mode       uint32 `json:"mode"`
		CreateDirs bool   `json:"create_dirs"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if err := a.validateFileAccess(p.Path); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(p.Content)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 content: %w", err)
	}

	mode := os.FileMode(0644)
	if p.Mode != 0 {
		// Mask off SUID/SGID/sticky bits — the panel has no business
		// requesting them and a compromised panel could otherwise drop
		// a setuid binary into an allowed path. If an operator
		// genuinely needs to write a setuid file they can chmod it via
		// system:exec (which is independently gated).
		mode = os.FileMode(p.Mode) & os.ModePerm
	}

	if p.CreateDirs {
		// Re-validate the parent directory under the symlink-resolved
		// rules — MkdirAll otherwise lets the panel create directories
		// outside AllowedPaths if the requested path is something like
		// /var/lib/serverkit/<symlink>/foo and <symlink> escapes.
		parent := filepath.Dir(p.Path)
		if err := a.validateFileAccess(parent); err != nil {
			return nil, fmt.Errorf("parent dir not allowed: %w", err)
		}
		if err := os.MkdirAll(parent, 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directories: %w", err)
		}
	}

	if err := os.WriteFile(p.Path, data, mode); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	return map[string]interface{}{
		"success": true,
		"path":    p.Path,
		"size":    len(data),
	}, nil
}

func (a *Agent) handleFileList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// The panel speaks forward-slash paths on the wire regardless of the
	// agent's OS. Convert to the native separator before any filesystem
	// call so os.ReadDir and the allowlist validation behave on Windows.
	reqPath := filepath.FromSlash(p.Path)

	// An empty (or bare-root) request has no single filesystem root on
	// Windows. Enumerate the logical drives as virtual directory entries
	// so the panel's file browser can pick a drive instead of silently
	// listing only the agent process's working drive. On non-Windows
	// enumerateDriveRoots() returns nil and we fall through to "/".
	if reqPath == "" || reqPath == "/" || reqPath == `\` {
		if drives := enumerateDriveRoots(); drives != nil {
			return map[string]interface{}{
				"path":  "/",
				"files": drives,
			}, nil
		}
		reqPath = "/"
	}

	if err := a.validateFileAccess(reqPath); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(reqPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	// Each entry carries an absolute, forward-slash path. The frontend
	// keys/selects/navigates on entry.path, and the agent is the only
	// party that knows the host separator, so it emits the canonical
	// path. (It was previously omitted, which broke remote browse
	// navigation on every OS — Windows additionally needs the separator
	// normalized.)
	files := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, map[string]interface{}{
			"name":     entry.Name(),
			"path":     filepath.ToSlash(filepath.Join(reqPath, entry.Name())),
			"is_dir":   entry.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime().UnixMilli(),
		})
	}

	return map[string]interface{}{
		"path":  filepath.ToSlash(reqPath),
		"files": files,
	}, nil
}

func (a *Agent) validateFileAccess(path string) error {
	allowedPaths := a.cfg.Security.AllowedPaths
	if len(allowedPaths) == 0 {
		return fmt.Errorf("file access denied: no allowed_paths configured")
	}

	target, err := resolveSymlinkPath(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	for _, allowedPath := range allowedPaths {
		if strings.TrimSpace(allowedPath) == "" {
			continue
		}
		allowed, err := resolveSymlinkPath(allowedPath)
		if err != nil {
			continue
		}

		if pathWithinAllowedRoot(target, allowed) {
			return nil
		}
	}

	return fmt.Errorf("file access denied for path: %s", path)
}

// resolveSymlinkPath returns an absolute, symlink-free path for use in
// allowlist comparison. Without this, an operator-allowed root that
// contains a symlink (eg. /var/lib/serverkit/data → /etc) lets the
// panel read or write any file the symlink points at — strings.HasPrefix
// matches the unresolved target string, which never sees the escape.
//
// For paths that don't yet exist (handleFileWrite creating a new file
// in an allowed directory), EvalSymlinks fails. Fall back to resolving
// the deepest existing ancestor and reattaching the unresolved suffix
// so a fresh file path is still validated against the real allowed
// root rather than its symlink alias.
func resolveSymlinkPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	// Path (or some ancestor) doesn't exist yet. Walk up to the
	// nearest existing ancestor, resolve that, then reattach the
	// missing suffix. This is the standard pattern for allowlist
	// checks against not-yet-created files; the suffix can't
	// introduce a new symlink because nothing on disk corresponds
	// to it yet.
	dir := abs
	suffix := ""
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, nil
		}
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(resolved, filepath.Base(dir), suffix), nil
		}
		suffix = filepath.Join(filepath.Base(dir), suffix)
		dir = parent
	}
}

func pathWithinAllowedRoot(target, allowed string) bool {
	if runtime.GOOS == "windows" {
		target = strings.ToLower(target)
		allowed = strings.ToLower(allowed)
	}

	if target == allowed {
		return true
	}

	allowedWithSeparator := strings.TrimRight(allowed, string(os.PathSeparator)) + string(os.PathSeparator)
	return strings.HasPrefix(target, allowedWithSeparator)
}

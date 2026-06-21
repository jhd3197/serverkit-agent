package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

// handleFileList must emit an absolute, forward-slash `path` for every
// entry (and for the directory itself). The frontend keys, selects, and
// navigates on entry.path; before this was added remote browse was broken
// on every OS. Cross-platform: on Windows the join also normalizes the
// backslash separator to forward-slash on the wire.
func TestHandleFileListEmitsForwardSlashPaths(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &Agent{cfg: &config.Config{
		Security: config.SecurityConfig{AllowedPaths: []string{tmp}},
	}}
	params, _ := json.Marshal(map[string]string{"path": filepath.ToSlash(tmp)})

	res, err := a.handleFileList(context.Background(), params)
	if err != nil {
		t.Fatalf("handleFileList error: %v", err)
	}

	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	if dp, _ := m["path"].(string); strings.ContainsRune(dp, '\\') {
		t.Errorf("directory path must be forward-slash on the wire, got %q", dp)
	}

	files, ok := m["files"].([]map[string]interface{})
	if !ok {
		t.Fatalf("unexpected files type %T", m["files"])
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(files))
	}

	for _, f := range files {
		p, ok := f["path"].(string)
		if !ok || p == "" {
			t.Fatalf("entry missing path field: %#v", f)
		}
		if strings.ContainsRune(p, '\\') {
			t.Errorf("entry path must be forward-slash on the wire, got %q", p)
		}
		want := filepath.ToSlash(filepath.Join(tmp, f["name"].(string)))
		if p != want {
			t.Errorf("entry path = %q, want %q", p, want)
		}
	}
}

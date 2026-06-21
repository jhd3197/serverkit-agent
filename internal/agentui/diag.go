package agentui

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// handleDiag builds a diagnostic bundle on the user's Desktop. Includes the
// current agent log, the activity events file, a redacted copy of
// config.yaml, and a small system info JSON. Returns the path so the React
// app can prompt "Open in Explorer" or just inform the user where it is.
//
// We write to Desktop on purpose: the most common reason to grab a bundle
// is to share it with someone, and Desktop is the universally-known spot.
// Falls back to the user's home dir if Desktop can't be located.
func (a *localActions) handleDiag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dest, err := buildDiagBundle()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": dest})
}

func buildDiagBundle() (string, error) {
	dataDir := dataDirGuess()
	dest := diagDestPath()

	out, err := os.Create(dest)
	if err != nil {
		return "", fmt.Errorf("create diag: %w", err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()

	// Current agent log (might not exist if never started — that's fine)
	if dataDir != "" {
		_ = addFileToZip(zw, filepath.Join(dataDir, "logs", "agent.log"), "agent.log")
		// Most-recent rotated backup, if any (lumberjack names them with a
		// timestamp suffix). Search and add up to 3 to keep the bundle slim.
		if backups, err := findLogBackups(filepath.Join(dataDir, "logs")); err == nil {
			for i, p := range backups {
				if i >= 3 {
					break
				}
				_ = addFileToZip(zw, p, "logs-backups/"+filepath.Base(p))
			}
		}
		// Events
		_ = addFileToZip(zw, filepath.Join(dataDir, "events.json"), "events.json")
		// Config (redacted)
		if redacted, err := redactedConfigYAML(filepath.Join(dataDir, "config.yaml")); err == nil {
			_ = addBytesToZip(zw, "config.redacted.yaml", redacted)
		}
	}

	// System info written last so it's the easiest to find when somebody
	// opens the zip.
	sysJSON, _ := json.MarshalIndent(systemInfo(), "", "  ")
	_ = addBytesToZip(zw, "sysinfo.json", sysJSON)

	return dest, nil
}

func addFileToZip(zw *zip.Writer, src, archivedName string) error {
	info, err := os.Stat(src)
	if err != nil || info.IsDir() {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := zw.Create(archivedName)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func addBytesToZip(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// redactedConfigYAML reads config.yaml and returns it with any auth secrets
// stripped. We don't need the api_key / api_secret to debug connectivity,
// and shipping them through casual support channels is a bad habit.
func redactedConfigYAML(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// Couldn't parse — return the raw bytes with a header noting that
		// redaction was skipped. Better than failing the bundle.
		var buf bytes.Buffer
		buf.WriteString("# diag: failed to parse for redaction; original returned as-is\n")
		buf.Write(data)
		return buf.Bytes(), nil
	}
	if auth, ok := doc["auth"].(map[string]interface{}); ok {
		for _, k := range []string{"api_key", "api_secret", "apikey", "apisecret"} {
			if _, has := auth[k]; has {
				auth[k] = "[REDACTED]"
			}
		}
	}
	return yaml.Marshal(doc)
}

func findLogBackups(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "agent-") && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz")) {
			out = append(out, filepath.Join(dir, name))
		}
	}
	// Newest first
	sortDescByModTime(out)
	return out, nil
}

func sortDescByModTime(paths []string) {
	type entry struct {
		path string
		mod  time.Time
	}
	infos := make([]entry, 0, len(paths))
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		infos = append(infos, entry{p, st.ModTime()})
	}
	// Tiny list (<= a handful) — bubble sort is plenty.
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[j].mod.After(infos[i].mod) {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	for i, e := range infos {
		if i < len(paths) {
			paths[i] = e.path
		}
	}
}

func systemInfo() map[string]interface{} {
	host, _ := os.Hostname()
	return map[string]interface{}{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"hostname":   host,
		"go_version": runtime.Version(),
		"generated":  time.Now().Format(time.RFC3339),
	}
}

func dataDirGuess() string {
	// Mirrors agent/config.DefaultConfigPath() without importing it (avoids
	// a cycle with the rest of the agent package). Best-effort — if the env
	// var isn't set we just skip the parts that need it.
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "ServerKit", "Agent")
	}
	return ""
}

func diagDestPath() string {
	stamp := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("serverkit-diag-%s.zip", stamp)
	if home, err := os.UserHomeDir(); err == nil {
		desktop := filepath.Join(home, "Desktop")
		if st, err := os.Stat(desktop); err == nil && st.IsDir() {
			return filepath.Join(desktop, name)
		}
		return filepath.Join(home, name)
	}
	return name
}

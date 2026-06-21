package agentui

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

// localActions exposes a small set of console-process-level operations to
// the React app: things that need to happen even when the agent service is
// down, or that need to be performed by a Windows interactive session
// rather than by SYSTEM-context service code.
//
// All endpoints live under /local/ so they're trivially distinguishable
// from agent-service IPC calls (which target a different port entirely).
type localActions struct {
	exePath    string
	configPath string
}

func newLocalActions(configPath string) *localActions {
	exe, _ := exeForSpawn()
	return &localActions{exePath: exe, configPath: configPath}
}

// register hooks the action handlers into the asset server's mux.
func (a *localActions) register(mux *http.ServeMux) {
	mux.HandleFunc("/local/service/restart", a.handleServiceAction("restart"))
	mux.HandleFunc("/local/service/start", a.handleServiceAction("start"))
	mux.HandleFunc("/local/service/stop", a.handleServiceAction("stop"))
	mux.HandleFunc("/local/open", a.handleOpen)
	mux.HandleFunc("/local/wizard", a.handleWizard)
	mux.HandleFunc("/local/diag", a.handleDiag)
	mux.HandleFunc("/local/status", a.handleStatus)
	mux.HandleFunc("/local/ipc-token", a.handleIPCToken)
}

// handleIPCToken returns the agent's IPC bearer token to the in-process
// React UI so it can authenticate against the agent service's HTTP API.
// Both processes run on the same machine under the same user, so the
// console process can read the token file directly — this endpoint
// just hides the OS-specific path from the JS side.
//
// Returns 503 (not 401) when the token isn't ready yet so the UI can
// distinguish "agent service hasn't started writing the file" from
// "you got the wrong credential" — the former resolves itself when the
// service starts, the latter is a real config bug.
func (a *localActions) handleIPCToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := os.ReadFile(config.IPCTokenPath())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "ipc token not yet available; is the agent service running?",
		})
		return
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "ipc token file empty",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// handleStatus reports whether the agent has been paired by reading
// config.yaml directly. The React PairGate uses this as a fallback when
// the agent service IPC is unreachable — which is exactly the case on a
// fresh install: no config means no service, so the service can't tell
// the UI it isn't registered. Without this endpoint the wizard is a
// dead end on first run.
func (a *localActions) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]interface{}{
		"registered": false,
		"agent_id":   "",
		"server_url": "",
	}
	if cfg, err := config.Load(a.configPath); err == nil && cfg != nil {
		if cfg.Agent.ID != "" {
			resp["registered"] = true
			resp["agent_id"] = cfg.Agent.ID
			resp["server_url"] = cfg.Server.URL
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleServiceAction performs sc.exe stop/start/restart against the
// installed ServerKitAgent service. Restart is "stop, brief wait, start"
// because sc.exe has no native restart verb and the agent's IPC restart
// is just a graceful stop with no auto-spin-up.
func (a *localActions) handleServiceAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		switch action {
		case "start":
			if err := runServiceCmd("start"); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		case "stop":
			if err := runServiceCmd("stop"); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		case "restart":
			// Best-effort stop — ignore "service not running" errors and
			// move on. Then start. This is what the tray's restart button
			// should have been doing all along.
			_ = runServiceCmd("stop")
			time.Sleep(1500 * time.Millisecond)
			if err := runServiceCmd("start"); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleOpen launches a path in Explorer or a URL in the default browser.
// Body: {"path": "C:\\..."} OR {"url": "https://..."}.
func (a *localActions) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Path string `json:"path"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	target := body.URL
	if target == "" {
		target = body.Path
	}
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path or url required"})
		return
	}
	if err := openTarget(target); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleWizard spawns the pairing wizard as a detached child process.
// Used by the Re-pair button — gives the user a fresh form without
// interrupting the running console window.
func (a *localActions) handleWizard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.exePath == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "agent executable path unknown"})
		return
	}
	cmd := exec.Command(a.exePath, "setup")
	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// We don't Wait on the child — it lives on its own.
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

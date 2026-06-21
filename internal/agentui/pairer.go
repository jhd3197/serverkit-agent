package agentui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/agent"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/connstring"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/pairdriver"
)

// pairer adapts the callback-style pairdriver into a polled state machine
// the React wizard can drive over HTTP. The wizard POSTs /local/pair/start
// once with panel URL + server name; from then on it polls
// /local/pair/state every second to render the current stage and react
// to claim / error transitions.
type pairer struct {
	log        *logger.Logger
	configPath string

	mu       sync.Mutex
	state    string // "idle" | "enrolling" | "waiting" | "claimed" | "error"
	code     string
	codeFmt  string
	pass     string
	panelURL string
	server   string
	errMsg   string
	cancel   context.CancelFunc
}

func newPairer(log *logger.Logger, configPath string) *pairer {
	return &pairer{
		log:        log.WithComponent("agentui-pair"),
		configPath: configPath,
		state:      "idle",
	}
}

// register adds the wizard endpoints to the asset server's mux.
func (p *pairer) register(mux *http.ServeMux) {
	mux.HandleFunc("/local/pair/start", p.handleStart)
	mux.HandleFunc("/local/pair/state", p.handleState)
	mux.HandleFunc("/local/pair/cancel", p.handleCancel)
	mux.HandleFunc("/local/pair/connection-string", p.handleConnectionString)
}

type pairStartRequest struct {
	PanelURL   string `json:"panel_url"`
	ServerName string `json:"server_name"`
}

type pairStateResponse struct {
	State          string `json:"state"`
	Code           string `json:"code,omitempty"`
	CodeFormatted  string `json:"code_formatted,omitempty"`
	Passphrase     string `json:"passphrase,omitempty"`
	PanelURL       string `json:"panel_url,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	Error          string `json:"error,omitempty"`
}

func (p *pairer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req pairStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if req.PanelURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "panel_url is required"})
		return
	}

	pass, err := pairdriver.GeneratePassphrase()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	p.mu.Lock()
	if p.cancel != nil {
		// Replace any in-flight pairing — typical when the user edits the
		// form and re-submits.
		p.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.state = "enrolling"
	p.errMsg = ""
	p.code = ""
	p.codeFmt = ""
	p.pass = pass
	p.panelURL = req.PanelURL
	p.server = req.ServerName
	p.mu.Unlock()

	cb := pairdriver.Callbacks{
		OnEnrolled: func(code, formatted string) {
			p.mu.Lock()
			p.state = "waiting"
			p.code = code
			p.codeFmt = formatted
			p.mu.Unlock()
		},
		OnClaimed: func(serverName string) {
			p.mu.Lock()
			p.state = "claimed"
			if serverName != "" {
				p.server = serverName
			}
			p.mu.Unlock()
			// After credentials land on disk the running service still has
			// the old config in memory — restart it so the new URL/agent_id
			// take effect immediately, and verify it actually came up.
			// Earlier versions ignored sc start errors silently which is
			// why users saw "successfully paired" on a dead service and
			// had to start it manually from the CLI.
			// Standalone (non-MSI) installs have no ServerKitAgent service
			// to restart — the credentials on disk are all the pairing
			// produces, and the agent runtime starts separately. Skip the
			// restart cleanly in that case instead of surfacing 1060.
			if !isServiceInstalled() {
				p.log.Info("ServerKitAgent service not installed; skipping post-pair restart (standalone mode)")
			} else {
				if err := runServiceCmd("stop"); err != nil {
					p.log.Info("Service stop reported error (likely already stopped)", "error", err)
				}
				// sc.exe returns once SCM accepts the stop request, not when the
				// service is fully stopped. Issuing sc start while the service is
				// still STOP_PENDING fails with 1056 ("instance already running"),
				// so wait until SCM reports STOPPED before starting.
				if err := waitForServiceStopped(15 * time.Second); err != nil {
					p.log.Info("Service did not reach STOPPED before start", "error", err)
				}
				if err := runServiceCmd("start"); err != nil {
					p.log.Error("Failed to start service after pairing", "error", err)
					p.mu.Lock()
					p.state = "error"
					p.errMsg = "Pairing succeeded but the agent service failed to start: " + err.Error() +
						"\n\nTry: restart the machine, or open Actions → Restart agent."
					p.mu.Unlock()
					return
				}
			}
			// sc start returns as soon as the SCM accepts the request, not
			// when the service is actually running. Poll for state=RUNNING
			// so the wizard's "claimed" stage reflects reality.
			if err := waitForServiceRunning(20 * time.Second); err != nil {
				p.log.Error("Service did not reach RUNNING after pairing", "error", err)
				p.mu.Lock()
				p.state = "error"
				p.errMsg = "Pairing succeeded but the agent service didn't come up within 20s. " +
					"This usually means another agent process is holding port 19780 — " +
					"try ending all serverkit-agent.exe processes from Task Manager and reopen the wizard.\n\n" +
					"Detail: " + err.Error()
				p.mu.Unlock()
				return
			}
			p.log.Info("Agent service running after pair", "server", serverName)
		},
		OnError: func(err error) {
			p.mu.Lock()
			// Cancellation isn't a "failure" the UI should surface.
			if !errors.Is(err, context.Canceled) {
				p.state = "error"
				p.errMsg = err.Error()
			}
			p.mu.Unlock()
		},
	}

	go pairdriver.Run(ctx, p.log, p.configPath, req.PanelURL, pass, req.ServerName, cb)

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *pairer) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	resp := pairStateResponse{
		State:         p.state,
		Code:          p.code,
		CodeFormatted: p.codeFmt,
		Passphrase:    p.pass,
		PanelURL:      p.panelURL,
		ServerName:    p.server,
		Error:         p.errMsg,
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (p *pairer) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.state = "idle"
	p.code = ""
	p.codeFmt = ""
	p.pass = ""
	p.errMsg = ""
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type connStringRequest struct {
	ConnectionString string `json:"connection_string"`
}

// handleConnectionString accepts a single sk1://… connection string,
// decodes it into a panel URL + registration token, and runs the legacy
// /api/v1/servers/register flow against the panel — the same one the
// `serverkit-agent register` CLI uses. We reuse the existing pairer
// state machine ("enrolling" -> "claimed") so the React wizard's polling
// loop doesn't need a separate state for this entry path.
//
// Note: this bypasses the pair-code/passphrase flow entirely. The token
// inside the connection string IS the credential — the panel mints the
// agent's permanent api_key/api_secret server-side once we POST to
// /register, which is exactly what the operator wanted: "one string from
// the panel, one paste in the agent."
func (p *pairer) handleConnectionString(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req connStringRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	decoded, err := connstring.Decode(req.ConnectionString)
	if err != nil {
		// Surface decoder errors directly: "unknown version" / "missing
		// url or token" are actionable for the user, where as a generic
		// "invalid input" wouldn't tell them whether to regenerate or
		// upgrade.
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	panelURL := pairdriver.NormalizePanelURL(decoded.URL)

	// Mark the pairer state machine "in-flight" so the wizard's poll
	// loop renders a spinner instead of bouncing back to the form.
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.state = "enrolling"
	p.errMsg = ""
	p.code = ""
	p.codeFmt = ""
	p.pass = ""
	p.panelURL = panelURL
	p.server = ""
	p.mu.Unlock()

	go p.runConnectionStringFlow(ctx, panelURL, decoded.Token)

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// runConnectionStringFlow performs the actual register + persist + service
// restart sequence. Mirrors the OnClaimed path of the pair-code flow so
// the user-visible end state ("agent running, panel reconnected") is
// identical regardless of which entry path they took.
func (p *pairer) runConnectionStringFlow(ctx context.Context, panelURL, token string) {
	reg := agent.NewRegistration(p.log)

	result, err := reg.Register(panelURL, token, "")
	if err != nil {
		p.failConnString("register: " + err.Error())
		return
	}
	if ctx.Err() != nil {
		// User clicked Cancel between the network call and the save.
		return
	}

	if err := saveRegistrationCredentials(p.configPath, panelURL, result); err != nil {
		p.failConnString("save credentials: " + err.Error())
		return
	}

	p.mu.Lock()
	p.state = "claimed"
	p.server = result.Name
	p.mu.Unlock()

	// Same restart-and-verify dance as the pair-code claim path. Earlier
	// versions skipped this and left users staring at "successfully
	// paired" on a service that never actually picked up the new config.
	// Standalone (non-MSI) installs have no service to restart; pairing
	// is still complete because the credentials are on disk.
	if !isServiceInstalled() {
		p.log.Info("ServerKitAgent service not installed; skipping post-pair restart (standalone mode)")
		return
	}
	if err := runServiceCmd("stop"); err != nil {
		p.log.Info("Service stop reported error (likely already stopped)", "error", err)
	}
	// Wait for STOPPED before starting — issuing sc start during
	// STOP_PENDING fails with 1056 ("instance already running").
	if err := waitForServiceStopped(15 * time.Second); err != nil {
		p.log.Info("Service did not reach STOPPED before start", "error", err)
	}
	if err := runServiceCmd("start"); err != nil {
		p.log.Error("Failed to start service after pairing", "error", err)
		p.failConnString("Pairing succeeded but the agent service failed to start: " + err.Error() +
			"\n\nTry: restart the machine, or open Actions → Restart agent.")
		return
	}
	if err := waitForServiceRunning(20 * time.Second); err != nil {
		p.log.Error("Service did not reach RUNNING after pairing", "error", err)
		p.failConnString("Pairing succeeded but the agent service didn't come up within 20s. " +
			"This usually means another agent process is holding port 19780 — " +
			"try ending all serverkit-agent.exe processes from Task Manager and reopen the wizard.\n\n" +
			"Detail: " + err.Error())
		return
	}
	p.log.Info("Agent service running after connection-string pair", "server", result.Name)
}

func (p *pairer) failConnString(msg string) {
	p.mu.Lock()
	p.state = "error"
	p.errMsg = msg
	p.mu.Unlock()
}

// saveRegistrationCredentials persists the result of a /register call to
// disk in the same shape as pairdriver.saveCredentials does for the
// claim flow. Lives here rather than in registration.go because the CLI
// `register` command does its own (slightly older-shaped) save and we
// don't want to disturb that path.
func saveRegistrationCredentials(configPath, panelURL string, r *agent.RegistrationResult) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.Default()
	}
	wsURL := strings.TrimSuffix(panelURL, "/")
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	cfg.Server.URL = wsURL + "/agent"
	cfg.Agent.ID = r.AgentID
	cfg.Agent.Name = r.Name
	cfg.Auth.APIKey = r.APIKey
	cfg.Auth.APISecret = r.APISecret

	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	return cfg.SaveCredentials()
}

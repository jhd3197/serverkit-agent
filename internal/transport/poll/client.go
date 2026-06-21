// Package poll implements the REST long-poll fallback transport.
//
// Used when WS-incompatible tunnels (free-tier ngrok, Cloudflare quick
// tunnels) corrupt WebSocket frames. Endpoints (panel side):
//
//   POST /api/v1/agent/connect    — HMAC auth, returns session_token
//   POST /api/v1/agent/poll       — heartbeat + long-poll for commands
//   POST /api/v1/agent/result     — command result
//   POST /api/v1/agent/disconnect — clean shutdown
//
// Streams (logs/metrics fan-out, terminal) are intentionally dropped —
// streaming features degrade to "view recent only" via the panel REST API.
package poll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/transport"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// Version is the agent version string surfaced in the User-Agent
// header. Defaults to "dev"; main.go's init() mirrors the ldflags-set
// main.Version into this on release builds. Was previously a hardcoded
// "dev" literal which made the panel display "ServerKit-Agent-Poll/dev"
// regardless of the actual built version.
var Version = "dev"

// Client is the polling-mode transport. Mirrors the surface of ws.Client
// so agent.Agent doesn't need to know which transport is wired up.
type Client struct {
	cfg     config.ServerConfig
	auth    *auth.Authenticator
	log     *logger.Logger
	http    *http.Client
	handler transport.MessageHandler

	mu      sync.Mutex
	session *auth.SessionToken
	connected atomic.Bool

	// Heartbeat metrics buffered between /poll requests. Updated when
	// SendHeartbeat is called; read and cleared by the poll loop.
	hbMu      sync.Mutex
	hbMetrics *protocol.HeartbeatMetrics
	// One-shot system info, sent on the first /poll after it's queued.
	sysInfo  map[string]interface{}
	// One-shot capabilities, sent on the first /poll after it's queued.
	// Re-queued on every reconnect by agent.connectionWatcher so the
	// panel's record stays current after a panel restart.
	caps map[string]interface{}

	baseURL string
}

// NewClient constructs a poll-mode client. baseURL is derived from the
// configured server URL — wss://host/agent → https://host. The agent
// already gets an http(s) scheme out of buildBaseURL.
func NewClient(cfg config.ServerConfig, authenticator *auth.Authenticator, log *logger.Logger) *Client {
	c := &Client{
		cfg:  cfg,
		auth: authenticator,
		log:  log.WithComponent("poll"),
		http: &http.Client{
			Timeout: 35 * time.Second, // > server long-poll window (25s)
		},
	}
	if os.Getenv("SERVERKIT_INSECURE_TLS") == "true" {
		c.http.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	c.baseURL = buildBaseURL(cfg.URL)
	return c
}

// buildBaseURL converts the configured ws(s) server URL to its http(s)
// equivalent and strips the namespace path. Examples:
//   wss://panel.example.com/agent  →  https://panel.example.com
//   ws://localhost:5000/agent      →  http://localhost:5000
func buildBaseURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	u.Path = ""
	u.RawQuery = ""
	return strings.TrimRight(u.String(), "/")
}

func (c *Client) SetHandler(h transport.MessageHandler) { c.handler = h }
func (c *Client) Mode() transport.Mode                  { return transport.ModePoll }
func (c *Client) Session() *auth.SessionToken {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}
func (c *Client) IsConnected() bool { return c.connected.Load() }

// Run authenticates, then runs the long-poll loop until ctx is cancelled
// or auth fails irrecoverably. Reconnects on transient errors.
func (c *Client) Run(ctx context.Context) error {
	if err := c.connect(ctx); err != nil {
		return fmt.Errorf("poll connect: %w", err)
	}
	c.log.Info("Connected via polling transport", "base", c.baseURL)
	defer c.disconnect()

	backoff := 1 * time.Second
	const backoffMax = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.pollOnce(ctx)
		if err == nil {
			backoff = 1 * time.Second
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Transient — back off and retry. Fatal-class errors (401)
		// are re-handled by re-authenticating.
		c.log.Warn("Poll cycle failed", "error", err, "backoff", backoff)
		c.connected.Store(false)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < backoffMax {
			backoff *= 2
		}
		if isAuthError(err) {
			if cerr := c.connect(ctx); cerr != nil {
				c.log.Warn("Re-auth failed", "error", cerr)
			} else {
				c.log.Info("Re-authenticated polling session")
				backoff = 1 * time.Second
			}
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	timestamp := time.Now().UnixMilli()
	nonce := auth.GenerateNonce()
	signature := c.auth.SignMessageWithNonce(timestamp, nonce)

	body := map[string]interface{}{
		"agent_id":       c.auth.AgentID(),
		"api_key_prefix": c.auth.GetAPIKeyPrefix(),
		"signature":      signature,
		"timestamp":      timestamp,
		"nonce":          nonce,
	}
	var resp struct {
		Success      bool   `json:"success"`
		SessionToken string `json:"session_token"`
		ServerID     string `json:"server_id"`
		PollInterval int    `json:"poll_interval_s"`
		Error        string `json:"error"`
	}
	if err := c.postJSON(ctx, "/api/v1/agent/connect", "", body, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("auth rejected: %s", resp.Error)
	}
	c.mu.Lock()
	c.session = &auth.SessionToken{
		Token:     resp.SessionToken,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	c.mu.Unlock()
	c.connected.Store(true)
	return nil
}

func (c *Client) disconnect() {
	c.mu.Lock()
	tok := ""
	if c.session != nil {
		tok = c.session.Token
	}
	c.mu.Unlock()
	if tok == "" {
		return
	}
	// Best-effort, don't block — server cleans up on heartbeat timeout
	// regardless. Use a short context so shutdown isn't held up.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.postJSON(ctx, "/api/v1/agent/disconnect", tok, nil, nil)
	c.connected.Store(false)
}

// pollOnce executes a single /poll request, dispatches any returned
// commands through the handler, and sends a one-shot system_info
// payload if queued. Returns the request error, if any.
func (c *Client) pollOnce(ctx context.Context) error {
	c.mu.Lock()
	tok := ""
	if c.session != nil {
		tok = c.session.Token
	}
	c.mu.Unlock()
	if tok == "" {
		return fmt.Errorf("no session")
	}

	// Don't drain the system_info / capabilities buffers here. They
	// get refreshed by the agent every 5–60s anyway, and if /poll
	// fails (tunnel reconnect, transient 5xx) the previous behaviour
	// was to silently lose the payload — the panel would then show
	// "none reported" until the next sendCapabilities tick. Re-sending
	// the same payload on every /poll is cheap and the panel's
	// update_capabilities is idempotent (pure overwrite).
	c.hbMu.Lock()
	body := map[string]interface{}{}
	if c.hbMetrics != nil {
		body["metrics"] = c.hbMetrics
	}
	if c.sysInfo != nil {
		body["system_info"] = c.sysInfo
	}
	if c.caps != nil {
		body["capabilities"] = c.caps
	}
	c.hbMu.Unlock()

	var resp struct {
		Commands []json.RawMessage `json:"commands"`
		Ack      bool              `json:"ack"`
	}
	if err := c.postJSON(ctx, "/api/v1/agent/poll", tok, body, &resp); err != nil {
		return err
	}
	c.connected.Store(true)

	for _, cmd := range resp.Commands {
		c.dispatchCommand(cmd)
	}
	return nil
}

// dispatchCommand routes a server-issued command to the agent's
// MessageHandler. The wire format mirrors what AgentNamespace emits.
func (c *Client) dispatchCommand(payload json.RawMessage) {
	if c.handler == nil {
		c.log.Warn("Dropping command — no handler installed")
		return
	}
	c.handler(protocol.TypeCommand, []byte(payload))
}

// SendHeartbeat buffers metrics for the next /poll request.
func (c *Client) SendHeartbeat(metrics protocol.HeartbeatMetrics) error {
	c.hbMu.Lock()
	defer c.hbMu.Unlock()
	m := metrics
	c.hbMetrics = &m
	return nil
}

// SendCommandResult posts the outcome of a server-issued command.
func (c *Client) SendCommandResult(commandID string, success bool, data interface{}, errMsg string, duration time.Duration) error {
	c.mu.Lock()
	tok := ""
	if c.session != nil {
		tok = c.session.Token
	}
	c.mu.Unlock()
	body := map[string]interface{}{
		"command_id": commandID,
		"success":    success,
		"data":       data,
		"error":      errMsg,
		"duration":   int64(duration.Milliseconds()),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.postJSON(ctx, "/api/v1/agent/result", tok, body, nil)
}

// SendStream is a no-op in poll mode — streaming features degrade to
// "view recent only" via the panel's REST API. We log at debug because
// the agent emits these often (system metrics fan-out) and warning-level
// would flood desktop.log.
func (c *Client) SendStream(channel string, data interface{}) error {
	c.log.Debug("Dropping stream in poll mode", "channel", channel)
	return nil
}

// SendError is best-effort — embed in next /poll body. Acceptable to
// drop because errors are also persisted server-side via heartbeat
// metadata in most cases.
func (c *Client) SendError(code, details string) error {
	c.log.Warn("Agent error in poll mode", "code", code, "details", details)
	return nil
}

// Send is the catch-all for protocol packets that don't fit the
// dedicated methods. The polling protocol only handles the explicit
// methods, so we surface a soft warning rather than fail.
func (c *Client) Send(msg interface{}) error {
	// Special-case system_info because the agent emits it on connect.
	if m, ok := msg.(map[string]interface{}); ok {
		if t, _ := m["type"].(string); t == string(protocol.TypeSystemInfo) {
			info, _ := m["info"].(map[string]interface{})
			c.hbMu.Lock()
			c.sysInfo = info
			c.hbMu.Unlock()
			return nil
		}
	}
	// Typed SystemInfoMessage path — the agent ships these on connect
	// and on a periodic cadence so the panel can persist CPU/memory/
	// disk/docker info. Round-trip through JSON to extract the inner
	// info field without a struct dependency in this layer.
	if sm, ok := msg.(protocol.SystemInfoMessage); ok {
		buf, err := json.Marshal(sm.Info)
		if err != nil {
			return err
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(buf, &raw); err != nil {
			return err
		}
		c.hbMu.Lock()
		c.sysInfo = raw
		c.hbMu.Unlock()
		return nil
	}
	// Capabilities arrive as a typed struct (CapabilitiesMessage), not
	// a map — round-trip through JSON to lift the inner fields out
	// without growing this layer a Go-typed dependency on the
	// protocol message shape.
	if cm, ok := msg.(protocol.CapabilitiesMessage); ok {
		buf, err := json.Marshal(cm)
		if err != nil {
			return err
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(buf, &raw); err != nil {
			return err
		}
		// Strip the envelope (type/id/timestamp/signature) — the panel
		// poll endpoint cares about the inner payload.
		delete(raw, "type")
		delete(raw, "id")
		delete(raw, "timestamp")
		delete(raw, "signature")
		c.hbMu.Lock()
		c.caps = raw
		c.hbMu.Unlock()
		return nil
	}
	c.log.Debug("Dropping unsupported Send in poll mode")
	return nil
}

func (c *Client) Close() error {
	c.disconnect()
	return nil
}

// postJSON sends a JSON body and decodes a JSON response. Empty body or
// out is allowed for endpoints that don't have one.
func (c *Client) postJSON(ctx context.Context, path, token string, body interface{}, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ServerKit-Agent-Poll/"+Version)
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errAuth
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

var errAuth = fmt.Errorf("session unauthorized")

func isAuthError(err error) bool {
	return err != nil && (err == errAuth || strings.Contains(err.Error(), "session unauthorized"))
}

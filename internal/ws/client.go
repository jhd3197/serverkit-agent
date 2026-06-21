package ws

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/transport"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// Version is the agent version string surfaced in the User-Agent
// header. Defaults to "dev"; main.go's init() mirrors the ldflags-set
// main.Version into this when a release build runs.
var Version = "dev"

func agentVersion() string { return Version }

// MessageHandler is the callback fired on inbound packets. Aliased to the
// transport package so ws.Client implements transport.Transport without
// adapter glue.
type MessageHandler = transport.MessageHandler

// Client is a Socket.IO client with auto-reconnect
type Client struct {
	cfg           config.ServerConfig
	auth          *auth.Authenticator
	log           *logger.Logger
	conn          *websocket.Conn
	handler       MessageHandler
	session       *auth.SessionToken

	mu            sync.RWMutex
	connected     bool
	reconnecting  bool
	lastErr       error
	everConnected bool

	sendCh        chan []byte
	doneCh        chan struct{}

	reconnectCount int

	// Socket.IO namespace
	namespace string
	// Engine.IO ping interval from server
	pingInterval time.Duration
	pingTimeout  time.Duration
}

// NewClient creates a new WebSocket client
func NewClient(cfg config.ServerConfig, authenticator *auth.Authenticator, log *logger.Logger) *Client {
	return &Client{
		cfg:       cfg,
		auth:      authenticator,
		log:       log.WithComponent("websocket"),
		sendCh:    make(chan []byte, 100),
		doneCh:    make(chan struct{}),
		namespace: "/agent",
	}
}

// SetHandler sets the message handler
func (c *Client) SetHandler(handler MessageHandler) {
	c.handler = handler
}

// buildSocketIOURL converts the configured server URL to a Socket.IO WebSocket URL.
// Input examples:
//   - "wss://server.example.com/agent"
//   - "ws://localhost:5000/agent"
//
// Output: "wss://server.example.com/socket.io/?EIO=4&transport=websocket"
func (c *Client) buildSocketIOURL() (string, error) {
	rawURL := c.cfg.URL
	if rawURL == "" {
		return "", fmt.Errorf("server URL is empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	// Keep the scheme (ws/wss), strip the path (e.g. /agent)
	parsed.Path = "/socket.io/"
	q := url.Values{}
	q.Set("EIO", "4")
	q.Set("transport", "websocket")
	parsed.RawQuery = q.Encode()

	return parsed.String(), nil
}

// Connect establishes a Socket.IO connection over WebSocket
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	sioURL, err := c.buildSocketIOURL()
	if err != nil {
		return err
	}

	// Compression default: off. Some tunnel intermediaries (free-tier ngrok,
	// trycloudflare.com quick tunnels) corrupt compressed WebSocket frames —
	// gorilla then rejects them with "RSV1 set, FIN not set on control". The
	// env var override exists for users behind a *permanent* cf tunnel or a
	// reverse proxy that handles WS compression cleanly: setting
	// SERVERKIT_WS_COMPRESSION=true makes the agent negotiate permessage-
	// deflate, which is necessary if the panel/proxy unconditionally sends
	// compressed frames regardless of negotiation.
	enableCompression := os.Getenv("SERVERKIT_WS_COMPRESSION") == "true"
	dialer := websocket.Dialer{
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: enableCompression,
	}

	// Only allow insecure TLS when explicitly set via environment variable
	if os.Getenv("SERVERKIT_INSECURE_TLS") == "true" {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Add authentication headers
	headers := http.Header{}
	headers.Set("X-Agent-ID", c.auth.AgentID())
	headers.Set("X-API-Key-Prefix", c.auth.GetAPIKeyPrefix())
	headers.Set("User-Agent", fmt.Sprintf("ServerKit-Agent/%s", agentVersion()))
	// Bypass ngrok's interstitial / browser-warning behaviour for free-tier
	// tunnels. Harmless when the panel isn't behind ngrok.
	headers.Set("ngrok-skip-browser-warning", "true")

	c.log.Debug("Connecting to Socket.IO", "url", sioURL)

	conn, resp, err := dialer.DialContext(ctx, sioURL, headers)
	if err != nil {
		if resp != nil {
			c.log.Error("Connection failed",
				"error", err,
				"status", resp.StatusCode,
			)
		}
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Step 1: Read Engine.IO OPEN packet
	if err := c.handleEngineIOOpen(); err != nil {
		conn.Close()
		// "RSV1 set, FIN not set on control" is the classic signature of a
		// tunnel intermediary (cf quick tunnels, free-tier ngrok) injecting
		// or corrupting WebSocket compression. The user can't fix the panel
		// from the agent side — the only useful action is "try a different
		// transport." Surface that explicitly so the error stops being
		// cryptic.
		if strings.Contains(err.Error(), "RSV1 set") {
			c.log.Error("WebSocket frame compression conflict — likely caused by the tunnel between agent and panel",
				"hint", "try SERVERKIT_WS_COMPRESSION=true, or switch from a Cloudflare quick tunnel (*.trycloudflare.com) to a permanent named tunnel, or front the panel with a direct HTTPS reverse proxy",
			)
		}
		return fmt.Errorf("engine.io handshake failed: %w", err)
	}

	// Step 2: Connect to Socket.IO namespace
	if err := c.connectNamespace(); err != nil {
		conn.Close()
		return fmt.Errorf("namespace connect failed: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.reconnecting = false
	c.reconnectCount = 0
	c.mu.Unlock()

	c.log.Info("Connected to server via Socket.IO")

	// Step 3: Authenticate via Socket.IO event
	if err := c.authenticate(); err != nil {
		c.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	return nil
}

// handleEngineIOOpen reads and processes the Engine.IO OPEN packet (type 0)
func (c *Client) handleEngineIOOpen() error {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read OPEN packet: %w", err)
	}
	c.conn.SetReadDeadline(time.Time{})

	msgStr := string(msg)
	c.log.Debug("Received Engine.IO packet", "raw", msgStr)

	// Engine.IO OPEN packet starts with '0'
	if len(msgStr) < 2 || msgStr[0] != '0' {
		return fmt.Errorf("expected OPEN packet (0), got: %s", msgStr)
	}

	// Parse the JSON payload
	var openData struct {
		SID          string `json:"sid"`
		Upgrades     []string `json:"upgrades"`
		PingInterval int    `json:"pingInterval"`
		PingTimeout  int    `json:"pingTimeout"`
	}
	if err := json.Unmarshal([]byte(msgStr[1:]), &openData); err != nil {
		return fmt.Errorf("failed to parse OPEN data: %w", err)
	}

	c.pingInterval = time.Duration(openData.PingInterval) * time.Millisecond
	c.pingTimeout = time.Duration(openData.PingTimeout) * time.Millisecond

	c.log.Debug("Engine.IO handshake complete",
		"sid", openData.SID,
		"pingInterval", c.pingInterval,
		"pingTimeout", c.pingTimeout,
	)

	return nil
}

// connectNamespace sends a Socket.IO CONNECT packet to the /agent namespace
func (c *Client) connectNamespace() error {
	// Socket.IO CONNECT: packet type 4 (MESSAGE) + message type 0 (CONNECT) + namespace
	// Wire format: "40/agent,"
	connectMsg := fmt.Sprintf("40%s,", c.namespace)
	c.log.Debug("Connecting to namespace", "namespace", c.namespace, "packet", connectMsg)

	if err := c.conn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		return fmt.Errorf("failed to send CONNECT: %w", err)
	}

	// Read namespace CONNECT ack
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read CONNECT ack: %w", err)
	}
	c.conn.SetReadDeadline(time.Time{})

	msgStr := string(msg)
	c.log.Debug("Received namespace response", "raw", msgStr)

	// Expected: "40/agent,{\"sid\":\"...\"}"
	// Or error: "44/agent,{\"message\":\"...\"}"
	prefix := fmt.Sprintf("40%s,", c.namespace)
	errorPrefix := fmt.Sprintf("44%s,", c.namespace)

	if strings.HasPrefix(msgStr, errorPrefix) {
		return fmt.Errorf("namespace connection rejected: %s", msgStr)
	}

	if !strings.HasPrefix(msgStr, prefix) {
		return fmt.Errorf("unexpected namespace response: %s", msgStr)
	}

	c.log.Info("Connected to namespace", "namespace", c.namespace)
	return nil
}

// authenticate sends an "auth" Socket.IO event and waits for response
func (c *Client) authenticate() error {
	timestamp := time.Now().UnixMilli()
	nonce := auth.GenerateNonce()
	signature := c.auth.SignMessageWithNonce(timestamp, nonce)

	authData := map[string]interface{}{
		"type":           "auth",
		"agent_id":       c.auth.AgentID(),
		"api_key_prefix": c.auth.GetAPIKeyPrefix(),
		"nonce":          nonce,
		"timestamp":      timestamp,
		"signature":      signature,
	}

	c.log.Debug("Sending authentication event")

	if err := c.emitEvent("auth", authData); err != nil {
		return fmt.Errorf("failed to send auth event: %w", err)
	}

	// Wait for auth response event
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read auth response: %w", err)
		}

		msgStr := string(msg)

		// Handle Engine.IO ping during auth
		if msgStr == "2" {
			c.conn.WriteMessage(websocket.TextMessage, []byte("3"))
			continue
		}

		eventName, eventData, err := c.parseEvent(msgStr)
		if err != nil {
			c.log.Debug("Ignoring non-event message during auth", "raw", msgStr)
			continue
		}

		switch eventName {
		case "auth_ok":
			var response struct {
				Type         string `json:"type"`
				SessionToken string `json:"session_token"`
				Expires      int64  `json:"expires"`
				ServerID     string `json:"server_id"`
			}
			if err := json.Unmarshal(eventData, &response); err != nil {
				return fmt.Errorf("failed to parse auth_ok: %w", err)
			}

			c.session = &auth.SessionToken{
				Token:     response.SessionToken,
				ExpiresAt: time.UnixMilli(response.Expires),
			}

			c.log.Info("Authentication successful",
				"expires_in", time.Until(c.session.ExpiresAt).Round(time.Second),
			)
			return nil

		case "auth_fail":
			var response struct {
				Type  string `json:"type"`
				Error string `json:"error"`
			}
			json.Unmarshal(eventData, &response)
			return fmt.Errorf("authentication rejected: %s", response.Error)

		default:
			c.log.Debug("Ignoring event during auth", "event", eventName)
		}
	}
}

// emitEvent sends a Socket.IO EVENT packet
// Wire format: 42/agent,["event_name",{data}]
func (c *Client) emitEvent(event string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Build Socket.IO EVENT: 42/namespace,["event",data]
	eventJSON := fmt.Sprintf(`42%s,["%s",%s]`, c.namespace, event, string(dataBytes))

	return c.conn.WriteMessage(websocket.TextMessage, []byte(eventJSON))
}

// parseEvent parses a Socket.IO EVENT packet and returns event name + data
// Expected format: 42/agent,["event_name",{data}]
func (c *Client) parseEvent(msg string) (string, json.RawMessage, error) {
	prefix := fmt.Sprintf("42%s,", c.namespace)
	if !strings.HasPrefix(msg, prefix) {
		return "", nil, fmt.Errorf("not a Socket.IO EVENT for namespace %s", c.namespace)
	}

	payload := msg[len(prefix):]

	// Parse as JSON array: ["event_name", data]
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(payload), &arr); err != nil {
		return "", nil, fmt.Errorf("failed to parse event array: %w", err)
	}

	if len(arr) < 1 {
		return "", nil, fmt.Errorf("empty event array")
	}

	// Extract event name (first element is a string)
	var eventName string
	if err := json.Unmarshal(arr[0], &eventName); err != nil {
		return "", nil, fmt.Errorf("failed to parse event name: %w", err)
	}

	// Data is the second element (may be absent)
	var eventData json.RawMessage
	if len(arr) > 1 {
		eventData = arr[1]
	}

	return eventName, eventData, nil
}

// Run starts the read/write loops and handles reconnection
func (c *Client) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			c.Close()
			return ctx.Err()
		default:
		}

		// Connect if not connected
		c.mu.RLock()
		connected := c.connected
		c.mu.RUnlock()

		if !connected {
			if err := c.Connect(ctx); err != nil {
				c.log.Warn("Connection failed", "error", err)
				c.mu.Lock()
				c.lastErr = err
				c.mu.Unlock()
				c.handleReconnect(ctx)
				continue
			}
			c.mu.Lock()
			c.everConnected = true
			c.lastErr = nil
			c.mu.Unlock()
		}

		// Per-iteration ctx so we can cancel readLoop/writeLoop/pingLoop
		// together when any one of them errors. The previous code only
		// read the first error off errCh and let the other two
		// goroutines leak until the next reconnect's conn.Close
		// happened to cause a read error in them — every flap leaked
		// goroutines that, in tunnel-flap scenarios, accumulated
		// quickly. With per-iteration cancellation each connection
		// owns exactly three goroutines for its lifetime.
		loopCtx, cancelLoop := context.WithCancel(ctx)
		errCh := make(chan error, 3)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			errCh <- c.readLoop(loopCtx)
		}()
		go func() {
			defer wg.Done()
			errCh <- c.writeLoop(loopCtx)
		}()
		go func() {
			defer wg.Done()
			errCh <- c.pingLoop(loopCtx)
		}()

		// Wait for error
		err := <-errCh
		c.log.Warn("Connection loop ended", "error", err)

		// Mark as disconnected before draining sendCh so any
		// concurrent Send() callers see the disconnected state and
		// fail fast rather than queueing onto a buffer about to
		// be flushed.
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()

		// Cancel siblings and close the conn so readLoop unblocks
		// from its read deadline. Then wait for both siblings to
		// drain their error onto errCh — leaving them running was
		// the goroutine leak.
		cancelLoop()
		if c.conn != nil {
			c.conn.Close()
		}
		wg.Wait()
		// Drain the remaining errCh entries so the channel doesn't
		// retain references to err values.
		for len(errCh) > 0 {
			<-errCh
		}

		// Drain stale messages buffered while the previous connection
		// was already failing. Replaying these on a fresh session
		// would ship heartbeats/results from a dead WS to a new auth
		// context — and worse, if the buffer ever filled mid-flap,
		// every subsequent Send() would return "send channel full"
		// permanently. Replace the channel with a fresh one so we
		// also drop any blocked senders cleanly.
		c.drainSendCh()

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			c.handleReconnect(ctx)
		}
	}
}

// drainSendCh empties any pending outbound messages from the previous
// connection. Called after a disconnect so we don't ship stale frames
// (heartbeats, command results) on the next session — they were
// computed against the old auth context and the panel will either
// reject them or attribute them to the wrong session window.
func (c *Client) drainSendCh() {
	for {
		select {
		case <-c.sendCh:
		default:
			return
		}
	}
}

// readLoop reads Socket.IO messages from the WebSocket
func (c *Client) readLoop(ctx context.Context) error {
	// Read deadline = pingInterval * 2.5 + 5s grace. Any inbound message
	// (server ping, app frame, WS-level pong) resets the deadline. If
	// nothing arrives within this window, the connection is presumed
	// dead at the network layer and the read errors out, which is what
	// the Manager's flap detector relies on. Without this, CF/ngrok
	// killing the connection at the network layer (without sending a
	// WS close frame) makes ReadMessage hang for minutes — exactly the
	// "ws_disconnected every 2-3 min" pattern in the user's events.json.
	readWait := c.pingInterval*5/2 + 5*time.Second
	if readWait < 30*time.Second {
		readWait = 30 * time.Second
	}
	resetDeadline := func() {
		_ = c.conn.SetReadDeadline(time.Now().Add(readWait))
	}
	resetDeadline()
	c.conn.SetPongHandler(func(string) error {
		resetDeadline()
		return nil
	})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}
		// Any successful read = liveness signal. Reset the window.
		resetDeadline()

		msgStr := string(msg)

		// Handle Engine.IO PING (server sends "2", we respond "3")
		if msgStr == "2" {
			if err := c.conn.WriteMessage(websocket.TextMessage, []byte("3")); err != nil {
				return fmt.Errorf("failed to send pong: %w", err)
			}
			c.log.Debug("Responded to Engine.IO ping")
			continue
		}

		// Handle Engine.IO CLOSE
		if msgStr == "1" {
			return fmt.Errorf("server sent Engine.IO CLOSE")
		}

		// Handle Socket.IO DISCONNECT for our namespace
		disconnectPrefix := fmt.Sprintf("41%s,", c.namespace)
		if strings.HasPrefix(msgStr, disconnectPrefix) || msgStr == "41" {
			return fmt.Errorf("server disconnected namespace %s", c.namespace)
		}

		// Parse Socket.IO EVENT
		eventName, eventData, err := c.parseEvent(msgStr)
		if err != nil {
			c.log.Debug("Ignoring unrecognized message", "raw", msgStr)
			continue
		}

		// Map event name to protocol message type and dispatch
		c.dispatchEvent(eventName, eventData)
	}
}

// dispatchEvent maps a Socket.IO event to the agent's message handler
func (c *Client) dispatchEvent(eventName string, data json.RawMessage) {
	c.log.Debug("Received event", "event", eventName)

	// Map Socket.IO event names to protocol message types
	msgType := protocol.MessageType(eventName)

	// Handle heartbeat ack internally
	if msgType == protocol.TypeHeartbeatAck {
		c.log.Debug("Received heartbeat ack")
		return
	}

	// For events that carry data, we need to reconstruct the full message
	// so the agent handler can unmarshal it as expected
	if c.handler != nil && len(data) > 0 {
		c.handler(msgType, data)
	}
}

// writeLoop writes queued messages via Socket.IO events
func (c *Client) writeLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-c.sendCh:
			// Parse the message to extract the type for the event name
			var base protocol.Message
			if err := json.Unmarshal(msg, &base); err != nil {
				c.log.Warn("Failed to parse outgoing message", "error", err)
				continue
			}

			eventName := string(base.Type)
			eventJSON := fmt.Sprintf(`42%s,["%s",%s]`, c.namespace, eventName, string(msg))

			if err := c.conn.WriteMessage(websocket.TextMessage, []byte(eventJSON)); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
		}
	}
}

// pingLoop sends Engine.IO PING packets to keep the connection alive
func (c *Client) pingLoop(ctx context.Context) error {
	if c.pingInterval <= 0 {
		c.pingInterval = 25 * time.Second
	}

	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.mu.RLock()
			connected := c.connected
			c.mu.RUnlock()

			if !connected {
				return fmt.Errorf("not connected")
			}

			// Engine.IO PING from client side (type 3 = PONG in EIO4 client-initiated)
			// Actually in EIO4, server sends PINGs (2) and client responds with PONGs (3)
			// Client doesn't need to send its own pings, just respond to server's
			// But we'll use this loop to detect stale connections via WriteControl
			if err := c.conn.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(5*time.Second),
			); err != nil {
				return fmt.Errorf("websocket ping failed: %w", err)
			}
		}
	}
}

// handleReconnect implements exponential backoff reconnection
func (c *Client) handleReconnect(ctx context.Context) {
	c.mu.Lock()
	c.reconnecting = true
	c.reconnectCount++
	count := c.reconnectCount
	c.mu.Unlock()

	// Calculate backoff duration
	backoff := c.cfg.ReconnectInterval * time.Duration(1<<uint(count-1))
	if backoff > c.cfg.MaxReconnectInterval {
		backoff = c.cfg.MaxReconnectInterval
	}

	c.log.Info("Reconnecting",
		"attempt", count,
		"backoff", backoff,
	)

	select {
	case <-ctx.Done():
		return
	case <-time.After(backoff):
		return
	}
}

// Send queues a message for sending
func (c *Client) Send(msg interface{}) error {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()
	if !connected {
		// Refuse to queue when there's nothing draining the channel.
		// Otherwise a backlog accumulates while the agent is offline
		// and floods the panel on reconnect with stale heartbeats.
		return fmt.Errorf("not connected")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	select {
	case c.sendCh <- data:
		return nil
	default:
		return fmt.Errorf("send channel full")
	}
}

// SendHeartbeat sends a heartbeat message
func (c *Client) SendHeartbeat(metrics protocol.HeartbeatMetrics) error {
	msg := protocol.HeartbeatMessage{
		Message: protocol.NewMessage(protocol.TypeHeartbeat, auth.GenerateNonce()),
		Metrics: metrics,
	}
	return c.Send(msg)
}

// SendCommandResult sends a command result
func (c *Client) SendCommandResult(commandID string, success bool, data interface{}, errMsg string, duration time.Duration) error {
	var dataBytes json.RawMessage
	if data != nil {
		var err error
		dataBytes, err = json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal data: %w", err)
		}
	}

	msg := protocol.CommandResult{
		Message:   protocol.NewMessage(protocol.TypeCommandResult, auth.GenerateNonce()),
		CommandID: commandID,
		Success:   success,
		Data:      dataBytes,
		Error:     errMsg,
		Duration:  duration.Milliseconds(),
	}
	return c.Send(msg)
}

// SendStream sends streaming data
func (c *Client) SendStream(channel string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	msg := protocol.StreamMessage{
		Message: protocol.NewMessage(protocol.TypeStream, auth.GenerateNonce()),
		Channel: channel,
		Data:    dataBytes,
	}
	return c.Send(msg)
}

// SendError sends an error message
func (c *Client) SendError(code, details string) error {
	msg := protocol.ErrorMessage{
		Message: protocol.NewMessage(protocol.TypeError, auth.GenerateNonce()),
		Code:    code,
		Details: details,
	}
	return c.Send(msg)
}

// IsConnected returns the connection status
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Close closes the WebSocket connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Send close message
		c.conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		c.conn.Close()
		c.conn = nil
	}

	c.connected = false
	return nil
}

// Session returns the current session token
// Mode reports this transport as WS so consumers (UI, log lines) can
// distinguish from the polling fallback.
func (c *Client) Mode() transport.Mode { return transport.ModeWS }

// LastError returns the most recent connect or runloop error, or nil
// when healthy. Used by the transport manager to decide whether to fall
// back to polling — specifically, RSV1/handshake errors indicate a
// tunnel intermediary that won't ever let WS through and we shouldn't
// keep retrying the same dial.
func (c *Client) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}

// EverConnected reports whether the client has successfully completed a
// handshake at least once during this Run. False after several seconds
// is the strongest signal that WS won't ever work for this network.
func (c *Client) EverConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.everConnected
}

func (c *Client) Session() *auth.SessionToken {
	return c.session
}

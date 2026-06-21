// Package transport abstracts the agent ↔ panel link. Two implementations
// share the same surface:
//
//   - ws (internal/ws.Client) — primary, long-lived Socket.IO connection.
//   - poll (internal/transport/poll.Client) — REST long-poll fallback used
//     when WS-incompatible tunnels (free-tier ngrok, cf quick tunnels)
//     mangle WebSocket frames.
//
// agent.Agent talks to a Transport, not a concrete client, and a small
// fallback Manager swaps which one is wired up when WS connectivity
// keeps failing.
package transport

import (
	"context"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// MessageHandler is invoked when an inbound packet (typically a command)
// arrives from the panel. data is the raw JSON payload.
type MessageHandler func(msgType protocol.MessageType, data []byte)

// Mode names a transport implementation. Surfaced through IPC so the UI
// can show "Connected via polling" when the agent has fallen back.
type Mode string

const (
	ModeWS   Mode = "ws"
	ModePoll Mode = "poll"
)

// Transport is the shared surface between WS and polling.
//
// Streaming methods (SendStream) are best-effort — the polling
// implementation drops them silently. Callers must not rely on stream
// delivery for correctness.
type Transport interface {
	// SetHandler installs the inbound message dispatcher.
	SetHandler(MessageHandler)

	// Run blocks until ctx is cancelled or the transport gives up. WS
	// runs the read/write/ping/reconnect loops; poll runs the
	// long-poll loop. Returns the reason it exited so the manager can
	// decide whether to retry, fall back, or surface the error.
	Run(ctx context.Context) error

	// IsConnected reports whether the transport is currently live (WS:
	// authenticated socket open; poll: at least one /poll round-trip
	// succeeded recently).
	IsConnected() bool

	// Send pushes a generic JSON-able message; only meaningful for WS.
	// Polling silently no-ops on these unless they map to a known
	// command result.
	Send(msg interface{}) error

	// SendHeartbeat dispatches metrics. WS sends an event; polling
	// piggybacks on the next /poll request.
	SendHeartbeat(metrics protocol.HeartbeatMetrics) error

	// SendCommandResult delivers the outcome of a command. Both
	// transports route this synchronously.
	SendCommandResult(commandID string, success bool, data interface{}, errMsg string, duration time.Duration) error

	// SendStream pushes streaming data (logs, container output, real-time
	// metrics fan-out). Polling drops these — streaming features
	// degrade naturally to "view recent only" via the panel's REST API.
	SendStream(channel string, data interface{}) error

	// SendError surfaces an error to the panel. Best-effort.
	SendError(code, details string) error

	// Session returns the current session token, or nil if unauthenticated.
	Session() *auth.SessionToken

	// Close terminates the transport.
	Close() error

	// Mode reports which implementation this is.
	Mode() Mode
}

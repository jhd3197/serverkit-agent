package transport

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// wsBackend is the slice of ws.Client functionality the manager needs.
// We avoid importing ws here to keep the dependency graph clean — the
// agent package wires concrete clients in via NewManager.
type wsBackend interface {
	Transport
	LastError() error
	EverConnected() bool
}

// Manager wraps two Transports (WS primary, poll fallback) and presents a
// single Transport surface to the agent. It runs WS first; if WS doesn't
// authenticate within the upgrade deadline OR errors out with a tunnel-
// incompat signature (RSV1, "engine.io handshake failed"), it shuts WS
// down and starts the polling client. The active transport is what every
// Send/SendHeartbeat/etc. call goes to.
//
// Once we've fallen back to polling, we stay there until the process
// restarts. Toggling back and forth would burn through reconnect/auth
// cycles and the whole point of falling back is "this network can't do
// WS." Restart-to-recover is fine — agents reconnect on service start
// and try WS again.
type Manager struct {
	primary  wsBackend
	fallback Transport
	log      *logger.Logger
	handler  MessageHandler

	mu     sync.RWMutex
	active Transport
	mode   atomic.Value // Mode

	// Upgrade deadline: WS gets this long to complete a handshake before
	// we declare it dead and switch to poll.
	upgradeDeadline time.Duration
}

// NewManager constructs a transport manager. Pass the WS client as the
// primary and a poll client as the fallback.
func NewManager(primary wsBackend, fallback Transport, log *logger.Logger) *Manager {
	m := &Manager{
		primary:         primary,
		fallback:        fallback,
		log:             log.WithComponent("transport"),
		upgradeDeadline: 30 * time.Second,
	}
	m.active = primary
	m.mode.Store(primary.Mode())
	return m
}

// SetHandler installs the inbound dispatcher on both backends so a
// transport switch doesn't lose the binding.
func (m *Manager) SetHandler(h MessageHandler) {
	m.handler = h
	m.primary.SetHandler(h)
	m.fallback.SetHandler(h)
}

// Mode reports which transport is currently active.
func (m *Manager) Mode() Mode {
	if v, ok := m.mode.Load().(Mode); ok {
		return v
	}
	return ModeWS
}

func (m *Manager) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.IsConnected()
}

func (m *Manager) Send(msg interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.Send(msg)
}

func (m *Manager) SendHeartbeat(metrics protocol.HeartbeatMetrics) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.SendHeartbeat(metrics)
}

func (m *Manager) SendCommandResult(commandID string, success bool, data interface{}, errMsg string, duration time.Duration) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.SendCommandResult(commandID, success, data, errMsg, duration)
}

func (m *Manager) SendStream(channel string, data interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.SendStream(channel, data)
}

func (m *Manager) SendError(code, details string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.SendError(code, details)
}

func (m *Manager) Session() *auth.SessionToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.Session()
}

func (m *Manager) Close() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.Close()
}

// Stability thresholds for the WS-flap detector. CF tunnels and other
// proxies can let WS connect successfully but kill it every couple of
// minutes — the symptom your events.json shows is "ws_connected →
// ws_disconnected" cycling forever, which generates pointless reconnect
// traffic without ever delivering live streams. Once we see the
// connection prove itself unstable, drop to polling permanently and
// stop wasting bandwidth on retries.
const (
	wsFlapWindow    = 10 * time.Minute
	wsFlapThreshold = 3 // disconnects within wsFlapWindow that trigger fallback
)

// Run executes the WS transport and watches for tunnel-incompat
// failures. When detected, it cancels WS and runs the poll transport.
// Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	wsCtx, cancelWS := context.WithCancel(ctx)
	defer cancelWS()

	wsDone := make(chan error, 1)
	go func() {
		wsDone <- m.primary.Run(wsCtx)
	}()

	// Watch WS for tunnel-incompat failure within the upgrade deadline.
	// If detected, kill WS and run poll for the rest of ctx's lifetime.
	deadline := time.NewTimer(m.upgradeDeadline)
	defer deadline.Stop()

	check := time.NewTicker(2 * time.Second)
	defer check.Stop()

	// Stability monitor: ticks at 1Hz to sample IsConnected and record
	// transitions. When we see wsFlapThreshold disconnects within
	// wsFlapWindow, give up on WS and run the fallback.
	stabilityTicker := time.NewTicker(1 * time.Second)
	defer stabilityTicker.Stop()
	wasConnected := false
	disconnectTimes := make([]time.Time, 0, wsFlapThreshold+1)

	for {
		select {
		case <-ctx.Done():
			cancelWS()
			<-wsDone
			return ctx.Err()

		case err := <-wsDone:
			// WS exited on its own (rare — its loop runs until ctx is
			// done). If ctx isn't cancelled, treat this as a permanent
			// WS failure and fall back.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			m.log.Warn("WS transport exited; falling back to polling", "error", err)
			return m.runFallback(ctx)

		case <-deadline.C:
			// Soft deadline: WS hasn't authenticated yet. If it never has
			// AND the last error looks like a tunnel issue, fall back.
			// If WS just hasn't connected yet for a benign reason
			// (panel slow to start), give it more rope.
			if !m.primary.EverConnected() {
				lastErr := m.primary.LastError()
				if isTunnelIncompat(lastErr) {
					m.log.Warn("WS handshake failed with a tunnel-incompat signature; falling back to polling",
						"error", lastErr)
					cancelWS()
					<-wsDone
					return m.runFallback(ctx)
				}
				m.log.Info("WS not yet connected after upgrade deadline; continuing to retry",
					"last_error", lastErr)
			}
			// Stop checking after the soft deadline; if WS is still
			// trying it'll either succeed eventually or stay broken
			// quietly. The user can restart the service to retry from
			// scratch.

		case <-check.C:
			// While WS is still inside the upgrade window, check
			// proactively for unambiguous failure modes that warrant a
			// fast switch instead of waiting out the deadline.
			if !m.primary.EverConnected() {
				if isTunnelIncompat(m.primary.LastError()) {
					m.log.Warn("WS reports tunnel-incompat error; falling back early to polling",
						"error", m.primary.LastError())
					cancelWS()
					<-wsDone
					return m.runFallback(ctx)
				}
			} else {
				// WS got through. Stop the deadline timer — we're good.
				deadline.Stop()
			}

		case now := <-stabilityTicker.C:
			// Sample the WS connection state and detect flap patterns:
			// repeatedly connecting then dropping within minutes
			// indicates an intermediary (CF tunnel, ngrok, NAT timeout)
			// that won't keep a long-lived WS open. Counting drops in a
			// sliding window catches both rapid churn and the slower
			// "drops every couple minutes" pattern reported in
			// events.json.
			isConn := m.primary.IsConnected()
			if !isConn && wasConnected {
				disconnectTimes = append(disconnectTimes, now)
				// Trim drops outside the window.
				cutoff := now.Add(-wsFlapWindow)
				kept := disconnectTimes[:0]
				for _, t := range disconnectTimes {
					if t.After(cutoff) {
						kept = append(kept, t)
					}
				}
				disconnectTimes = kept
				m.log.Info("WS disconnected", "drops_in_window", len(disconnectTimes))
				if len(disconnectTimes) >= wsFlapThreshold {
					m.log.Warn("WS connection unstable — falling back to polling permanently",
						"drops", len(disconnectTimes),
						"window_minutes", int(wsFlapWindow.Minutes()))
					cancelWS()
					<-wsDone
					return m.runFallback(ctx)
				}
			}
			wasConnected = isConn
		}
	}
}

func (m *Manager) runFallback(ctx context.Context) error {
	m.mu.Lock()
	m.active = m.fallback
	m.mu.Unlock()
	m.mode.Store(m.fallback.Mode())
	m.log.Info("Active transport switched to polling (streams unavailable in this mode)")
	return m.fallback.Run(ctx)
}

// isTunnelIncompat reports whether err carries one of the known
// signatures of a tunnel intermediary mangling WebSocket frames.
// Matches both "RSV1" frame errors and engine.io handshake failures
// after a successful TCP/TLS dial — both indicate the connection is
// reaching the panel but the WS layer is unusable.
func isTunnelIncompat(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "RSV1 set") ||
		strings.Contains(msg, "engine.io handshake failed") ||
		strings.Contains(msg, "websocket: close 1006") // abnormal closure mid-handshake
}

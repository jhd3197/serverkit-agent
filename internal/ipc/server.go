package ipc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/events"
	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// StatusProvider provides agent status information
type StatusProvider interface {
	GetStatus() AgentStatus
	GetDetailedMetrics() *DetailedMetrics
	GetMetricsHistory() []MetricSample
	GetConnectionInfo() ConnectionInfo
	GetRecentLogs(lines int) []string
	ClearLogs() error
	GetEvents(since int64) []events.Event
	Restart() error
}

// AgentStatus represents the current agent status
type AgentStatus struct {
	Running     bool    `json:"running"`
	Connected   bool    `json:"connected"`
	Registered  bool    `json:"registered"`
	AgentID     string  `json:"agent_id"`
	AgentName   string  `json:"agent_name"`
	ServerURL   string  `json:"server_url"`
	Uptime      int64   `json:"uptime_seconds"`
	Version     string  `json:"version"`
	// Transport reports which link the agent is on right now: "ws" for
	// the primary Socket.IO link, "poll" when WS-incompatible tunnels
	// forced a fallback to the REST polling transport. UI uses this to
	// surface a "limited mode" badge — streams are unavailable in poll.
	Transport   string  `json:"transport,omitempty"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	DiskPercent float64 `json:"disk_percent"`
}

// DetailedMetrics contains detailed system metrics
type DetailedMetrics struct {
	CPU       CPUMetrics    `json:"cpu"`
	Memory    MemoryMetrics `json:"memory"`
	Disk      DiskMetrics   `json:"disk"`
	Network   NetworkMetrics `json:"network"`
	Timestamp int64          `json:"timestamp"`
}

// CPUMetrics contains CPU information
type CPUMetrics struct {
	UsagePercent float64   `json:"usage_percent"`
	PerCPU       []float64 `json:"per_cpu,omitempty"`
	Cores        int       `json:"cores"`
}

// MemoryMetrics contains memory information
type MemoryMetrics struct {
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	UsagePercent float64 `json:"usage_percent"`
}

// DiskMetrics contains disk information
type DiskMetrics struct {
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	UsagePercent float64 `json:"usage_percent"`
}

// NetworkMetrics contains network information
type NetworkMetrics struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// MetricSample is one entry in the agent's CPU/memory ring buffer used by
// the desktop console to render sparklines. Timestamp is unix milliseconds.
type MetricSample struct {
	Timestamp int64   `json:"t"`
	CPU       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
}

// ConnectionInfo contains WebSocket connection details
type ConnectionInfo struct {
	Connected      bool   `json:"connected"`
	ServerURL      string `json:"server_url"`
	ReconnectCount int    `json:"reconnect_count"`
	LastConnected  int64  `json:"last_connected,omitempty"`
	SessionExpires int64  `json:"session_expires,omitempty"`
}

// Server is the IPC HTTP server for tray app communication
type Server struct {
	cfg      config.IPCConfig
	log      *logger.Logger
	server   *http.Server
	provider StatusProvider
	startTime time.Time
	// token is the bearer credential that gates every endpoint except
	// /health. Loaded from disk if present (so a tray app already
	// running survives an agent restart) or generated on first start.
	// Localhost binding alone isn't enough — any local process on the
	// box (browser tab, malicious npm postinstall, low-priv service
	// account) could otherwise read panel URL / agent ID / logs and
	// trigger /restart without authorisation.
	token string
}

// NewServer creates a new IPC server
func NewServer(cfg config.IPCConfig, log *logger.Logger, provider StatusProvider) *Server {
	return &Server{
		cfg:       cfg,
		log:       log.WithComponent("ipc"),
		provider:  provider,
		startTime: time.Now(),
	}
}

// Start starts the IPC HTTP server
func (s *Server) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info("IPC server disabled")
		return nil
	}

	// Load or generate the bearer token before binding the listener.
	// Token failures are fatal — running the IPC API without auth
	// would expose /restart and /logs to any local process.
	//
	// SERVERKIT_IPC_NO_AUTH=true disables the bearer check entirely.
	// This exists for dev environments where the desktop console
	// bundle, asset server, and agent service can't always be
	// rebuilt in lockstep — the auth requires all three to ship
	// together. Logged at WARN every startup so it can't be set
	// silently in production.
	noAuth := os.Getenv("SERVERKIT_IPC_NO_AUTH") == "true"
	if noAuth {
		s.log.Warn("SERVERKIT_IPC_NO_AUTH=true: IPC bearer-token check is DISABLED; only use this for development")
	} else {
		tok, err := loadOrGenerateToken(config.IPCTokenPath())
		if err != nil {
			return fmt.Errorf("ipc token: %w", err)
		}
		s.token = tok
	}

	mux := http.NewServeMux()

	// Register handlers
	handlers := NewHandlers(s.provider, s.log)
	mux.HandleFunc("/status", handlers.HandleStatus)
	mux.HandleFunc("/metrics", handlers.HandleMetrics)
	mux.HandleFunc("/metrics/history", handlers.HandleMetricsHistory)
	mux.HandleFunc("/events", handlers.HandleEvents)
	mux.HandleFunc("/logs/clear", handlers.HandleLogsClear)
	mux.HandleFunc("/connection", handlers.HandleConnection)
	mux.HandleFunc("/logs", handlers.HandleLogs)
	mux.HandleFunc("/restart", handlers.HandleRestart)
	mux.HandleFunc("/health", handlers.HandleHealth)

	addr := fmt.Sprintf("%s:%d", s.cfg.Address, s.cfg.Port)

	// Verify we're only binding to localhost for security
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		s.log.Warn("IPC server can only bind to localhost, forcing 127.0.0.1")
		addr = fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	}

	var handler http.Handler = mux
	if !noAuth {
		handler = authMiddleware(s.token, handler)
	}
	s.server = &http.Server{
		Addr:         addr,
		Handler:      corsMiddleware(handler),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	s.log.Info("Starting IPC server", "address", addr)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Check for immediate startup errors
	select {
	case err := <-errCh:
		return fmt.Errorf("IPC server failed to start: %w", err)
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	// Wait for context cancellation
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

// Stop gracefully stops the IPC server
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}

	s.log.Info("Stopping IPC server")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// corsMiddleware adds CORS headers for local development.
//
// The desktop console's React UI runs on the asset server (127.0.0.1:<random>)
// and calls the IPC server (127.0.0.1:19780) — different ports means CORS
// applies. Authorization must be in Allow-Headers, otherwise the browser
// preflight refuses to forward the bearer token and every IPC request
// arrives unauthenticated → 401 storm. The previous list (just Content-Type)
// was OK before IPC auth existed; with auth required, it silently broke
// the entire desktop console.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow requests from localhost
		origin := r.Header.Get("Origin")
		if origin == "" || isLocalhost(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalhost checks if the origin is from localhost. Strict suffix
// matching against a small allowlist keeps this honest — earlier
// substring slicing was easy to mis-edit and survives only because
// browsers send a fixed-format Origin header.
func isLocalhost(origin string) bool {
	switch origin {
	case "http://localhost", "https://localhost",
		"http://127.0.0.1", "https://127.0.0.1":
		return true
	}
	for _, prefix := range []string{
		"http://localhost:", "https://localhost:",
		"http://127.0.0.1:", "https://127.0.0.1:",
	} {
		if strings.HasPrefix(origin, prefix) {
			return true
		}
	}
	return false
}

// authMiddleware enforces a constant-time bearer-token check on every
// request. /health is exempt so external probes (systemd watchdog,
// external monitoring) can verify the agent is reachable without
// being trusted with the token. Every other endpoint exposes data
// (panel URL, agent ID, logs, metrics) or actions (restart, log
// rotation) that a malicious local process must not reach.
func authMiddleware(expected string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow CORS preflight to pass through; the actual
		// request that follows still has to authenticate.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := bearerToken(r)
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="serverkit-agent"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		// Fallback to query string for places where setting headers
		// is awkward (eg. EventSource URLs in older browsers). The
		// token is only valid on 127.0.0.1 anyway, so this isn't a
		// new exposure.
		return r.URL.Query().Get("token")
	}
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// loadOrGenerateToken returns a per-host IPC bearer token. The file is
// reused across runs so a tray app that picked up the token on first
// launch keeps working through agent restarts; only when the file is
// missing or unreadable do we generate a fresh one.
func loadOrGenerateToken(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(data))
		if len(tok) >= 32 {
			return tok, nil
		}
		// File exists but contents are too short — treat as
		// corrupted and regenerate.
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create token dir: %w", err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", fmt.Errorf("write token: %w", err)
	}
	return tok, nil
}

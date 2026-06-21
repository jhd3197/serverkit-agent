package ipc

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Handlers contains the HTTP handlers for the IPC API
type Handlers struct {
	provider StatusProvider
	log      *logger.Logger
}

// NewHandlers creates a new handlers instance
func NewHandlers(provider StatusProvider, log *logger.Logger) *Handlers {
	return &Handlers{
		provider: provider,
		log:      log,
	}
}

// HandleStatus returns the current agent status
func (h *Handlers) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := h.provider.GetStatus()
	h.writeJSON(w, status)
}

// HandleMetrics returns detailed system metrics
func (h *Handlers) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics := h.provider.GetDetailedMetrics()
	if metrics == nil {
		h.writeJSON(w, map[string]string{"error": "metrics not available"})
		return
	}

	h.writeJSON(w, metrics)
}

// HandleMetricsHistory returns the recent CPU/memory ring buffer used by
// the agent console to render sparklines. The buffer is bounded (5 minutes
// at 1 Hz) so the response is always tiny.
func (h *Handlers) HandleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	samples := h.provider.GetMetricsHistory()
	h.writeJSON(w, map[string]interface{}{
		"samples": samples,
	})
}

// HandleLogsClear rotates the agent log so the live tail in the desktop
// console starts fresh. Existing entries move to a timestamped backup file
// (lumberjack handles the rename) and the agent continues writing to a
// brand-new agent.log without re-opening or interrupting any goroutine.
func (h *Handlers) HandleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.provider.ClearLogs(); err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	h.writeJSON(w, map[string]bool{"success": true})
}

// HandleEvents returns the agent's recent activity events. Optional `since`
// query param (unix milliseconds) makes the endpoint cheap to poll: clients
// pass the timestamp of the most recent event they've seen and only get
// new ones back.
func (h *Handlers) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		if parsed, err := strconv.ParseInt(s, 10, 64); err == nil {
			since = parsed
		}
	}
	evs := h.provider.GetEvents(since)
	h.writeJSON(w, map[string]interface{}{
		"events": evs,
	})
}

// HandleConnection returns WebSocket connection information
func (h *Handlers) HandleConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := h.provider.GetConnectionInfo()
	h.writeJSON(w, info)
}

// HandleLogs returns recent log lines
func (h *Handlers) HandleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse lines parameter (default 50)
	lines := 50
	if l := r.URL.Query().Get("lines"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			lines = parsed
		}
	}

	logs := h.provider.GetRecentLogs(lines)
	h.writeJSON(w, map[string]interface{}{
		"lines": logs,
		"count": len(logs),
	})
}

// HandleRestart triggers a graceful agent restart
func (h *Handlers) HandleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.log.Info("Restart requested via IPC")

	if err := h.provider.Restart(); err != nil {
		h.writeJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Restart initiated",
	})
}

// HandleHealth returns a simple health check response
func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := h.provider.GetStatus()
	h.writeJSON(w, map[string]interface{}{
		"healthy":   status.Running,
		"connected": status.Connected,
	})
}

// writeJSON writes a JSON response
func (h *Handlers) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.log.Warn("Failed to encode JSON response", "error", err)
	}
}

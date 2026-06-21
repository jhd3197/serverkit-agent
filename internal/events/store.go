// Package events provides a small append-only event log that powers the
// agent console's Activity tab. Events are higher-signal than raw log lines:
// "Service started", "Connection lost (timeout)", "Restart requested by
// tray". The agent process owns the store; producers across the codebase
// (websocket, lifecycle, IPC handlers) push to it via Append; the IPC server
// exposes the snapshot to the desktop UI.
//
// Persistence is a single JSON file rewritten on each Append. That sounds
// wasteful but the buffer is tiny (~200 events, one or two KB) and these
// events don't fire often enough for the rewrite cost to matter. Trade-off:
// crash-during-write is a non-issue since each rewrite is the entire state.
package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Kind is a stable identifier for the event type. Frontends use it to pick
// icons and colours; storage uses it for filtering.
type Kind string

const (
	KindServiceStart      Kind = "service_start"
	KindServiceStop       Kind = "service_stop"
	KindRestartRequested  Kind = "restart_requested"
	KindWSConnected       Kind = "ws_connected"
	KindWSDisconnected    Kind = "ws_disconnected"
	KindWSReconnecting    Kind = "ws_reconnecting"
	KindAuthFailed        Kind = "auth_failed"
	KindError             Kind = "error"
	KindInfo              Kind = "info"
)

// Severity controls visual emphasis in the UI. Use sparingly — Info is the
// default; Warn for transient issues; Error for things the user should act on.
type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

// Event is one entry in the activity log. Keep the JSON keys short and
// stable — they're a public-ish wire format consumed by the desktop UI.
type Event struct {
	ID       int64                  `json:"id"`
	Time     int64                  `json:"t"`
	Kind     Kind                   `json:"kind"`
	Severity Severity               `json:"sev"`
	Message  string                 `json:"msg"`
	Metadata map[string]interface{} `json:"meta,omitempty"`
}

// Store is a bounded ring buffer of events with optional disk persistence.
// Methods are safe for concurrent callers.
type Store struct {
	mu       sync.Mutex
	events   []Event
	cap      int
	nextID   int64
	persist  string // file path; empty = in-memory only
}

// NewStore returns a new event store with the given capacity. If
// persistPath is non-empty, the store loads events from that file on
// startup and rewrites it on every Append. Pass "" to skip persistence
// (e.g. tests).
func NewStore(capacity int, persistPath string) *Store {
	s := &Store{
		events:  make([]Event, 0, capacity),
		cap:     capacity,
		persist: persistPath,
	}
	s.load()
	return s
}

// Append records an event. Caller doesn't need to set ID or Time — the
// store assigns them. Persistence errors are swallowed (best-effort) since
// the in-memory buffer is the source of truth at runtime.
func (s *Store) Append(kind Kind, sev Severity, message string, meta map[string]interface{}) Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextID++
	ev := Event{
		ID:       s.nextID,
		Time:     time.Now().UnixMilli(),
		Kind:     kind,
		Severity: sev,
		Message:  message,
		Metadata: meta,
	}

	if len(s.events) >= s.cap {
		copy(s.events, s.events[1:])
		s.events = s.events[:len(s.events)-1]
	}
	s.events = append(s.events, ev)

	s.saveLocked()
	return ev
}

// Snapshot returns a copy of all events in chronological order. Optional
// since=unix-ms returns only events newer than that; pass 0 to get all.
func (s *Store) Snapshot(since int64) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Event, 0, len(s.events))
	for _, ev := range s.events {
		if ev.Time > since {
			out = append(out, ev)
		}
	}
	return out
}

// Clear drops all events and rewrites the persisted file.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = s.events[:0]
	s.saveLocked()
}

// load reads persisted events from disk. Silent on missing file (first run)
// and swallows malformed-file errors so a corrupt persist file can never
// take down the agent — we'd rather lose history than fail to start.
func (s *Store) load() {
	if s.persist == "" {
		return
	}
	data, err := os.ReadFile(s.persist)
	if err != nil {
		return
	}
	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return
	}
	if len(events) > s.cap {
		events = events[len(events)-s.cap:]
	}
	s.events = events
	for _, ev := range events {
		if ev.ID > s.nextID {
			s.nextID = ev.ID
		}
	}
}

// saveLocked persists the current buffer. Must be called with s.mu held.
// Writes to a tempfile and renames so a partial write can't corrupt the
// canonical file.
func (s *Store) saveLocked() {
	if s.persist == "" {
		return
	}
	dir := filepath.Dir(s.persist)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, "events-*.tmp")
	if err != nil {
		return
	}
	enc := json.NewEncoder(tmp)
	if err := enc.Encode(s.events); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return
	}
	tmp.Close()
	_ = os.Rename(tmp.Name(), s.persist)
}

// DefaultPath returns the canonical event-log file location next to the
// agent's other data files.
func DefaultPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "events.json")
}

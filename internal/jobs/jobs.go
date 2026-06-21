// Package jobs tracks long-running operations (package installs, image
// builds, pyenv installs) so the panel can subscribe to a streaming
// channel and receive progress events as they happen, plus a replay of
// recent events when subscribing mid-flight.
//
// A Job is created when a handler kicks off async work (e.g.
// packages:install) and returns {job_id, channel} to the caller. The
// handler then emits Event values via Job.Push, which:
//   - sends the event to the agent's stream transport (so any active
//     subscriber sees it live), AND
//   - records the event in a bounded ring buffer (so a late subscriber
//     can be caught up via Replay).
//
// The package is small on purpose — no goroutines, no timers, no I/O.
// Callers own concurrency. The only synchronization is a mutex around
// the registry map and per-job buffer mutex.
package jobs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// newID returns a 16-byte hex string suitable as a job identifier.
// Falls back to a timestamp if /dev/urandom is unavailable, matching
// the agent's auth.GenerateNonce style without taking a dep on it.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixMilli())
	}
	return hex.EncodeToString(b)
}

// Phase enumerates lifecycle phases emitted by streaming jobs. The
// panel uses these to drive its progress UI.
const (
	PhaseStart  = "start"
	PhaseLog    = "log"
	PhaseStatus = "status"
	PhaseDone   = "done"
)

// Event is the wire shape pushed onto a job's channel. Fields are kept
// minimal and JSON-tagged so the panel can render terminal-style output
// without per-handler parsers. Free-form Extra is for handlers that
// want to attach structured data (e.g. installed package list) to the
// final event.
type Event struct {
	Phase    string                 `json:"phase"`
	Lines    []string               `json:"lines,omitempty"`
	Message  string                 `json:"message,omitempty"`
	Percent  *int                   `json:"percent,omitempty"`
	ExitCode *int                   `json:"exit_code,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

// Job is one in-flight long-running operation. It owns a ring buffer
// of recent events so late subscribers can replay missed history.
type Job struct {
	ID      string
	Channel string

	mu     sync.Mutex
	events []Event // ring buffer
	cap    int
	head   int  // index of the next slot to write
	full   bool // whether we've wrapped past cap

	doneOnce sync.Once
	done     chan struct{}
}

// Streamer is the slice of the agent transport that jobs need. Wraps
// SendStream so handlers don't have to import the transport package
// directly.
type Streamer interface {
	SendStream(channel string, data interface{}) error
}

// Registry tracks active and recently-completed jobs by ID. The bounded
// retention means a panel that subscribes to a job channel a few
// seconds after it completed still sees the final event. After enough
// new jobs land, the old job ages out and Replay returns nothing — at
// which point the panel knows the job is gone and should show "no
// progress available."
type Registry struct {
	mu   sync.Mutex
	jobs map[string]*Job
	// keep the last MaxJobs jobs in memory so a brief subscribe-after-finish
	// race still serves the final "done" event.
	maxJobs int
	order   []string // FIFO of job IDs; trimmed when len > maxJobs
}

// NewRegistry returns a Registry retaining up to maxJobs jobs.
func NewRegistry(maxJobs int) *Registry {
	if maxJobs <= 0 {
		maxJobs = 64
	}
	return &Registry{
		jobs:    make(map[string]*Job),
		maxJobs: maxJobs,
	}
}

// New creates and registers a new Job. bufferCap is the ring-buffer
// size for replay (suggested 200).
func (r *Registry) New(bufferCap int) *Job {
	if bufferCap <= 0 {
		bufferCap = 200
	}
	id := newID()
	j := &Job{
		ID:      id,
		Channel: "job:" + id,
		events:  make([]Event, bufferCap),
		cap:     bufferCap,
		done:    make(chan struct{}),
	}
	r.mu.Lock()
	r.jobs[id] = j
	r.order = append(r.order, id)
	// Trim oldest jobs if we're over capacity.
	for len(r.order) > r.maxJobs {
		oldest := r.order[0]
		r.order = r.order[1:]
		delete(r.jobs, oldest)
	}
	r.mu.Unlock()
	return j
}

// Get returns the job with the given ID, or nil if unknown.
func (r *Registry) Get(id string) *Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobs[id]
}

// LookupByChannel returns the job whose Channel matches the given
// channel name (e.g. "job:<id>"), or nil. Used by Subscribe handlers
// to decide whether to replay buffered events.
func (r *Registry) LookupByChannel(channel string) *Job {
	if len(channel) <= 4 || channel[:4] != "job:" {
		return nil
	}
	return r.Get(channel[4:])
}

// Push records an event in the ring buffer and pushes it on the
// transport's stream channel. Panic-safe: a nil streamer just records
// the event, useful for tests.
func (j *Job) Push(s Streamer, ev Event) error {
	j.mu.Lock()
	j.events[j.head] = ev
	j.head = (j.head + 1) % j.cap
	if j.head == 0 {
		j.full = true
	}
	j.mu.Unlock()

	if ev.Phase == PhaseDone {
		j.doneOnce.Do(func() { close(j.done) })
	}

	if s == nil {
		return nil
	}
	return s.SendStream(j.Channel, ev)
}

// Replay returns a copy of the buffered events in chronological order.
// Used when a late subscriber wants to catch up.
func (j *Job) Replay() []Event {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.full {
		out := make([]Event, j.head)
		copy(out, j.events[:j.head])
		return out
	}
	// Ring is full: oldest is at head, newest is just before head.
	out := make([]Event, 0, j.cap)
	out = append(out, j.events[j.head:]...)
	out = append(out, j.events[:j.head]...)
	return out
}

// Done returns a channel closed when the job emits a final event with
// Phase == PhaseDone. Useful for tests.
func (j *Job) Done() <-chan struct{} { return j.done }

// HasTerminated reports whether a Done event has already been emitted.
// Useful for handler shutdown paths that want to avoid double-emitting
// a final terminator if their primary loop already pushed one.
func (j *Job) HasTerminated() bool {
	select {
	case <-j.done:
		return true
	default:
		return false
	}
}

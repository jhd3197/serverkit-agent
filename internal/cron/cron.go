// Package cron manages user-crontab entries for the agent host.
//
// Linux-only. The Manager is implemented by a build-tagged file
// (cron_linux.go for the real thing, cron_other.go for a stub that
// returns "unsupported" on every call). Higher layers always go through
// New() so non-Linux agents short-circuit before doing any work.
//
// Storage model:
//
//   - The user's crontab is the source of truth for schedule + command.
//   - Entries get a stable ID derived from sha256(schedule + command),
//     truncated to 12 hex chars. IDs survive add/remove of unrelated
//     entries — line-index IDs would not.
//   - Disabled entries are commented (`# <line>`); the leading `# `
//     is stripped on parse and re-added on toggle. We do NOT store
//     enable state out-of-band.
//   - Optional human metadata (name, description) lives in a sibling
//     JSON file owned by the agent. Loss of that file degrades to "no
//     names" but doesn't lose any actual schedules.
package cron

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// Entry is one cron line.
type Entry struct {
	ID          string `json:"id"`
	Schedule    string `json:"schedule"`
	Command     string `json:"command"`
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Status reports whether cron is usable on this host.
type Status struct {
	Available bool   `json:"available"`
	Running   bool   `json:"running"`
	Daemon    string `json:"daemon,omitempty"` // e.g. "cron", "cronie"
	Reason    string `json:"reason,omitempty"` // explanation when Available=false
}

// AddRequest is what the panel sends to add a job.
type AddRequest struct {
	Schedule    string `json:"schedule"`
	Command     string `json:"command"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Manager is the platform-agnostic interface over the crontab.
type Manager interface {
	Status(ctx context.Context) (*Status, error)
	List(ctx context.Context) ([]Entry, error)
	Add(ctx context.Context, req AddRequest) (*Entry, error)
	Remove(ctx context.Context, id string) error
	Toggle(ctx context.Context, id string, enabled bool) error
}

// entryID is the public hashing rule for content-based IDs.
// Exposed so tests can mirror it; not used outside the package.
func entryID(schedule, command string) string {
	sum := sha256.Sum256([]byte(schedule + "\x00" + command))
	return "cron_" + hex.EncodeToString(sum[:6])
}

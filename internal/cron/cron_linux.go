//go:build linux

package cron

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// New returns a Manager. On Linux this drives crontab(1).
func New() Manager { return &linuxManager{} }

type linuxManager struct{}

// Pure parsing/validation helpers (validateCommand, validateSchedule,
// parseLine, describeSchedule, applyUpdate) live in cron_parse.go so they
// are unit-testable on any platform; this file keeps the exec-driven
// crontab read/write and the Manager wiring.

func (l *linuxManager) Status(ctx context.Context) (*Status, error) {
	if _, err := exec.LookPath("crontab"); err != nil {
		return &Status{
			Available: false,
			Reason:    "crontab not installed on host",
		}, nil
	}
	// Best-effort daemon liveness. systemctl will respond on most modern
	// distros; if it isn't present we still report Available=true since
	// crontab(1) is what we drive — the user's job sits in the table
	// either way.
	running, daemon := false, ""
	for _, name := range []string{"cron", "crond", "cronie"} {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", name).Output()
		if strings.TrimSpace(string(out)) == "active" {
			running = true
			daemon = name
			break
		}
	}
	return &Status{Available: true, Running: running, Daemon: daemon}, nil
}

// readCrontab returns the current user's crontab. An exit code 1 with
// "no crontab for $USER" on stderr is normal and means "empty"; treat
// that as success with empty content.
func (l *linuxManager) readCrontab(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		// "no crontab for X" is not an error — it's the empty state.
		if strings.Contains(stderr.String(), "no crontab for") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// writeCrontab installs new content via `crontab -`.
func (l *linuxManager) writeCrontab(ctx context.Context, content string) error {
	cmd := exec.CommandContext(ctx, "crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab install: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (l *linuxManager) List(ctx context.Context) ([]Entry, error) {
	content, err := l.readCrontab(ctx)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		p := parseLine(scanner.Text())
		if !p.IsEntry {
			continue
		}
		entries = append(entries, Entry{
			ID:          entryID(p.Schedule, p.Command),
			Schedule:    p.Schedule,
			Command:     p.Command,
			Enabled:     p.Enabled,
			Description: describeSchedule(p.Schedule),
		})
	}
	return entries, nil
}

func (l *linuxManager) Add(ctx context.Context, req AddRequest) (*Entry, error) {
	if err := validateSchedule(req.Schedule); err != nil {
		return nil, err
	}
	if err := validateCommand(req.Command); err != nil {
		return nil, err
	}
	id := entryID(req.Schedule, req.Command)

	content, err := l.readCrontab(ctx)
	if err != nil {
		return nil, err
	}

	// Reject duplicates by content ID. Lets the panel safely retry on a
	// flaky network without ending up with two identical rows.
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		p := parseLine(scanner.Text())
		if p.IsEntry && entryID(p.Schedule, p.Command) == id {
			return nil, fmt.Errorf("an entry with the same schedule and command already exists")
		}
	}

	var b strings.Builder
	b.WriteString(strings.TrimRight(content, "\n"))
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	if req.Name != "" {
		fmt.Fprintf(&b, "# ServerKit: %s\n", req.Name)
	}
	fmt.Fprintf(&b, "%s %s\n", req.Schedule, req.Command)

	if err := l.writeCrontab(ctx, b.String()); err != nil {
		return nil, err
	}

	return &Entry{
		ID:          id,
		Schedule:    req.Schedule,
		Command:     req.Command,
		Enabled:     true,
		Name:        req.Name,
		Description: describeSchedule(req.Schedule),
	}, nil
}

// Update edits the entry identified by req.ID via an atomic whole-table
// rewrite (the pure logic is applyUpdate in cron_parse.go). The id is
// content-derived, so changing schedule/command yields a NEW id which is
// returned in the fresh Entry (Decision 4).
func (l *linuxManager) Update(ctx context.Context, req UpdateRequest) (*Entry, error) {
	content, err := l.readCrontab(ctx)
	if err != nil {
		return nil, err
	}
	newContent, entry, err := applyUpdate(content, req)
	if err != nil {
		return nil, err
	}
	if err := l.writeCrontab(ctx, newContent); err != nil {
		return nil, err
	}
	return entry, nil
}

func (l *linuxManager) Remove(ctx context.Context, id string) error {
	content, err := l.readCrontab(ctx)
	if err != nil {
		return err
	}
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	removed := false
	skipNextComment := false
	for scanner.Scan() {
		line := scanner.Text()
		if skipNextComment {
			// Don't drop unrelated comments — only strip the
			// immediately-following entry comment if we just removed
			// its schedule line. Reset the flag here regardless.
			skipNextComment = false
		}
		p := parseLine(line)
		if p.IsEntry && entryID(p.Schedule, p.Command) == id {
			removed = true
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	if !removed {
		return fmt.Errorf("entry %s not found", id)
	}
	return l.writeCrontab(ctx, strings.TrimRight(out.String(), "\n")+"\n")
}

func (l *linuxManager) Toggle(ctx context.Context, id string, enabled bool) error {
	content, err := l.readCrontab(ctx)
	if err != nil {
		return err
	}
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	matched := false
	for scanner.Scan() {
		line := scanner.Text()
		p := parseLine(line)
		if p.IsEntry && entryID(p.Schedule, p.Command) == id {
			matched = true
			if enabled {
				out.WriteString(p.Schedule + " " + p.Command + "\n")
			} else {
				out.WriteString("# " + p.Schedule + " " + p.Command + "\n")
			}
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	if !matched {
		return fmt.Errorf("entry %s not found", id)
	}
	return l.writeCrontab(ctx, strings.TrimRight(out.String(), "\n")+"\n")
}

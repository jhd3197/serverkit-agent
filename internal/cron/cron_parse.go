package cron

// Pure crontab parsing + rewrite helpers, shared by the Linux manager and
// unit-testable on any platform (the exec-driven read/write stays in
// cron_linux.go). Keeping these here means the table-rewrite semantics
// (id derivation, disabled-state + name-comment preservation) are proven
// without a live crontab.

import (
	"fmt"
	"regexp"
	"strings"
)

// blockedShellPatterns mirror the panel's CronService validation. We
// re-check on the agent because a malicious or misconfigured panel
// shouldn't be able to push shell-injection payloads through. Reject
// anything that turns "X command" into multiple shell-evaluated
// statements.
var blockedShellPatterns = []string{";", "&&", "||", "|", "`", "$(", ">", "<", "\n", "\r"}

func validateCommand(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return fmt.Errorf("command cannot be empty")
	}
	for _, p := range blockedShellPatterns {
		if strings.Contains(cmd, p) {
			return fmt.Errorf("command contains blocked shell operator %q", p)
		}
	}
	// First token must be an absolute path to a binary — same rule as
	// the panel-local CronService.
	first := strings.Fields(cmd)[0]
	if !strings.HasPrefix(first, "/") {
		return fmt.Errorf("command must start with an absolute path")
	}
	return nil
}

var scheduleRegex = regexp.MustCompile(`^[\d\*,\-/]+$`)

func validateSchedule(schedule string) error {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return fmt.Errorf("schedule must have 5 fields, got %d", len(parts))
	}
	for _, p := range parts {
		if !scheduleRegex.MatchString(p) {
			return fmt.Errorf("invalid schedule field %q", p)
		}
	}
	return nil
}

// parsedLine is a typed view of one crontab row.
type parsedLine struct {
	Raw      string // verbatim text including leading "# " for disabled
	Schedule string
	Command  string
	Enabled  bool
	IsEntry  bool // false for blank lines / pure comments
}

// parseLine extracts schedule + command from one crontab row. Pure
// comments (lines that are # without a 5-field schedule body) are
// ignored. Disabled entries (# <schedule> <command>) are recognised.
func parseLine(line string) parsedLine {
	out := parsedLine{Raw: line}
	body := strings.TrimSpace(line)
	if body == "" {
		return out
	}
	enabled := true
	if strings.HasPrefix(body, "#") {
		// Could be a pure comment or a disabled entry. Strip the leading
		// "#" and any whitespace, then try to parse as cron syntax.
		body = strings.TrimSpace(strings.TrimPrefix(body, "#"))
		enabled = false
	}
	fields := strings.Fields(body)
	if len(fields) < 6 {
		return out // not an entry
	}
	if validateSchedule(strings.Join(fields[:5], " ")) != nil {
		return out // first 5 fields don't look like a schedule
	}
	out.IsEntry = true
	out.Schedule = strings.Join(fields[:5], " ")
	out.Command = strings.Join(fields[5:], " ")
	out.Enabled = enabled
	return out
}

// applyUpdate is the pure whole-table rewrite behind Manager.Update. It
// locates the entry by req.ID, applies the changed fields (validating
// like Add), preserves disabled state and the `# ServerKit: <name>`
// comment unless changed, and returns the rewritten crontab plus the
// fresh Entry (whose id changes when schedule/command change, since ids
// are content-derived — Decision 4). Rejects a change that would collide
// with a DIFFERENT existing entry.
func applyUpdate(content string, req UpdateRequest) (string, *Entry, error) {
	if req.ID == "" {
		return "", nil, fmt.Errorf("id is required")
	}
	lines := strings.Split(content, "\n")

	// First pass: locate the target entry + its immediately-preceding
	// `# ServerKit: <name>` comment.
	targetIdx := -1
	nameCommentIdx := -1
	var oldSchedule, oldCommand, oldName string
	oldEnabled := true
	pendingName := ""
	pendingNameIdx := -1
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "# ServerKit:") {
			pendingName = strings.TrimSpace(strings.TrimPrefix(trimmed, "# ServerKit:"))
			pendingNameIdx = i
			continue
		}
		p := parseLine(raw)
		if p.IsEntry && entryID(p.Schedule, p.Command) == req.ID {
			targetIdx = i
			oldSchedule, oldCommand, oldEnabled = p.Schedule, p.Command, p.Enabled
			oldName = pendingName
			nameCommentIdx = pendingNameIdx
		}
		// Only an immediately-preceding ServerKit comment binds to an
		// entry; anything else clears the pending association.
		pendingName = ""
		pendingNameIdx = -1
	}
	if targetIdx == -1 {
		return "", nil, fmt.Errorf("entry %s not found", req.ID)
	}

	newSchedule := oldSchedule
	if req.Schedule != nil {
		newSchedule = strings.TrimSpace(*req.Schedule)
	}
	newCommand := oldCommand
	if req.Command != nil {
		newCommand = strings.TrimSpace(*req.Command)
	}
	newName := oldName
	if req.Name != nil {
		newName = strings.TrimSpace(*req.Name)
	}

	if err := validateSchedule(newSchedule); err != nil {
		return "", nil, err
	}
	if err := validateCommand(newCommand); err != nil {
		return "", nil, err
	}

	newID := entryID(newSchedule, newCommand)
	if newID != req.ID {
		for _, raw := range lines {
			p := parseLine(raw)
			if p.IsEntry && entryID(p.Schedule, p.Command) == newID {
				return "", nil, fmt.Errorf("an entry with the same schedule and command already exists")
			}
		}
	}

	// Second pass: rewrite. Drop the old name comment (re-emitted with the
	// entry) and replace the entry line, preserving the disabled prefix.
	var b strings.Builder
	for i, raw := range lines {
		if i == nameCommentIdx {
			continue
		}
		if i == targetIdx {
			if newName != "" {
				fmt.Fprintf(&b, "# ServerKit: %s\n", newName)
			}
			if oldEnabled {
				fmt.Fprintf(&b, "%s %s\n", newSchedule, newCommand)
			} else {
				fmt.Fprintf(&b, "# %s %s\n", newSchedule, newCommand)
			}
			continue
		}
		b.WriteString(raw)
		b.WriteString("\n")
	}

	entry := &Entry{
		ID:          newID,
		Schedule:    newSchedule,
		Command:     newCommand,
		Enabled:     oldEnabled,
		Name:        newName,
		Description: describeSchedule(newSchedule),
	}
	return strings.TrimRight(b.String(), "\n") + "\n", entry, nil
}

// describeSchedule returns a short human label for common patterns.
// Falls back to the raw schedule when nothing matches — matches the
// behaviour the panel-local CronService already produces, so per-server
// rows look the same as panel-local rows in the UI.
func describeSchedule(schedule string) string {
	switch schedule {
	case "* * * * *":
		return "Every minute"
	case "*/5 * * * *":
		return "Every 5 minutes"
	case "*/15 * * * *":
		return "Every 15 minutes"
	case "*/30 * * * *":
		return "Every 30 minutes"
	case "0 * * * *":
		return "Hourly"
	case "0 0 * * *":
		return "Daily at midnight"
	case "0 12 * * *":
		return "Daily at noon"
	case "0 0 * * 0":
		return "Weekly (Sunday)"
	case "0 0 1 * *":
		return "Monthly (1st)"
	case "0 0 1 1 *":
		return "Yearly (Jan 1)"
	}
	return schedule
}

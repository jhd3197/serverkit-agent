package cron

import (
	"strings"
	"testing"
)

func strptr(s string) *string { return &s }

// TestApplyUpdateChangesIDAndSchedule proves the id-adoption contract
// (Decision 4): changing the schedule yields a new content-derived id,
// returned in the fresh Entry.
func TestApplyUpdateChangesIDAndSchedule(t *testing.T) {
	orig := "0 3 * * * /usr/bin/backup\n"
	oldID := entryID("0 3 * * *", "/usr/bin/backup")

	newContent, entry, err := applyUpdate(orig, UpdateRequest{
		ID:       oldID,
		Schedule: strptr("30 4 * * *"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	wantID := entryID("30 4 * * *", "/usr/bin/backup")
	if entry.ID != wantID {
		t.Errorf("entry.ID = %q, want fresh id %q", entry.ID, wantID)
	}
	if entry.ID == oldID {
		t.Error("id should change when the schedule changes")
	}
	if entry.Schedule != "30 4 * * *" || entry.Command != "/usr/bin/backup" {
		t.Errorf("entry = %+v", entry)
	}
	if !strings.Contains(newContent, "30 4 * * * /usr/bin/backup") {
		t.Errorf("rewritten table missing new line:\n%s", newContent)
	}
	if strings.Contains(newContent, "0 3 * * *") {
		t.Errorf("rewritten table still has old schedule:\n%s", newContent)
	}
}

// TestApplyUpdateDisabledStaysDisabled proves a disabled entry stays
// commented after an update.
func TestApplyUpdateDisabledStaysDisabled(t *testing.T) {
	orig := "# 0 3 * * * /usr/bin/backup\n"
	id := entryID("0 3 * * *", "/usr/bin/backup")

	newContent, entry, err := applyUpdate(orig, UpdateRequest{
		ID:      id,
		Command: strptr("/usr/bin/newbackup"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if entry.Enabled {
		t.Error("entry should stay disabled")
	}
	line := strings.TrimSpace(newContent)
	if !strings.HasPrefix(line, "# ") {
		t.Errorf("disabled entry should stay commented, got %q", line)
	}
	if !strings.Contains(newContent, "/usr/bin/newbackup") {
		t.Errorf("command not updated:\n%s", newContent)
	}
}

// TestApplyUpdatePreservesName proves the `# ServerKit: <name>` comment
// survives an update that doesn't touch the name, and can be changed.
func TestApplyUpdatePreservesName(t *testing.T) {
	orig := "# ServerKit: nightly backup\n0 3 * * * /usr/bin/backup\n"
	id := entryID("0 3 * * *", "/usr/bin/backup")

	// Change only the schedule — name must survive.
	newContent, entry, err := applyUpdate(orig, UpdateRequest{
		ID:       id,
		Schedule: strptr("0 4 * * *"),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if entry.Name != "nightly backup" {
		t.Errorf("name not preserved: %q", entry.Name)
	}
	if strings.Count(newContent, "# ServerKit: nightly backup") != 1 {
		t.Errorf("expected exactly one name comment:\n%s", newContent)
	}

	// Now rename.
	renamed, entry2, err := applyUpdate(newContent, UpdateRequest{
		ID:   entry.ID,
		Name: strptr("morning backup"),
	})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if entry2.Name != "morning backup" {
		t.Errorf("rename failed: %q", entry2.Name)
	}
	if strings.Contains(renamed, "nightly backup") {
		t.Errorf("old name still present:\n%s", renamed)
	}
}

// TestApplyUpdateRejectsDuplicate proves an update that would collide with
// a DIFFERENT existing entry is refused.
func TestApplyUpdateRejectsDuplicate(t *testing.T) {
	orig := "0 3 * * * /usr/bin/backup\n0 4 * * * /usr/bin/other\n"
	id := entryID("0 3 * * *", "/usr/bin/backup")

	_, _, err := applyUpdate(orig, UpdateRequest{
		ID:       id,
		Schedule: strptr("0 4 * * *"),
		Command:  strptr("/usr/bin/other"),
	})
	if err == nil {
		t.Fatal("expected a duplicate-target rejection")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestApplyUpdateNotFound proves a missing id errors cleanly.
func TestApplyUpdateNotFound(t *testing.T) {
	_, _, err := applyUpdate("0 3 * * * /usr/bin/backup\n", UpdateRequest{
		ID:       "cron_deadbeef",
		Schedule: strptr("0 4 * * *"),
	})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

// TestApplyUpdateValidates proves invalid schedules/commands are rejected
// like Add (shell-injection guard, absolute-path rule).
func TestApplyUpdateValidates(t *testing.T) {
	orig := "0 3 * * * /usr/bin/backup\n"
	id := entryID("0 3 * * *", "/usr/bin/backup")

	if _, _, err := applyUpdate(orig, UpdateRequest{ID: id, Schedule: strptr("bad schedule")}); err == nil {
		t.Error("expected invalid-schedule rejection")
	}
	if _, _, err := applyUpdate(orig, UpdateRequest{ID: id, Command: strptr("rm -rf /")}); err == nil {
		t.Error("expected non-absolute-command rejection")
	}
	if _, _, err := applyUpdate(orig, UpdateRequest{ID: id, Command: strptr("/bin/sh; rm -rf /")}); err == nil {
		t.Error("expected shell-injection rejection")
	}
}

// TestApplyUpdateLeavesOtherEntriesUntouched proves the rewrite only
// touches the target entry.
func TestApplyUpdateLeavesOtherEntriesUntouched(t *testing.T) {
	orig := "0 1 * * * /usr/bin/a\n0 2 * * * /usr/bin/b\n0 3 * * * /usr/bin/c\n"
	id := entryID("0 2 * * *", "/usr/bin/b")

	newContent, _, err := applyUpdate(orig, UpdateRequest{ID: id, Schedule: strptr("30 2 * * *")})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, want := range []string{"0 1 * * * /usr/bin/a", "0 3 * * * /usr/bin/c", "30 2 * * * /usr/bin/b"} {
		if !strings.Contains(newContent, want) {
			t.Errorf("expected %q in:\n%s", want, newContent)
		}
	}
}

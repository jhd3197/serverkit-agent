//go:build windows

package agent

import "golang.org/x/sys/windows"

// enumerateDriveRoots lists the available logical drives (C:/, D:/, …) as
// virtual directory entries. Windows has no single filesystem root, so a
// browse request for "" or "/" returns the drive list rather than silently
// listing only the agent process's working drive. Paths are forward-slash
// to match the on-the-wire convention the rest of file:list uses; the
// allowlist still gates whether the panel can actually enter each drive.
func enumerateDriveRoots() []map[string]interface{} {
	mask, err := windows.GetLogicalDrives()
	if err != nil || mask == 0 {
		return nil
	}
	drives := make([]map[string]interface{}, 0)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i))
		drives = append(drives, map[string]interface{}{
			"name":     letter + ":",
			"path":     letter + ":/",
			"is_dir":   true,
			"size":     int64(0),
			"modified": int64(0),
		})
	}
	if len(drives) == 0 {
		return nil
	}
	return drives
}

//go:build !windows

package agent

// enumerateDriveRoots is a no-op on non-Windows platforms, which have a
// single "/" filesystem root and therefore no drive list to enumerate.
// Returning nil makes handleFileList fall through to reading "/".
func enumerateDriveRoots() []map[string]interface{} {
	return nil
}

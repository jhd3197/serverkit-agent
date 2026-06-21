//go:build !windows

package main

// attachParentConsole is a no-op outside Windows. The Windows build needs it
// to keep CLI output working when the binary is built with the windowsgui
// subsystem; on POSIX that subsystem distinction does not exist.
func attachParentConsole() {}

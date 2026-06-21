//go:build windows

package main

import "syscall"

const (
	// CreateNoWindow: hide the new console window if any.
	createNoWindow = 0x08000000
	// DetachedProcess: child process is not bound to the parent's console.
	detachedProcess = 0x00000008
)

// detachedProcessAttrs returns SysProcAttr that detaches the spawned process
// from the parent without smothering its UI. Used when the tray spawns a
// fresh `serverkit-agent setup` to relaunch the wizard.
//
// HideWindow MUST be false here. STARTUPINFO.wShowWindow propagates to the
// child's first top-level window via SW_SHOWDEFAULT, so HideWindow:true
// (which sets SW_HIDE) was leaving the wizard window invisible until the
// user manually called ShowWindow from outside — exactly the "Start Menu
// blank, CLI works" inconsistency users reported in 1.6.2. The agent .exe
// is built as a GUI subsystem so there's no console window to hide; the
// flag was redundant from the start.
func detachedProcessAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    false,
		CreationFlags: createNoWindow | detachedProcess,
	}
}

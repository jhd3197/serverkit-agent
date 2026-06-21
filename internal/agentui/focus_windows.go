//go:build windows

package agentui

import (
	"syscall"
	"unsafe"
)

// 1.6.1 shipped without explicit show/focus, leaving the host window hidden
// when the wizard was spawned with HideWindow:true (the STARTUPINFO bit
// propagates to child windows on some Windows builds — explicit SW_SHOW in
// the webview library wasn't enough). This file forces visibility from our
// side so 1.6.2 doesn't depend on that race.

const (
	swHide         = 0
	swShow         = 5
	swRestore      = 9
	hwndTopmost    = ^uintptr(0) // -1
	hwndNotopmost  = ^uintptr(1) // -2
	swpNoMove      = 0x0002
	swpNoSize      = 0x0001
	swpShowWindow  = 0x0040
)

// hideHostWindow stuffs the WebView2 host out of sight immediately after
// construction so the user never sees the white pre-paint or black
// post-CSS-but-pre-React frames. We re-show via forceForeground once the
// JS bundle reports ready (or a safety timeout fires).
func hideHostWindow(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	procShowWindow.Call(uintptr(hwnd), swHide)
}

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	procShowWindow           = user32.NewProc("ShowWindow")
	procSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop     = user32.NewProc("BringWindowToTop")
	procSetWindowPos         = user32.NewProc("SetWindowPos")
	procIsIconic             = user32.NewProc("IsIconic")
	procAttachThreadInput    = user32.NewProc("AttachThreadInput")
	procGetForegroundWindow  = user32.NewProc("GetForegroundWindow")
	procGetWindowThreadProc  = user32.NewProc("GetWindowThreadProcessId")
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadID   = kernel32.NewProc("GetCurrentThreadId")
)

// forceForeground does the dance Windows requires when a non-foreground
// process wants to grab focus: attach to the foreground thread's input
// queue, call SetForegroundWindow + BringWindowToTop, then detach. Without
// the attach step Windows silently demotes the request to a flashing
// taskbar button — exactly the symptom we saw in 1.6.1.
func forceForeground(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	h := uintptr(hwnd)

	// If minimized, restore first.
	if iconic, _, _ := procIsIconic.Call(h); iconic != 0 {
		procShowWindow.Call(h, swRestore)
	} else {
		procShowWindow.Call(h, swShow)
	}

	// Topmost-then-not flash forces the window onto Z-top reliably; some
	// users reported the window living below the taskbar otherwise.
	procSetWindowPos.Call(h, hwndTopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	procSetWindowPos.Call(h, hwndNotopmost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)

	fg, _, _ := procGetForegroundWindow.Call()
	if fg == 0 {
		procSetForegroundWindow.Call(h)
		procBringWindowToTop.Call(h)
		return
	}

	curThread, _, _ := procGetCurrentThreadID.Call()
	var fgPid uint32
	fgThread, _, _ := procGetWindowThreadProc.Call(fg, uintptr(unsafe.Pointer(&fgPid)))
	if fgThread == 0 || fgThread == curThread {
		procSetForegroundWindow.Call(h)
		procBringWindowToTop.Call(h)
		return
	}

	procAttachThreadInput.Call(curThread, fgThread, 1)
	procSetForegroundWindow.Call(h)
	procBringWindowToTop.Call(h)
	procAttachThreadInput.Call(curThread, fgThread, 0)
}

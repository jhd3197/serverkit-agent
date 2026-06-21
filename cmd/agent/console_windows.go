//go:build windows

package main

import (
	"os"
	"syscall"
)

// attachParentConsole reattaches stdin/stdout/stderr to the parent console
// (e.g. PowerShell or cmd.exe) when the binary was built with the
// "windowsgui" subsystem. With that subsystem set, double-clicking a
// shortcut no longer flashes a console — but CLI invocations like
// `serverkit-agent register` would also lose their output. This call
// restores the terminal experience when one is available, and is a
// silent no-op when launched from Explorer/Start menu.
func attachParentConsole() {
	const attachParentProcess = ^uint32(0) // -1, ATTACH_PARENT_PROCESS
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("AttachConsole")
	r, _, _ := proc.Call(uintptr(attachParentProcess))
	if r == 0 {
		return // no parent console; we're a GUI process
	}
	if h, err := syscall.Open("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = os.NewFile(uintptr(h), "stdout")
	}
	if h, err := syscall.Open("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stderr = os.NewFile(uintptr(h), "stderr")
	}
	if h, err := syscall.Open("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = os.NewFile(uintptr(h), "stdin")
	}
}

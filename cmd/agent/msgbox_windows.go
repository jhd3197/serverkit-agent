//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const (
	mbIconError = 0x00000010
	mbIconInfo  = 0x00000040
)

// showMessageBox is a tiny user32!MessageBoxW wrapper for early-stage failures
// where we either don't have walk loaded yet or we want to display before the
// main window exists. Modal; blocks until the user clicks OK.
func showMessageBox(title, body string, icon uint32) {
	user32 := syscall.NewLazyDLL("user32.dll")
	mb := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(body)
	_, _, _ = mb.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(icon))
}

//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const errAlreadyExists = 183

// acquireSingleInstance opens (or creates) a per-user named mutex. If the
// mutex already existed, another instance of the desktop app is already
// running for this user and we should bow out. Otherwise we hold the mutex
// for the lifetime of the process.
//
// Per-user (Local\) namespace: each Windows user gets their own ServerKit
// tray, which matches the per-user Run-key autostart.
func acquireSingleInstance() (alreadyRunning bool, release func()) {
	return acquireMutex(`Local\ServerKitAgentDesktop`)
}

// acquireServiceInstance is the agent-service equivalent of the desktop
// mutex above. Lives in the Global\ namespace because the service runs as
// SYSTEM and a per-user mutex wouldn't collide with a user-launched
// `serverkit-agent start`. With this in place, a second invocation of
// the start subcommand exits immediately with a clear message instead
// of racing the SCM-launched service for port 19780 and tripping a
// 30s "service did not respond" timeout.
func acquireServiceInstance() (alreadyRunning bool, release func()) {
	return acquireMutex(`Global\ServerKitAgentService`)
}

func acquireMutex(name string) (alreadyRunning bool, release func()) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutexW := kernel32.NewProc("CreateMutexW")
	closeHandle := kernel32.NewProc("CloseHandle")

	wname, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, func() {}
	}

	handle, _, lastErr := createMutexW.Call(
		0, // lpMutexAttributes = NULL
		0, // bInitialOwner = FALSE
		uintptr(unsafe.Pointer(wname)),
	)

	if handle == 0 {
		return false, func() {}
	}

	if errno, ok := lastErr.(syscall.Errno); ok && uintptr(errno) == errAlreadyExists {
		closeHandle.Call(handle)
		return true, func() {}
	}

	return false, func() { closeHandle.Call(handle) }
}

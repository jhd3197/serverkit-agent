//go:build windows

package setupui

import (
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
)

// forceForegroundWindow uses the documented AttachThreadInput recipe to bring
// a freshly-created walk window to the front, working around Windows'
// anti-focus-stealing rules.
//
// The plain TopMost-toggle trick is unreliable: it changes the Z-order but
// Windows still treats the activation as a focus-steal attempt and silently
// drops it on Windows 10/11 if our process isn't already in the foreground.
// AttachThreadInput briefly merges our input queue with the current
// foreground thread's, which Windows treats as the same UI session — and so
// SetForegroundWindow goes through.
func forceForegroundWindow(form walk.Form) {
	if form == nil {
		return
	}
	hwnd := uintptr(form.Handle())
	if hwnd == 0 {
		return
	}

	user32 := syscall.NewLazyDLL("user32.dll")
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	showWindow := user32.NewProc("ShowWindow")
	setForegroundWindow := user32.NewProc("SetForegroundWindow")
	setFocus := user32.NewProc("SetFocus")
	setActiveWindow := user32.NewProc("SetActiveWindow")
	bringWindowToTop := user32.NewProc("BringWindowToTop")
	getForegroundWindow := user32.NewProc("GetForegroundWindow")
	getWindowThreadProcessId := user32.NewProc("GetWindowThreadProcessId")
	getCurrentThreadId := kernel32.NewProc("GetCurrentThreadId")
	attachThreadInput := user32.NewProc("AttachThreadInput")
	setWindowPos := user32.NewProc("SetWindowPos")
	keybdEvent := user32.NewProc("keybd_event")
	allowSetForegroundWindow := user32.NewProc("AllowSetForegroundWindow")

	const (
		swRestore       = 9
		hwndTopmost     = ^uintptr(0)     // -1
		hwndNotTopmost  = ^uintptr(0) - 1 // -2
		swpNoSize       = 0x0001
		swpNoMove       = 0x0002
		swpShowWindow   = 0x0040
		keyEventfKeyUp  = 0x0002
		ASFW_ANY        = ^uint32(0) // -1
	)

	// (1) Allow ourselves to be the foreground for the next operation,
	// regardless of who's calling. -1 = ASFW_ANY.
	allowSetForegroundWindow.Call(uintptr(ASFW_ANY))

	// (2) Make sure the window is at least restored from any minimized state.
	showWindow.Call(hwnd, swRestore)

	// (3) Simulate a no-op keypress. Windows treats keyboard input as user
	//     activity and grants the receiving thread foreground privilege —
	//     even on Win10/11 where SetForegroundWindow is otherwise denied.
	keybdEvent.Call(0, 0, 0, 0)
	keybdEvent.Call(0, 0, keyEventfKeyUp, 0)

	// (4) AttachThreadInput trick: temporarily fuse our input queue with the
	//     current foreground thread's so SetForegroundWindow is treated as
	//     coming from the same UI session.
	fgHwnd, _, _ := getForegroundWindow.Call()
	var fgPid uint32
	fgThread, _, _ := getWindowThreadProcessId.Call(fgHwnd, uintptr(unsafe.Pointer(&fgPid)))
	ourThread, _, _ := getCurrentThreadId.Call()

	attached := false
	if fgThread != 0 && fgThread != ourThread {
		r, _, _ := attachThreadInput.Call(fgThread, ourThread, 1)
		attached = r != 0
	}

	// (5) The full activation sequence: Z-order, foreground, active, focus.
	bringWindowToTop.Call(hwnd)
	setWindowPos.Call(hwnd, hwndTopmost, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpShowWindow))
	setForegroundWindow.Call(hwnd)
	setActiveWindow.Call(hwnd)
	setFocus.Call(hwnd)
	setWindowPos.Call(hwnd, hwndNotTopmost, 0, 0, 0, 0,
		uintptr(swpNoMove|swpNoSize|swpShowWindow))

	if attached {
		attachThreadInput.Call(fgThread, ourThread, 0)
	}
}

// scheduleForceForeground fires the activation recipe several times across
// the first ~1.5 seconds of window life. The first attempt usually races
// the message loop start; later attempts win once the pump is servicing.
// Cheap and idempotent.
func scheduleForceForeground(form walk.Form) {
	if form == nil {
		return
	}
	go func() {
		for _, d := range []time.Duration{
			0,
			50 * time.Millisecond,
			150 * time.Millisecond,
			400 * time.Millisecond,
			900 * time.Millisecond,
			1500 * time.Millisecond,
		} {
			time.Sleep(d)
			form.Synchronize(func() {
				forceForegroundWindow(form)
			})
		}
	}()
}

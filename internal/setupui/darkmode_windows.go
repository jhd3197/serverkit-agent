//go:build windows

package setupui

import (
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
)

// enableDarkMode flips the window's title bar to the dark colour scheme on
// Windows 10/11 and registers the process as dark-mode aware so native
// controls (Edit, Button, ScrollBar) follow suit on Win11.
//
// Belt-and-braces: try the documented Win11 attribute (20), fall back to the
// undocumented Win10 1903+ value (19); call SetPreferredAppMode via its
// uxtheme ordinal export. All calls are best-effort and silently ignored on
// older builds where the API isn't present.
func enableDarkMode(form walk.Form) {
	if form == nil {
		return
	}
	hwnd := form.Handle()
	if hwnd == 0 {
		return
	}

	dwmapi := syscall.NewLazyDLL("dwmapi.dll")
	setAttr := dwmapi.NewProc("DwmSetWindowAttribute")
	var enable int32 = 1
	setAttr.Call(uintptr(hwnd), 20, uintptr(unsafe.Pointer(&enable)), 4)
	setAttr.Call(uintptr(hwnd), 19, uintptr(unsafe.Pointer(&enable)), 4)

	uxtheme := syscall.NewLazyDLL("uxtheme.dll")
	// SetPreferredAppMode(AllowDark = 1). Ordinal #135 on Win10 1903+.
	if proc := uxtheme.NewProc("SetPreferredAppMode"); proc != nil && proc.Find() == nil {
		proc.Call(1)
	}
}

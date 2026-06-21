//go:build windows

package setupui

import (
	"os/exec"
	"syscall"
)

// startServiceIfInstalled flips the ServerKitAgent service to auto-start
// and starts it. Best-effort: silently ignores errors (e.g. service not
// installed, no admin rights).
func startServiceIfInstalled() {
	run := func(args ...string) {
		cmd := exec.Command("sc.exe", args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = cmd.Run()
	}
	run("config", "ServerKitAgent", "start=", "auto")
	run("start", "ServerKitAgent")
}

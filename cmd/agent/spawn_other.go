//go:build !windows

package main

import "syscall"

func detachedProcessAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

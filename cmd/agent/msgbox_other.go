//go:build !windows

package main

const (
	mbIconError = 0
	mbIconInfo  = 0
)

func showMessageBox(_ string, _ string, _ uint32) {}

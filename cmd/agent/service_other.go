//go:build !windows

package main

import "context"

// runAsService is a no-op stub on POSIX — systemd handles process
// supervision, so there's nothing to dispatch.
func runAsService(runFn func(ctx context.Context) error) error {
	return runFn(context.Background())
}

func isWindowsService() bool { return false }

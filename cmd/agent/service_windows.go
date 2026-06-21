//go:build windows

package main

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"
)

// serviceHandler implements the Windows Service Control dispatcher
// contract. SCM launches the binary, calls Execute on a serviceHandler,
// expects status callbacks via the supplied channel within 30s. Without
// this dispatcher the binary runs normally but never signals
// SERVICE_RUNNING and SCM kills it with error 1053. Agents on Windows
// have been silently failing as services since the 1.0 line because of
// this — the whole "Start-Service ServerKitAgent" path was broken.
type serviceHandler struct {
	// runFn is the actual agent loop. Returns when ctx is cancelled or
	// the agent terminates on its own. We pass it a cancellable ctx and
	// flip cancel when SCM tells us to stop.
	runFn func(ctx context.Context) error
}

// Execute is invoked by svc.Run after the SCM connection is established.
// We immediately tell SCM we're starting, then SCM we're running, then
// run the agent loop in a goroutine while we listen for stop/shutdown
// requests on the supplied channel. The svc package owns the timing of
// the SCM handshake so all we need to do is push the right StateRunning
// / StateStopped statuses at the right moments.
func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- h.runFn(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// SCM polling for liveness — re-echo our status so it
				// knows we're still alive. Required by the contract.
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				// Wait for the agent loop to exit cleanly. svc.Run
				// internally allows up to 30s after StopPending
				// before SCM force-kills, which matches the existing
				// shutdown timing in agent.Run.
				<-runDone
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				// Unknown control code — ignore. SCM doesn't send
				// pause/continue without us advertising support.
			}
		case err := <-runDone:
			// Agent loop exited on its own (config error, fatal panic
			// caught upstream, etc.). Tell SCM we're done so the
			// service shows as stopped instead of "running but dead".
			if err != nil && err != context.Canceled {
				status <- svc.Status{State: svc.Stopped, Win32ExitCode: 1}
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// runAsService is the SCM entry point. Called from runAgent when we
// detect we're in a service context. Blocks until SCM tells us to stop.
func runAsService(runFn func(ctx context.Context) error) error {
	if err := svc.Run("ServerKitAgent", &serviceHandler{runFn: runFn}); err != nil {
		return fmt.Errorf("service dispatcher failed: %w", err)
	}
	return nil
}

// isWindowsService reports whether the current process was launched by
// the SCM. The svc package detects this by inspecting the process tree
// and the Windows session — there's no other reliable signal.
func isWindowsService() bool {
	in, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return in
}

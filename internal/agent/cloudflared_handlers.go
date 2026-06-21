package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/cloudflared"
	"github.com/jhd3197/serverkit-agent/internal/jobs"
)

// Handlers for cloudflared:* actions. Same shape as cron handlers:
// thin parse + dispatch. Validation lives in the cloudflared package.

func (a *Agent) handleCloudflaredStatus(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	return a.cloudflared.Status(ctx)
}

func (a *Agent) handleCloudflaredTunnelList(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	tunnels, err := a.cloudflared.List(ctx)
	if err != nil {
		return nil, err
	}
	if tunnels == nil {
		tunnels = []cloudflared.Tunnel{}
	}
	return map[string]interface{}{"tunnels": tunnels}, nil
}

func (a *Agent) handleCloudflaredTunnelCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req cloudflared.CreateRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	tunnel, err := a.cloudflared.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return tunnel, nil
}

func (a *Agent) handleCloudflaredTunnelRoute(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req cloudflared.RouteRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.cloudflared.Route(ctx, req); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

// handleCloudflaredLogin starts `cloudflared tunnel login` and streams
// progress on a job channel. Returns {job_id, channel} immediately so
// the panel can subscribe and surface the auth URL the moment
// cloudflared prints it. The flow:
//
//   1. Agent spawns `cloudflared tunnel login` with stdout/stderr piped
//   2. First line containing https://dash.cloudflare.com/argotunnel?...
//      is reported as a 'status' event with auth_url
//   3. Panel renders a clickable button; user opens URL → authorises
//   4. cloudflared writes cert.pem and exits
//   5. Agent emits 'done' with the cert path; panel can refresh
//      capabilities to flip the Authenticated badge.
//
// 15-minute hard ceiling (cloudflared blocks waiting for the OAuth
// callback) — long enough for a coffee break, short enough that a
// forgotten browser tab gets reaped.
func (a *Agent) handleCloudflaredLogin(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	// Use a background context for the subscription so the agent's
	// 5-minute command timeout doesn't kill the login flow.
	loginCtx := context.Background()
	ch, err := a.cloudflared.Login(loginCtx)
	if err != nil {
		return nil, fmt.Errorf("start login: %w", err)
	}
	job := a.jobs.New(64)
	go a.runCloudflaredLoginJob(job, ch)
	return map[string]interface{}{
		"job_id":  job.ID,
		"channel": job.Channel,
	}, nil
}

func (a *Agent) runCloudflaredLoginJob(job *jobs.Job, events <-chan cloudflared.LoginEvent) {
	exit := 0
	emit := func(ev jobs.Event) { _ = job.Push(a.ws, ev) }
	emit(jobs.Event{Phase: jobs.PhaseStart, Message: "starting cloudflared tunnel login"})

	for ev := range events {
		switch {
		case ev.AuthURL != "":
			emit(jobs.Event{
				Phase:   jobs.PhaseStatus,
				Message: "Open this URL in your browser to authorise the agent",
				Extra:   map[string]interface{}{"auth_url": ev.AuthURL},
			})
			if ev.Line != "" {
				emit(jobs.Event{Phase: jobs.PhaseLog, Lines: []string{ev.Line}})
			}
		case ev.Done:
			if ev.Error != "" {
				exit = 1
				emit(jobs.Event{
					Phase:    jobs.PhaseDone,
					ExitCode: &exit,
					Error:    ev.Error,
				})
			} else {
				emit(jobs.Event{
					Phase:    jobs.PhaseDone,
					ExitCode: &exit,
					Message:  "authenticated",
					Extra:    map[string]interface{}{"cert_path": ev.CertPath},
				})
			}
		case ev.Line != "":
			emit(jobs.Event{Phase: jobs.PhaseLog, Lines: []string{ev.Line}})
		}
	}
	// Channel closed without explicit Done — emit a defensive
	// terminator so the panel modal doesn't hang indefinitely.
	if !job.HasTerminated() {
		exit = 1
		emit(jobs.Event{Phase: jobs.PhaseDone, ExitCode: &exit, Error: "login stream ended unexpectedly"})
	}
}

func (a *Agent) handleCloudflaredTunnelDelete(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Ref string `json:"ref"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.cloudflared.Delete(ctx, p.Ref); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

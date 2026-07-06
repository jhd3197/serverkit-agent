package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/cron"
)

// Cron handlers wrap the cron.Manager interface for the panel's
// command-routing path. Validation happens inside the cron package,
// so handlers here are thin: parse params, dispatch, return.
//
// Linux-only operations on non-Linux agents return the manager's
// "unsupported" error, which the panel surfaces as a normal failure
// rather than a transport bug.

func (a *Agent) handleCronStatus(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	return a.cron.Status(ctx)
}

func (a *Agent) handleCronList(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	entries, err := a.cron.List(ctx)
	if err != nil {
		return nil, err
	}
	// Stable shape even on empty: {"jobs": []} so the UI can
	// unconditionally read .jobs.
	if entries == nil {
		entries = []cron.Entry{}
	}
	return map[string]interface{}{"jobs": entries}, nil
}

func (a *Agent) handleCronAdd(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req cron.AddRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	entry, err := a.cron.Add(ctx, req)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (a *Agent) handleCronUpdate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req cron.UpdateRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if req.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	entry, err := a.cron.Update(ctx, req)
	if err != nil {
		return nil, err
	}
	// The id changes when schedule/command change (content-derived); the
	// panel adopts the returned entry.
	return entry, nil
}

func (a *Agent) handleCronRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if err := a.cron.Remove(ctx, p.ID); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleCronToggle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if err := a.cron.Toggle(ctx, p.ID, p.Enabled); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true, "enabled": p.Enabled}, nil
}

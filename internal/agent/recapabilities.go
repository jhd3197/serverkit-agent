package agent

// agent:recapabilities — re-runs the capability probe on demand. The
// panel calls this after the user installs a runtime / sudoers entry /
// new package manager, so new feature surfaces light up without a
// service restart.
//
// Concurrent re-probes are common (the panel may fire one per server
// detail page open) and the underlying probes spawn subprocesses, so
// we guard with a coarse mutex: if a probe is already in flight we
// return the cached set with reprobe="in_progress" instead of
// queueing.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/capabilities"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

func (a *Agent) handleAgentRecapabilities(ctx context.Context, params json.RawMessage) (interface{}, error) {
	a.capMu.Lock()
	if a.reprobing {
		caps := a.capabilities
		a.capMu.Unlock()
		return map[string]interface{}{
			"reprobe":      "in_progress",
			"capabilities": caps,
		}, nil
	}
	a.reprobing = true
	a.capMu.Unlock()
	defer func() {
		a.capMu.Lock()
		a.reprobing = false
		a.capMu.Unlock()
	}()

	// Use a fresh, bounded context — the caller's request timeout
	// might be shorter than the probe takes, but we still want to
	// finish so the next subscriber sees fresh state.
	probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Clear the PATH lookup cache so newly installed binaries (e.g. the
	// user just ran apt install nginx) are seen by this re-probe.
	capabilities.ClearPathCache()

	fresh := capabilities.Probe(
		probeCtx,
		a.log,
		a.docker != nil,
		a.cfg.Features.FileAccess,
		a.cfg.Security.AllowedPaths,
	)

	// Re-probe sudo as well — the user may have added passwordless
	// sudoers config since boot.
	mode := probeSudoMode(probeCtx)
	fresh.Sudo = string(mode)
	// Re-detect runtime version managers; user may have just bootstrapped
	// pyenv via runtimes:pyenv:bootstrap and is hitting refresh.
	fresh.RuntimeManagers = map[string]string{
		"python": pyenvManagerKind(),
	}
	fresh.ProbedAt = time.Now().UnixMilli()

	// Capabilities are additive across re-probes: if the previous
	// snapshot saw a feature the panel cared about, don't drop it just
	// because a transient probe failed (e.g. dockerd briefly
	// restarting). Only flip false→true here, never true→false.
	a.capMu.Lock()
	merged := mergeCapabilities(a.capabilities, fresh)
	a.capabilities = merged
	a.sudoMode = mode
	a.capMu.Unlock()

	// Push to the panel so the in-memory ConnectedAgent record updates
	// without an explicit refetch.
	a.sendCapabilities()

	return map[string]interface{}{
		"reprobe":      "ok",
		"capabilities": merged,
	}, nil
}

// mergeCapabilities returns a payload where bool capabilities are the
// OR of prev and fresh, runtime maps are unioned, and the "presence"
// of optional fields prefers fresh values. Numeric/string fields like
// distro version are taken from fresh because the host might have been
// upgraded between probes.
//
// The asymmetry is deliberate: a transient probe failure (dockerd
// briefly down, journalctl hung) shouldn't cause a panel-side feature
// to disappear, but a real upgrade/install should be reflected. So we
// only flip false→true here, never true→false. To force a clean view
// the operator can restart the agent.
func mergeCapabilities(prev, fresh protocol.CapabilitiesMessage) protocol.CapabilitiesMessage {
	out := fresh
	if out.Capabilities == nil {
		out.Capabilities = protocol.Capabilities{}
	}
	for k, v := range prev.Capabilities {
		if v && !out.Capabilities[k] {
			out.Capabilities[k] = true
		}
	}
	if out.Runtimes == nil {
		out.Runtimes = map[string]string{}
	}
	for k, v := range prev.Runtimes {
		if _, ok := out.Runtimes[k]; !ok && v != "" {
			out.Runtimes[k] = v
		}
	}
	if out.RuntimeManagers == nil {
		out.RuntimeManagers = map[string]string{}
	}
	for k, v := range prev.RuntimeManagers {
		if _, ok := out.RuntimeManagers[k]; !ok && v != "" {
			out.RuntimeManagers[k] = v
		}
	}
	return out
}

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Handlers for firewall:* actions. Minimal host-firewall control so the
// tunnel broker can open the edge's inbound WireGuard UDP port (roadmap
// #10). Linux-only; tries ufw → firewalld → iptables, first present.
// Requires root (the agent already runs privileged for systemd/packages);
// failures return a clear error and the broker falls back to surfacing
// the manual command.

func (a *Agent) handleFirewallAllowPort(_ context.Context, params json.RawMessage) (interface{}, error) {
	return firewallPort(params, true)
}

func (a *Agent) handleFirewallDenyPort(_ context.Context, params json.RawMessage) (interface{}, error) {
	return firewallPort(params, false)
}

func firewallPort(params json.RawMessage, allow bool) (interface{}, error) {
	var p struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", p.Port)
	}
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if proto != "tcp" && proto != "udp" {
		proto = "udp"
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("firewall management is only supported on Linux agents")
	}
	spec := fmt.Sprintf("%d/%s", p.Port, proto)

	if _, err := exec.LookPath("ufw"); err == nil {
		action := "allow"
		if !allow {
			action = "deny"
		}
		if out, err := exec.Command("ufw", action, spec).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("ufw %s %s: %w (%s)", action, spec, err, strings.TrimSpace(string(out)))
		}
		return map[string]interface{}{"success": true, "method": "ufw", "spec": spec}, nil
	}

	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		flag := "--add-port"
		if !allow {
			flag = "--remove-port"
		}
		if out, err := exec.Command("firewall-cmd", flag+"="+spec).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("firewall-cmd %s=%s: %w (%s)", flag, spec, err, strings.TrimSpace(string(out)))
		}
		// Persist across reboots (best-effort) + reload.
		_, _ = exec.Command("firewall-cmd", flag+"="+spec, "--permanent").CombinedOutput()
		_, _ = exec.Command("firewall-cmd", "--reload").CombinedOutput()
		return map[string]interface{}{"success": true, "method": "firewalld", "spec": spec}, nil
	}

	if _, err := exec.LookPath("iptables"); err == nil {
		op := "-I" // insert (allow)
		if !allow {
			op = "-D" // delete the rule
		}
		out, err := exec.Command("iptables", op, "INPUT", "-p", proto, "--dport", strconv.Itoa(p.Port), "-j", "ACCEPT").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("iptables %s %s: %w (%s)", op, spec, err, strings.TrimSpace(string(out)))
		}
		return map[string]interface{}{"success": true, "method": "iptables", "spec": spec}, nil
	}

	return nil, fmt.Errorf("no supported firewall found (ufw / firewalld / iptables)")
}

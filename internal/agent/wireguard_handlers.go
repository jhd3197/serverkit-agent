package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/wireguard"
)

// Handlers for wireguard:* actions. Thin parse + dispatch; validation
// lives in the wireguard package. The panel's tunnel broker
// (backend/app/services/tunnel_broker_service.py) sequences these to
// pair two agents. See docs/REMOTE_ACCESS_ROADMAP.md.

func (a *Agent) handleWireguardKeygen(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Interface string `json:"interface"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return a.wireguard.Keygen(p.Interface)
}

func (a *Agent) handleWireguardInterfaceUp(_ context.Context, params json.RawMessage) (interface{}, error) {
	var req wireguard.InterfaceUpRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.InterfaceUp(req); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleWireguardInterfaceDown(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Interface string `json:"interface"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.InterfaceDown(p.Interface); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleWireguardPeerSet(_ context.Context, params json.RawMessage) (interface{}, error) {
	var req wireguard.PeerSetRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.SetPeer(req); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleWireguardPeerRemove(_ context.Context, params json.RawMessage) (interface{}, error) {
	var req wireguard.PeerRemoveRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.RemovePeer(req); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleWireguardStatus(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Interface string `json:"interface"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return a.wireguard.Status(p.Interface)
}

func (a *Agent) handleWireguardForward(_ context.Context, params json.RawMessage) (interface{}, error) {
	var req wireguard.ForwardRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.Forward(req); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func (a *Agent) handleWireguardUnforward(_ context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Interface  string `json:"interface"`
		ListenPort int    `json:"listen_port"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.wireguard.Unforward(p.Interface, p.ListenPort); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

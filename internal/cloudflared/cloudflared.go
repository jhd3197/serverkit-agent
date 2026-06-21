// Package cloudflared manages Cloudflare named tunnels via the
// cloudflared CLI. Linux-only.
//
// Auth model (approach A):
//
//	The user runs `cloudflared tunnel login` once per host. That writes
//	~/.cloudflared/cert.pem (or /etc/cloudflared/cert.pem when run as
//	root). The cert is the long-lived "I'm allowed to manage tunnels
//	for account X" credential. We never see, copy, or store the user's
//	Cloudflare API token; the panel only ever shells out to
//	`cloudflared` and trusts whatever auth the binary already has.
//
//	Status() reports two flags:
//	  - Available: cloudflared is on PATH
//	  - Authenticated: cert.pem is present in one of the standard
//	    locations
//
//	The panel uses both: the tab is gated on `capabilities.cloudflared`
//	(binary installed, set by capabilities.Probe at agent startup) and
//	the tab body shows an "authenticate first" affordance when
//	Authenticated=false.
//
// Tunnel lifecycle:
//
//	1. Create:  `cloudflared tunnel create <name>`
//	            (writes <UUID>.json credentials file)
//	2. Route:   `cloudflared tunnel route dns <name|UUID> <hostname>`
//	            (creates a Cloudflare DNS record pointing the
//	            hostname at the tunnel — *the* useful action)
//	3. Run:     out of scope here; the operator wires up
//	            `cloudflared tunnel run <name>` as a systemd service
//	            with a config.yml ingress mapping. Future iteration.
//	4. Delete:  `cloudflared tunnel delete <name|UUID>`
package cloudflared

import (
	"context"
	"os/exec"
)

// Status reports usability and auth state.
type Status struct {
	Available     bool   `json:"available"`               // binary installed
	Authenticated bool   `json:"authenticated"`           // cert.pem present
	CertPath      string `json:"cert_path,omitempty"`     // detected cert.pem path, if any
	Reason        string `json:"reason,omitempty"`        // explanation when Available=false
	LoginHint     string `json:"login_hint,omitempty"`    // canned "run this command" when Authenticated=false
	Version       string `json:"version,omitempty"`       // cloudflared --version line, best-effort
}

// Tunnel mirrors `cloudflared tunnel list --output json` rows.
type Tunnel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CreatedAt   string   `json:"created_at,omitempty"`
	Connections []string `json:"connections,omitempty"`
}

// CreateRequest creates a new named tunnel.
type CreateRequest struct {
	Name string `json:"name"`
}

// RouteRequest binds a hostname to an existing tunnel via Cloudflare
// DNS. TunnelRef can be the tunnel name or UUID — cloudflared accepts
// either.
type RouteRequest struct {
	TunnelRef string `json:"tunnel_ref"`
	Hostname  string `json:"hostname"`
}

// LoginEvent is emitted while a `cloudflared tunnel login` flow is in
// flight. AuthURL is the OAuth URL the user must open in a browser
// to authorise the agent host with their Cloudflare account; cert.pem
// is written by cloudflared once the OAuth round-trips.
type LoginEvent struct {
	AuthURL  string `json:"auth_url,omitempty"`
	Line     string `json:"line,omitempty"`
	Done     bool   `json:"done,omitempty"`
	CertPath string `json:"cert_path,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Manager is the platform-agnostic interface; the Linux build wires
// it up with real exec calls, non-Linux builds return "unsupported."
type Manager interface {
	Status(ctx context.Context) (*Status, error)
	List(ctx context.Context) ([]Tunnel, error)
	Create(ctx context.Context, req CreateRequest) (*Tunnel, error)
	Route(ctx context.Context, req RouteRequest) error
	Delete(ctx context.Context, ref string) error
	// Login starts `cloudflared tunnel login` and streams events on
	// the returned channel. The first event carries the auth URL; the
	// channel closes when cert.pem is written (Done=true) or the
	// underlying process errors out.
	Login(ctx context.Context) (<-chan LoginEvent, error)
}

// hasCloudflared is shared between the Linux backend and tests.
func hasCloudflared() (string, bool) {
	p, err := exec.LookPath("cloudflared")
	if err != nil {
		return "", false
	}
	return p, true
}

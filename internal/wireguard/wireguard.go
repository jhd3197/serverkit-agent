// Package wireguard manages a WireGuard interface on the agent host so
// the panel can pair two agents into a NAT-traversing tunnel (the
// "edge" agent on a public IP + a "private" agent behind NAT). See
// docs/REMOTE_ACCESS_ROADMAP.md.
//
// Split mirrors the cloudflared package:
//   - wireguard.go        — the platform-agnostic Manager interface,
//     shared request/result types, key generation
//     and validation.
//   - wireguard_linux.go  — the real backend (kernel WireGuard via the
//     `wg` + `ip` tools).
//   - wireguard_other.go  — a stub that reports "unsupported" until the
//     userspace wireguard-go backend (roadmap #6)
//     lands for Windows/macOS private peers.
//
// Security model (stated once):
//
//	Private keys NEVER leave the host. Keygen generates the keypair
//	locally, persists the private key in a root-only file under the
//	agent's key directory, and returns ONLY the public key in the
//	command result. The panel brokers public keys + endpoints +
//	allowed-IPs; it never sees, transmits or stores a private key.
package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Keypair is a WireGuard (Curve25519 / X25519) keypair, base64-encoded
// in the canonical `wg` format. PrivateKey is host-only and must never
// be serialized to the panel — it carries `json:"-"` for that reason.
type Keypair struct {
	PrivateKey string `json:"-"`
	PublicKey  string `json:"public_key"`
}

// KeygenResult is what the wireguard:keygen command returns to the
// panel: the public key only.
type KeygenResult struct {
	PublicKey string `json:"public_key"`
}

// InterfaceUpRequest brings up (or reconciles) a WireGuard interface.
// ListenPort is set only on the edge agent; the private agent dials
// out and lets the kernel pick an ephemeral source port.
type InterfaceUpRequest struct {
	Name       string `json:"name"`        // e.g. "skwg0"
	Address    string `json:"address"`     // CIDR, e.g. "10.88.0.2/24"
	ListenPort int    `json:"listen_port"` // 0 = unset (private side)
}

// PeerSetRequest adds or updates a single peer on an interface. On the
// private side, Endpoint points at the edge (`ip:port`) and
// PersistentKeepalive is set (typically 25s) to punch and hold the NAT
// mapping. On the edge side, Endpoint is empty (learned on handshake).
type PeerSetRequest struct {
	Interface           string   `json:"interface"`
	PublicKey           string   `json:"public_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// PeerRemoveRequest removes a peer from an interface.
type PeerRemoveRequest struct {
	Interface string `json:"interface"`
	PublicKey string `json:"public_key"`
}

// PeerStatus mirrors one peer row from `wg show <iface> dump`.
type PeerStatus struct {
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	LatestHandshake     int64    `json:"latest_handshake"` // unix seconds; 0 = never
	TransferRx          int64    `json:"transfer_rx"`      // bytes
	TransferTx          int64    `json:"transfer_tx"`      // bytes
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// InterfaceStatus is the wireguard:status result for one interface.
// Up=false (with a nil/empty Peers) means the interface doesn't exist
// yet — the panel polls this on a not-yet-built tunnel without it being
// an error.
type InterfaceStatus struct {
	Name       string       `json:"name"`
	PublicKey  string       `json:"public_key,omitempty"`
	ListenPort int          `json:"listen_port,omitempty"`
	Up         bool         `json:"up"`
	Peers      []PeerStatus `json:"peers"`
}

// Manager is the platform-agnostic surface the agent's handlers call.
// The Linux build wires it to kernel WireGuard; non-Linux builds return
// "unsupported" until roadmap #6.
type Manager interface {
	// Available reports whether this host can manage WireGuard (kernel
	// tools present on Linux; userspace backend on others once #6 lands).
	Available() bool
	// Keygen generates a keypair for iface, persists the private key
	// locally (root-only), and returns the public key.
	Keygen(iface string) (*KeygenResult, error)
	// InterfaceUp creates/reconciles the interface using the persisted
	// private key. Idempotent.
	InterfaceUp(req InterfaceUpRequest) error
	// InterfaceDown tears the interface down. Idempotent (a missing
	// interface is a no-op success).
	InterfaceDown(iface string) error
	// SetPeer adds or updates a peer. Idempotent.
	SetPeer(req PeerSetRequest) error
	// RemovePeer removes a peer. Idempotent.
	RemovePeer(req PeerRemoveRequest) error
	// Status returns the live interface + peer state.
	Status(iface string) (*InterfaceStatus, error)
	// Forward starts a TCP forwarder: it accepts connections arriving over
	// the tunnel at ListenIP:ListenPort and proxies each to
	// TargetHost:TargetPort on the host. This is how a service behind a
	// userspace (netstack) peer is reached — and is uniform for the kernel
	// backend. Idempotent per (interface, ListenPort): re-Forward replaces.
	Forward(req ForwardRequest) error
	// Unforward stops the forwarder for ListenPort on iface (idempotent).
	Unforward(iface string, listenPort int) error
}

// ForwardRequest configures a tunnel→host TCP forwarder (roadmap #13).
// On the private peer, ListenIP is the peer's own WireGuard IP, and the
// service (e.g. Jellyfin) listens on TargetHost:TargetPort on the host.
type ForwardRequest struct {
	Interface  string `json:"interface"`
	ListenIP   string `json:"listen_ip"`   // the WG IP to listen on, e.g. 10.88.3.2
	ListenPort int    `json:"listen_port"` // WG-side port the edge proxies to
	TargetHost string `json:"target_host"` // default 127.0.0.1
	TargetPort int    `json:"target_port"` // default = ListenPort
}

func (r ForwardRequest) normalized() ForwardRequest {
	if r.TargetHost == "" {
		r.TargetHost = "127.0.0.1"
	}
	if r.TargetPort == 0 {
		r.TargetPort = r.ListenPort
	}
	return r
}

func validateForward(req ForwardRequest) error {
	if err := validIfaceName(req.Interface); err != nil {
		return err
	}
	if net.ParseIP(req.ListenIP) == nil {
		return fmt.Errorf("invalid listen_ip %q", req.ListenIP)
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		return fmt.Errorf("invalid listen_port %d", req.ListenPort)
	}
	if req.TargetPort < 0 || req.TargetPort > 65535 {
		return fmt.Errorf("invalid target_port %d", req.TargetPort)
	}
	return nil
}

// forwardKey identifies a forwarder by interface + listen port.
func forwardKey(iface string, port int) string {
	return iface + ":" + strconv.Itoa(port)
}

// serveForward accepts on l and proxies each connection to
// targetHost:targetPort until l is closed. Backends create the listener
// (kernel: net.Listen on the real WG iface; userspace: tnet.ListenTCP)
// then hand it here.
func serveForward(l net.Listener, targetHost string, targetPort int) {
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	for {
		conn, err := l.Accept()
		if err != nil {
			return // listener closed
		}
		go proxyConn(conn, target)
	}
}

func proxyConn(client net.Conn, target string) {
	defer client.Close()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); done <- struct{}{} }
	go cp(server, client)
	go cp(client, server)
	<-done // first side to close ends the pair (defers close both)
}

// GenerateKeypair produces a fresh WireGuard keypair. X25519 via
// crypto/ecdh, which clamps the scalar exactly as WireGuard expects;
// the byte layout and base64 encoding match `wg genkey | wg pubkey`.
// Shared across all platforms — keygen is pure crypto and works even
// where interface management doesn't.
func GenerateKeypair() (*Keypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// PublicKeyFromPrivate derives the base64 WireGuard public key from a
// base64 private key (X25519 scalar-mult with the base point, matching
// `wg pubkey`). The userspace backend uses this for Status, where it
// only has the private key on hand.
func PublicKeyFromPrivate(privB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid private key")
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// --- validation helpers (shared, so both backends and tests reuse) ---

// ifaceNameRegex constrains interface names to what the Linux kernel
// accepts (IFNAMSIZ is 16 including the NUL, so 15 usable chars) and
// what won't trip shell/`ip` parsing.
var ifaceNameRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

func validIfaceName(name string) error {
	if !ifaceNameRegex.MatchString(name) {
		return fmt.Errorf("invalid interface name %q (alphanumeric, -, _, max 15 chars)", name)
	}
	return nil
}

// validPublicKey checks a base64 WireGuard key decodes to 32 bytes.
func validPublicKey(key string) error {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("public key is not valid base64")
	}
	if len(raw) != 32 {
		return fmt.Errorf("public key must be 32 bytes, got %d", len(raw))
	}
	return nil
}

// validCIDR checks a "addr/prefix" string parses.
func validCIDR(cidr string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return nil
}

// validEndpoint checks a "host:port" with a numeric, in-range port.
func validEndpoint(ep string) error {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q (want host:port): %w", ep, err)
	}
	if host == "" {
		return fmt.Errorf("invalid endpoint %q: empty host", ep)
	}
	p := 0
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid endpoint port %q", port)
	}
	return nil
}

// validateInterfaceUp validates an InterfaceUpRequest. Shared so the
// stub can reject bad input identically to the real backend.
func validateInterfaceUp(req InterfaceUpRequest) error {
	if err := validIfaceName(req.Name); err != nil {
		return err
	}
	if err := validCIDR(req.Address); err != nil {
		return err
	}
	if req.ListenPort < 0 || req.ListenPort > 65535 {
		return fmt.Errorf("invalid listen_port %d", req.ListenPort)
	}
	return nil
}

// validatePeerSet validates a PeerSetRequest.
func validatePeerSet(req PeerSetRequest) error {
	if err := validIfaceName(req.Interface); err != nil {
		return err
	}
	if err := validPublicKey(req.PublicKey); err != nil {
		return err
	}
	if len(req.AllowedIPs) == 0 {
		return fmt.Errorf("allowed_ips is required")
	}
	for _, ip := range req.AllowedIPs {
		if err := validCIDR(strings.TrimSpace(ip)); err != nil {
			return err
		}
	}
	if req.Endpoint != "" {
		if err := validEndpoint(req.Endpoint); err != nil {
			return err
		}
	}
	if req.PersistentKeepalive < 0 || req.PersistentKeepalive > 65535 {
		return fmt.Errorf("invalid persistent_keepalive %d", req.PersistentKeepalive)
	}
	return nil
}

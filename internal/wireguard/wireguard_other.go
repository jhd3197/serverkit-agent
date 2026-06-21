//go:build !linux

package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Userspace WireGuard backend (roadmap #6) — wireguard-go + gVisor
// netstack. Pure userspace: NO kernel module, NO TUN driver (no Wintun),
// NO admin. That's what makes it viable on a home Windows/macOS box
// (e.g. the user's Jellyfin host).
//
// Difference vs the Linux kernel backend: netstack is an in-process
// TCP/IP stack, not a transparent L3 interface. keygen / interface:up /
// peer:set / status are fully functional (the WireGuard handshake works),
// which is what Phases 0–1 need. Forwarding a host service over the
// tunnel happens in Phase 2 through the retained *netstack.Net (tnet);
// the iface struct keeps it for exactly that.

// New returns a userspace Manager. keyDir holds per-interface private
// keys (0600); empty falls back to the user-config dir.
func New(keyDir string) Manager {
	if keyDir == "" {
		keyDir = userspaceDefaultKeyDir()
	}
	return &userspaceManager{
		keyDir:   keyDir,
		ifaces:   map[string]*usIface{},
		forwards: map[string]net.Listener{},
	}
}

func userspaceDefaultKeyDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "serverkit-agent", "wireguard")
	}
	return filepath.Join(os.TempDir(), "serverkit-agent-wireguard")
}

type userspaceManager struct {
	keyDir   string
	mu       sync.Mutex
	ifaces   map[string]*usIface
	forwards map[string]net.Listener
}

type usIface struct {
	dev    *device.Device
	tnet   *netstack.Net // retained for Phase 2 service forwarding
	pubKey string        // base64; derived at up, surfaced by Status
	listen int
}

func (m *userspaceManager) keyPath(iface string) string {
	return filepath.Join(m.keyDir, iface+".key")
}

func (m *userspaceManager) Available() bool { return true }

func (m *userspaceManager) Keygen(iface string) (*KeygenResult, error) {
	if err := validIfaceName(iface); err != nil {
		return nil, err
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := os.WriteFile(m.keyPath(iface), []byte(kp.PrivateKey+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("persist private key: %w", err)
	}
	return &KeygenResult{PublicKey: kp.PublicKey}, nil
}

func (m *userspaceManager) InterfaceUp(req InterfaceUpRequest) error {
	if err := validateInterfaceUp(req); err != nil {
		return err
	}
	raw, err := os.ReadFile(m.keyPath(req.Name))
	if err != nil {
		return fmt.Errorf("no private key for %q — run wireguard:keygen first", req.Name)
	}
	privB64 := strings.TrimSpace(string(raw))
	privHex, err := keyB64ToHex(privB64)
	if err != nil {
		return fmt.Errorf("bad stored private key: %w", err)
	}
	pub, err := PublicKeyFromPrivate(privB64)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	prefix, err := netip.ParsePrefix(req.Address)
	if err != nil {
		return fmt.Errorf("bad address %q: %w", req.Address, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ifaces[req.Name]; ok {
		return nil // idempotent: already up
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{prefix.Addr()}, nil, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("create userspace tun: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "wg/"+req.Name+" "))

	var cfg strings.Builder
	cfg.WriteString("private_key=" + privHex + "\n")
	if req.ListenPort > 0 {
		cfg.WriteString("listen_port=" + strconv.Itoa(req.ListenPort) + "\n")
	}
	if err := dev.IpcSet(cfg.String()); err != nil {
		dev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring up device: %w", err)
	}
	m.ifaces[req.Name] = &usIface{dev: dev, tnet: tnet, pubKey: pub, listen: req.ListenPort}
	return nil
}

func (m *userspaceManager) InterfaceDown(iface string) error {
	if err := validIfaceName(iface); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, l := range m.forwards {
		if strings.HasPrefix(k, iface+":") {
			l.Close()
			delete(m.forwards, k)
		}
	}
	if ifc, ok := m.ifaces[iface]; ok {
		ifc.dev.Close()
		delete(m.ifaces, iface)
	}
	return nil // idempotent
}

func (m *userspaceManager) Forward(req ForwardRequest) error {
	if err := validateForward(req); err != nil {
		return err
	}
	req = req.normalized()
	m.mu.Lock()
	ifc := m.ifaces[req.Interface]
	m.mu.Unlock()
	if ifc == nil {
		return fmt.Errorf("interface %q is not up", req.Interface)
	}
	ip, err := netip.ParseAddr(req.ListenIP)
	if err != nil {
		return fmt.Errorf("invalid listen_ip %q: %w", req.ListenIP, err)
	}
	// Listen INSIDE the netstack on the WG IP — this receives the
	// connections the edge proxies over the tunnel. serveForward then
	// dials the real host service over the OS network.
	l, err := ifc.tnet.ListenTCPAddrPort(netip.AddrPortFrom(ip, uint16(req.ListenPort)))
	if err != nil {
		return fmt.Errorf("netstack listen %s:%d: %w", req.ListenIP, req.ListenPort, err)
	}
	key := forwardKey(req.Interface, req.ListenPort)
	m.mu.Lock()
	if old, ok := m.forwards[key]; ok {
		old.Close()
	}
	m.forwards[key] = l
	m.mu.Unlock()
	go serveForward(l, req.TargetHost, req.TargetPort)
	return nil
}

func (m *userspaceManager) Unforward(iface string, listenPort int) error {
	if err := validIfaceName(iface); err != nil {
		return err
	}
	key := forwardKey(iface, listenPort)
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.forwards[key]; ok {
		l.Close()
		delete(m.forwards, key)
	}
	return nil
}

func (m *userspaceManager) SetPeer(req PeerSetRequest) error {
	if err := validatePeerSet(req); err != nil {
		return err
	}
	m.mu.Lock()
	ifc := m.ifaces[req.Interface]
	m.mu.Unlock()
	if ifc == nil {
		return fmt.Errorf("interface %q is not up", req.Interface)
	}
	pubHex, err := keyB64ToHex(req.PublicKey)
	if err != nil {
		return fmt.Errorf("bad peer public key: %w", err)
	}
	var cfg strings.Builder
	cfg.WriteString("public_key=" + pubHex + "\n")
	cfg.WriteString("replace_allowed_ips=true\n")
	for _, ip := range req.AllowedIPs {
		cfg.WriteString("allowed_ip=" + strings.TrimSpace(ip) + "\n")
	}
	if req.Endpoint != "" {
		cfg.WriteString("endpoint=" + req.Endpoint + "\n")
	}
	if req.PersistentKeepalive > 0 {
		cfg.WriteString("persistent_keepalive_interval=" + strconv.Itoa(req.PersistentKeepalive) + "\n")
	}
	return ifc.dev.IpcSet(cfg.String())
}

func (m *userspaceManager) RemovePeer(req PeerRemoveRequest) error {
	if err := validIfaceName(req.Interface); err != nil {
		return err
	}
	if err := validPublicKey(req.PublicKey); err != nil {
		return err
	}
	m.mu.Lock()
	ifc := m.ifaces[req.Interface]
	m.mu.Unlock()
	if ifc == nil {
		return nil // nothing to remove
	}
	pubHex, err := keyB64ToHex(req.PublicKey)
	if err != nil {
		return fmt.Errorf("bad peer public key: %w", err)
	}
	return ifc.dev.IpcSet("public_key=" + pubHex + "\nremove=true\n")
}

func (m *userspaceManager) Status(iface string) (*InterfaceStatus, error) {
	if err := validIfaceName(iface); err != nil {
		return nil, err
	}
	st := &InterfaceStatus{Name: iface, Peers: []PeerStatus{}}
	m.mu.Lock()
	ifc := m.ifaces[iface]
	m.mu.Unlock()
	if ifc == nil {
		return st, nil // down
	}
	st.Up = true
	st.PublicKey = ifc.pubKey
	st.ListenPort = ifc.listen
	cfg, err := ifc.dev.IpcGet()
	if err != nil {
		return st, nil
	}
	parseUAPIStatus(cfg, st)
	return st, nil
}

// parseUAPIStatus parses wireguard-go's IpcGet() output into peers.
// It deliberately ignores the interface's private_key line (never
// surfaced). Peer public keys are converted hex→base64 to match the
// panel and the kernel backend's `wg show dump` output.
func parseUAPIStatus(cfg string, st *InterfaceStatus) {
	var cur *PeerStatus
	flush := func() {
		if cur != nil {
			st.Peers = append(st.Peers, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key": // begins a new peer section
			flush()
			cur = &PeerStatus{PublicKey: keyHexToB64(v)}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "allowed_ip":
			if cur != nil {
				cur.AllowedIPs = append(cur.AllowedIPs, v)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LatestHandshake = atoi64u(v)
			}
		case "rx_bytes":
			if cur != nil {
				cur.TransferRx = atoi64u(v)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TransferTx = atoi64u(v)
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				cur.PersistentKeepalive = int(atoi64u(v))
			}
		}
		// private_key / preshared_key / errno / protocol_version /
		// last_handshake_time_nsec / listen_port / fwmark → ignored.
	}
	flush()
}

func keyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func keyHexToB64(h string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return h // fall back to the raw value on parse failure
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func atoi64u(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

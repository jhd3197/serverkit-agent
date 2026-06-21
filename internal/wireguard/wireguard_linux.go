//go:build linux

package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultKeyDir is used when the agent didn't supply a data directory.
const defaultKeyDir = "/etc/serverkit-agent/wireguard"

// New returns a Linux Manager backed by kernel WireGuard (`wg` + `ip`).
// keyDir is where per-interface private keys are persisted (root-only);
// empty falls back to defaultKeyDir.
func New(keyDir string) Manager {
	if keyDir == "" {
		keyDir = defaultKeyDir
	}
	return &linuxManager{keyDir: keyDir, forwards: map[string]net.Listener{}}
}

type linuxManager struct {
	keyDir   string
	mu       sync.Mutex
	forwards map[string]net.Listener
}

func (m *linuxManager) keyPath(iface string) string {
	return filepath.Join(m.keyDir, iface+".key")
}

func (m *linuxManager) Available() bool {
	return onPath("wg") && onPath("ip")
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// run executes a command with a short ceiling and returns stdout, with
// stderr folded into any error (the panel surfaces these directly).
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w (%s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (m *linuxManager) Keygen(iface string) (*KeygenResult, error) {
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
	// 0600 + the key dir at 0700: the private key is readable only by
	// the agent's (root) user. It never travels to the panel.
	if err := os.WriteFile(m.keyPath(iface), []byte(kp.PrivateKey+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("persist private key: %w", err)
	}
	return &KeygenResult{PublicKey: kp.PublicKey}, nil
}

func (m *linuxManager) linkExists(iface string) bool {
	_, err := run("ip", "link", "show", iface)
	return err == nil
}

func (m *linuxManager) InterfaceUp(req InterfaceUpRequest) error {
	if err := validateInterfaceUp(req); err != nil {
		return err
	}
	keyPath := m.keyPath(req.Name)
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("no private key for %q — run wireguard:keygen first", req.Name)
	}

	// 1. Create the interface if it doesn't already exist (idempotent).
	if !m.linkExists(req.Name) {
		if _, err := run("ip", "link", "add", "dev", req.Name, "type", "wireguard"); err != nil {
			return err
		}
	}

	// 2. Apply the private key (+ listen port on the edge side).
	wgArgs := []string{"set", req.Name}
	if req.ListenPort > 0 {
		wgArgs = append(wgArgs, "listen-port", strconv.Itoa(req.ListenPort))
	}
	wgArgs = append(wgArgs, "private-key", keyPath)
	if _, err := run("wg", wgArgs...); err != nil {
		return err
	}

	// 3. Address — `replace` adds or updates, so re-running up is safe.
	if _, err := run("ip", "address", "replace", req.Address, "dev", req.Name); err != nil {
		return err
	}

	// 4. Bring it up.
	if _, err := run("ip", "link", "set", req.Name, "up"); err != nil {
		return err
	}
	return nil
}

func (m *linuxManager) InterfaceDown(iface string) error {
	if err := validIfaceName(iface); err != nil {
		return err
	}
	m.closeForwards(iface)
	if !m.linkExists(iface) {
		return nil // already gone — idempotent
	}
	_, err := run("ip", "link", "del", "dev", iface)
	return err
}

func (m *linuxManager) Forward(req ForwardRequest) error {
	if err := validateForward(req); err != nil {
		return err
	}
	req = req.normalized()
	// The WG IP is a real address on the kernel interface, so a normal
	// listen on it receives traffic arriving over the tunnel.
	l, err := net.Listen("tcp", net.JoinHostPort(req.ListenIP, strconv.Itoa(req.ListenPort)))
	if err != nil {
		return fmt.Errorf("listen %s:%d: %w", req.ListenIP, req.ListenPort, err)
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

func (m *linuxManager) Unforward(iface string, listenPort int) error {
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

// closeForwards stops every forwarder bound to iface (called on teardown).
func (m *linuxManager) closeForwards(iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, l := range m.forwards {
		if strings.HasPrefix(k, iface+":") {
			l.Close()
			delete(m.forwards, k)
		}
	}
}

func (m *linuxManager) SetPeer(req PeerSetRequest) error {
	if err := validatePeerSet(req); err != nil {
		return err
	}
	args := []string{"set", req.Interface, "peer", req.PublicKey,
		"allowed-ips", strings.Join(req.AllowedIPs, ",")}
	if req.Endpoint != "" {
		args = append(args, "endpoint", req.Endpoint)
	}
	if req.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(req.PersistentKeepalive))
	}
	_, err := run("wg", args...)
	return err
}

func (m *linuxManager) RemovePeer(req PeerRemoveRequest) error {
	if err := validIfaceName(req.Interface); err != nil {
		return err
	}
	if err := validPublicKey(req.PublicKey); err != nil {
		return err
	}
	_, err := run("wg", "set", req.Interface, "peer", req.PublicKey, "remove")
	return err
}

func (m *linuxManager) Status(iface string) (*InterfaceStatus, error) {
	if err := validIfaceName(iface); err != nil {
		return nil, err
	}
	st := &InterfaceStatus{Name: iface, Peers: []PeerStatus{}}

	out, err := run("wg", "show", iface, "dump")
	if err != nil {
		// The interface most likely doesn't exist yet — report "down"
		// rather than erroring so the panel can poll a tunnel that's
		// still being built.
		return st, nil
	}
	st.Up = true
	parseWgDump(out, st)
	return st, nil
}

// parseWgDump parses `wg show <iface> dump`. Line 1 is the interface
// (private-key, public-key, listen-port, fwmark); subsequent lines are
// peers (public-key, preshared-key, endpoint, allowed-ips,
// latest-handshake, transfer-rx, transfer-tx, persistent-keepalive).
//
// IMPORTANT: field [0] of the interface line is the PRIVATE key. We
// read field [1] (public) and deliberately never surface field [0].
func parseWgDump(out string, st *InterfaceStatus) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if i == 0 {
			// interface line
			if len(f) >= 2 {
				st.PublicKey = f[1]
			}
			if len(f) >= 3 {
				st.ListenPort = atoiSafe(f[2])
			}
			continue
		}
		// peer line
		if len(f) < 8 {
			continue
		}
		p := PeerStatus{PublicKey: f[0]}
		if f[2] != "(none)" {
			p.Endpoint = f[2]
		}
		if f[3] != "(none)" && f[3] != "" {
			for _, a := range strings.Split(f[3], ",") {
				if a = strings.TrimSpace(a); a != "" {
					p.AllowedIPs = append(p.AllowedIPs, a)
				}
			}
		}
		p.LatestHandshake = atoi64Safe(f[4])
		p.TransferRx = atoi64Safe(f[5])
		p.TransferTx = atoi64Safe(f[6])
		if f[7] != "off" {
			p.PersistentKeepalive = atoiSafe(f[7])
		}
		st.Peers = append(st.Peers, p)
	}
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64Safe(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

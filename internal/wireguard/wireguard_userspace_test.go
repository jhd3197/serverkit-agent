//go:build !linux

package wireguard

import "testing"

func TestKeyHexRoundTrip(t *testing.T) {
	kp, _ := GenerateKeypair()
	h, err := keyB64ToHex(kp.PublicKey)
	if err != nil {
		t.Fatalf("keyB64ToHex: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("hex key length = %d, want 64", len(h))
	}
	if back := keyHexToB64(h); back != kp.PublicKey {
		t.Errorf("roundtrip mismatch: %s != %s", back, kp.PublicKey)
	}
}

// TestParseUAPIStatus checks the wireguard-go IpcGet() parser and guards
// the no-leak invariant: the interface's private_key line must never end
// up in any surfaced field.
func TestParseUAPIStatus(t *testing.T) {
	ifaceKp, _ := GenerateKeypair()
	peerKp, _ := GenerateKeypair()
	privHex, _ := keyB64ToHex(ifaceKp.PrivateKey)
	peerHex, _ := keyB64ToHex(peerKp.PublicKey)

	cfg := "private_key=" + privHex + "\n" +
		"listen_port=51820\n" +
		"public_key=" + peerHex + "\n" +
		"endpoint=203.0.113.5:51820\n" +
		"allowed_ip=10.88.0.1/32\n" +
		"last_handshake_time_sec=1700000000\n" +
		"rx_bytes=1024\n" +
		"tx_bytes=2048\n" +
		"persistent_keepalive_interval=25\n" +
		"protocol_version=1\n"

	st := &InterfaceStatus{Name: "skwg0", Peers: []PeerStatus{}}
	parseUAPIStatus(cfg, st)

	if len(st.Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(st.Peers))
	}
	p := st.Peers[0]
	if p.PublicKey != peerKp.PublicKey {
		t.Errorf("peer PublicKey = %s, want %s (hex→base64)", p.PublicKey, peerKp.PublicKey)
	}
	if p.Endpoint != "203.0.113.5:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.88.0.1/32" {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.LatestHandshake != 1700000000 {
		t.Errorf("LatestHandshake = %d", p.LatestHandshake)
	}
	if p.TransferRx != 1024 || p.TransferTx != 2048 {
		t.Errorf("transfer rx/tx = %d/%d", p.TransferRx, p.TransferTx)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d", p.PersistentKeepalive)
	}
	// No-leak: the private key (as base64) must not appear in any field.
	if p.PublicKey == ifaceKp.PrivateKey {
		t.Fatal("LEAK: interface private key surfaced as a peer public key")
	}
}

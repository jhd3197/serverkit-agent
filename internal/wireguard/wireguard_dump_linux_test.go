//go:build linux

package wireguard

import "testing"

// TestParseWgDump checks the `wg show <iface> dump` parser, and in
// particular guards the security-critical invariant: the interface
// line's field[0] is the PRIVATE key and must never surface — we read
// field[1] (public) for InterfaceStatus.PublicKey.
func TestParseWgDump(t *testing.T) {
	dump := "PRIVATEKEYMUSTNOTLEAK=\tIFACEPUBKEY=\t51820\toff\n" +
		"PEERPUBKEY=\t(none)\t203.0.113.5:51820\t10.88.0.2/32\t1700000000\t1024\t2048\t25\n" +
		"PEER2PUBKEY=\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"

	st := &InterfaceStatus{Name: "skwg0", Peers: []PeerStatus{}}
	parseWgDump(dump, st)

	if st.PublicKey != "IFACEPUBKEY=" {
		t.Errorf("interface PublicKey = %q, want field[1] IFACEPUBKEY=", st.PublicKey)
	}
	if st.PublicKey == "PRIVATEKEYMUSTNOTLEAK=" {
		t.Fatal("LEAK: interface private key surfaced as PublicKey")
	}
	if st.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", st.ListenPort)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(st.Peers))
	}

	p := st.Peers[0]
	if p.PublicKey != "PEERPUBKEY=" {
		t.Errorf("peer0 PublicKey = %q", p.PublicKey)
	}
	if p.Endpoint != "203.0.113.5:51820" {
		t.Errorf("peer0 Endpoint = %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.88.0.2/32" {
		t.Errorf("peer0 AllowedIPs = %v", p.AllowedIPs)
	}
	if p.LatestHandshake != 1700000000 {
		t.Errorf("peer0 LatestHandshake = %d", p.LatestHandshake)
	}
	if p.TransferRx != 1024 || p.TransferTx != 2048 {
		t.Errorf("peer0 transfer rx/tx = %d/%d", p.TransferRx, p.TransferTx)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("peer0 PersistentKeepalive = %d", p.PersistentKeepalive)
	}

	// peer1: "(none)" endpoint → empty, "off" keepalive → 0
	p2 := st.Peers[1]
	if p2.Endpoint != "" {
		t.Errorf("peer1 Endpoint = %q, want empty", p2.Endpoint)
	}
	if len(p2.AllowedIPs) != 0 {
		t.Errorf("peer1 AllowedIPs = %v, want empty", p2.AllowedIPs)
	}
	if p2.PersistentKeepalive != 0 {
		t.Errorf("peer1 PersistentKeepalive = %d, want 0", p2.PersistentKeepalive)
	}
}

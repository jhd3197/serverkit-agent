package wireguard

import (
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if err := validPublicKey(kp.PublicKey); err != nil {
		t.Errorf("generated public key invalid: %v", err)
	}
	priv, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Errorf("private key not 32 base64 bytes: err=%v len=%d", err, len(priv))
	}
	if kp.PrivateKey == kp.PublicKey {
		t.Error("private and public key are identical")
	}
	kp2, _ := GenerateKeypair()
	if kp.PrivateKey == kp2.PrivateKey {
		t.Error("two keygens produced identical private keys")
	}
}

func TestValidPublicKey(t *testing.T) {
	kp, _ := GenerateKeypair()
	if err := validPublicKey(kp.PublicKey); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	if validPublicKey("not base64!!!") == nil {
		t.Error("non-base64 key accepted")
	}
	if validPublicKey(base64.StdEncoding.EncodeToString([]byte("short"))) == nil {
		t.Error("wrong-length key accepted")
	}
}

func TestValidateInterfaceUp(t *testing.T) {
	ok := InterfaceUpRequest{Name: "skwg0", Address: "10.88.0.1/24", ListenPort: 51820}
	if err := validateInterfaceUp(ok); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}
	bad := []InterfaceUpRequest{
		{Name: "bad iface!", Address: "10.88.0.1/24"},
		{Name: "skwg0", Address: "not-a-cidr"},
		{Name: "skwg0", Address: "10.88.0.1/24", ListenPort: 70000},
		{Name: "this-name-is-far-too-long", Address: "10.88.0.1/24"},
	}
	for i, b := range bad {
		if validateInterfaceUp(b) == nil {
			t.Errorf("invalid request %d was accepted", i)
		}
	}
}

func TestValidatePeerSet(t *testing.T) {
	kp, _ := GenerateKeypair()
	ok := PeerSetRequest{
		Interface: "skwg0", PublicKey: kp.PublicKey,
		AllowedIPs: []string{"10.88.0.2/32"},
		Endpoint:   "203.0.113.5:51820", PersistentKeepalive: 25,
	}
	if err := validatePeerSet(ok); err != nil {
		t.Errorf("valid peer rejected: %v", err)
	}
	bad := []PeerSetRequest{
		{Interface: "skwg0", PublicKey: "bad", AllowedIPs: []string{"10.88.0.2/32"}},
		{Interface: "skwg0", PublicKey: kp.PublicKey, AllowedIPs: nil},
		{Interface: "skwg0", PublicKey: kp.PublicKey, AllowedIPs: []string{"nope"}},
		{Interface: "skwg0", PublicKey: kp.PublicKey, AllowedIPs: []string{"10.88.0.2/32"}, Endpoint: "no-port"},
	}
	for i, b := range bad {
		if validatePeerSet(b) == nil {
			t.Errorf("invalid peer %d was accepted", i)
		}
	}
}

func TestPublicKeyFromPrivate(t *testing.T) {
	kp, _ := GenerateKeypair()
	pub, err := PublicKeyFromPrivate(kp.PrivateKey)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if pub != kp.PublicKey {
		t.Errorf("derived public key %s != keypair public key %s", pub, kp.PublicKey)
	}
	if _, err := PublicKeyFromPrivate("not-a-key"); err == nil {
		t.Error("accepted an invalid private key")
	}
}

// TestForwarder proves serveForward's accept loop + bidirectional proxy
// with real sockets (the listener-creation differs per backend, but the
// proxy plumbing is shared and is what carries the user's traffic).
func TestForwarder(t *testing.T) {
	// Echo server standing in for the real local service (e.g. Jellyfin).
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); c.Close() }(c)
		}
	}()
	_, tportStr, _ := net.SplitHostPort(target.Addr().String())
	tport, _ := strconv.Atoi(tportStr)

	// Forwarder listener standing in for the WG-side listen.
	fwd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forwarder listen: %v", err)
	}
	defer fwd.Close()
	go serveForward(fwd, "127.0.0.1", tport)

	conn, err := net.Dial("tcp", fwd.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	msg := []byte("hello-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf, msg)
	}
}

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func hashOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// platformName is a checksums.txt filename that matches the host this test
// runs on, so matchChecksum's GOOS/GOARCH substring match finds it.
func platformName() string {
	return fmt.Sprintf("serverkit-agent-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

func TestMatchChecksum_ValidPasses(t *testing.T) {
	data := []byte("pretend archive contents")
	good := hashOf(data)
	body := good + "  " + platformName() + "\n"
	if err := matchChecksum(good, body); err != nil {
		t.Fatalf("expected verification to pass, got: %v", err)
	}
}

func TestMatchChecksum_MismatchFails(t *testing.T) {
	good := hashOf([]byte("the real archive"))
	wrong := hashOf([]byte("a tampered archive"))
	body := wrong + "  " + platformName() + "\n"
	if err := matchChecksum(good, body); err == nil {
		t.Fatal("expected a mismatch error, got nil")
	}
}

func TestMatchChecksum_NoMatchingEntryFailsClosed(t *testing.T) {
	good := hashOf([]byte("archive"))
	// An entry that cannot match this host's GOOS/GOARCH. The old code returned
	// nil here ("skip verification") — the bug this guards against.
	body := good + "  serverkit-agent-xxos-yyarch.tar.gz\n"
	if err := matchChecksum(good, body); err == nil {
		t.Fatal("expected fail-closed when no entry matches the platform, got nil")
	}
}

func TestMatchChecksum_EmptyBodyFails(t *testing.T) {
	good := hashOf([]byte("archive"))
	if err := matchChecksum(good, ""); err == nil {
		t.Fatal("expected error on empty checksums body, got nil")
	}
	if err := matchChecksum(good, "not a valid checksums line\n"); err == nil {
		t.Fatal("expected error on a body with no usable entries, got nil")
	}
}

func TestMatchChecksum_CaseInsensitiveHash(t *testing.T) {
	data := []byte("archive")
	good := hashOf(data)
	body := strings.ToUpper(good) + "  " + platformName() + "\n"
	if err := matchChecksum(good, body); err != nil {
		t.Fatalf("expected case-insensitive hash comparison to pass, got: %v", err)
	}
}

func TestRequireSecureURL(t *testing.T) {
	if err := requireSecureURL("https://example.com/agent.tar.gz"); err != nil {
		t.Fatalf("https URL should be accepted, got: %v", err)
	}
	if err := requireSecureURL("HTTPS://Example.com/x"); err != nil {
		t.Fatalf("https scheme check should be case-insensitive, got: %v", err)
	}

	// http must be rejected unless the insecure dev flag is set.
	os.Unsetenv("SERVERKIT_INSECURE_TLS")
	if err := requireSecureURL("http://example.com/agent.tar.gz"); err == nil {
		t.Fatal("http URL should be rejected without SERVERKIT_INSECURE_TLS")
	}
	t.Setenv("SERVERKIT_INSECURE_TLS", "true")
	if err := requireSecureURL("http://localhost:5000/agent.tar.gz"); err != nil {
		t.Fatalf("http should be allowed when SERVERKIT_INSECURE_TLS=true, got: %v", err)
	}
}

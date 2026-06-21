package connstring

import (
	"errors"
	"strings"
	"testing"
)

func TestDecode_Roundtrip(t *testing.T) {
	got, err := Decode("sk1://panel.example.com/sk_reg_abc?exp=2026-05-08T17:00:00Z")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.URL != "https://panel.example.com" {
		t.Errorf("url = %q", got.URL)
	}
	if got.Token != "sk_reg_abc" {
		t.Errorf("token = %q", got.Token)
	}
	if got.ExpiresAtRaw != "2026-05-08T17:00:00Z" {
		t.Errorf("expires_at_raw = %q", got.ExpiresAtRaw)
	}
	if got.ExpiresAt.IsZero() {
		t.Errorf("expires_at not parsed: %v", got.ExpiresAt)
	}
}

func TestDecode_PreservesPort(t *testing.T) {
	got, err := Decode("sk1://panel.example.com:9443/t")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.URL != "https://panel.example.com:9443" {
		t.Errorf("url = %q", got.URL)
	}
}

func TestDecode_HonoursInsecureFlag(t *testing.T) {
	// http panels (typically dev / local-network) round-trip via the
	// insecure=1 flag. Without honouring it, the agent would default
	// to https and fail TLS against an http-only backend.
	got, err := Decode("sk1://localhost:47927/t?insecure=1")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.URL != "http://localhost:47927" {
		t.Errorf("url = %q (want http scheme)", got.URL)
	}
}

func TestDecode_NoExpiry(t *testing.T) {
	got, err := Decode("sk1://panel.example.com/t")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ExpiresAtRaw != "" {
		t.Errorf("expected no raw expiry, got %q", got.ExpiresAtRaw)
	}
	if !got.ExpiresAt.IsZero() {
		t.Errorf("expected zero ExpiresAt, got %v", got.ExpiresAt)
	}
}

func TestDecode_TrimsWhitespace(t *testing.T) {
	// Clipboard pastes often have a trailing newline; verify Decode
	// doesn't reject a string just because of that.
	if _, err := Decode("\n  sk1://panel.example.com/t  \n"); err != nil {
		t.Fatalf("decode with whitespace: %v", err)
	}
}

func TestDecode_RejectsUnknownVersion(t *testing.T) {
	cases := []string{
		"sk2://panel.example.com/t",
		"sk_conn_v1.eyJ1cmwiOiJodHRwczovL3gifQ", // legacy format
		"not-a-connection-string",
	}
	for _, in := range cases {
		_, err := Decode(in)
		if !errors.Is(err, ErrUnknownVersion) {
			t.Errorf("Decode(%q): want ErrUnknownVersion, got %v", in, err)
		}
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Errorf("want error for empty input")
	}
	if _, err := Decode("   "); err == nil {
		t.Errorf("want error for whitespace-only input")
	}
}

func TestDecode_RejectsMissingToken(t *testing.T) {
	cases := []string{
		"sk1://panel.example.com",
		"sk1://panel.example.com/",
	}
	for _, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("Decode(%q): want error, got nil", in)
			continue
		}
		if !strings.Contains(err.Error(), "token") {
			t.Errorf("Decode(%q): unexpected error %v", in, err)
		}
	}
}

func TestDecode_RejectsTokenWithSlash(t *testing.T) {
	_, err := Decode("sk1://panel.example.com/sk_reg/abc")
	if err == nil || !strings.Contains(err.Error(), "/") {
		t.Errorf("expected error about '/', got %v", err)
	}
}

func TestDecode_RejectsMissingHost(t *testing.T) {
	_, err := Decode("sk1:///t")
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("expected host error, got %v", err)
	}
}

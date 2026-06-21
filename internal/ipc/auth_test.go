package ipc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		query  string
		want   string
	}{
		{"no auth header, no query", "", "", ""},
		{"valid bearer", "Bearer abc123", "", "abc123"},
		{"case-insensitive scheme", "bearer abc123", "", "abc123"},
		{"trims whitespace", "Bearer   abc123  ", "", "abc123"},
		{"non-bearer scheme", "Basic abc123", "", ""},
		{"query string fallback", "", "tok-from-query", "tok-from-query"},
		{"header wins over query", "Bearer header-tok", "query-tok", "header-tok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if tc.query != "" {
				q := r.URL.Query()
				q.Set("token", tc.query)
				r.URL.RawQuery = q.Encode()
			}
			if got := bearerToken(r); got != tc.want {
				t.Fatalf("bearerToken: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthMiddleware(t *testing.T) {
	const tok = "secret-token-value"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mw := authMiddleware(tok, inner)

	t.Run("health is exempt", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("/health blocked: got %d", w.Code)
		}
	})

	t.Run("missing token rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("wrong token rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("correct token allowed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("OPTIONS bypasses auth (CORS preflight)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodOptions, "/status", nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("CORS preflight blocked: got %d", w.Code)
		}
	})
}

func TestLoadOrGenerateToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipc.token")

	// First call creates the file with a fresh token.
	tok1, err := loadOrGenerateToken(path)
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if len(tok1) < 32 {
		t.Fatalf("token too short: %q", tok1)
	}

	// Second call reuses the same token (so a tray app already running
	// keeps working through agent restarts).
	tok2, err := loadOrGenerateToken(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if tok1 != tok2 {
		t.Fatalf("token regenerated unexpectedly: %q vs %q", tok1, tok2)
	}
}

func TestLoadOrGenerateTokenRegeneratesOnTooShort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipc.token")

	// Pre-seed with a short value (eg. truncated file). loadOrGenerateToken
	// should treat it as corrupted and write a fresh one rather than honour
	// the stub credential.
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	tok, err := loadOrGenerateToken(path)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if tok == "short" || len(tok) < 32 {
		t.Fatalf("expected regenerated token, got %q", tok)
	}
}

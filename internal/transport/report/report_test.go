package report

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

func TestSignMatchesContract(t *testing.T) {
	body := []byte(`{"a":1}`)
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte("sec"))
	m.Write([]byte("1700000000" + "." + "abcd" + "." + hex.EncodeToString(sum[:])))
	want := hex.EncodeToString(m.Sum(nil))
	if got := Sign("sec", "1700000000", "abcd", body); got != want {
		t.Fatalf("Sign = %s, want %s", got, want)
	}
}

type captured struct {
	hdr  http.Header
	body []byte
}

func TestSendOnceHeadersBodyAndNonceUniqueness(t *testing.T) {
	var reqs []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs = append(reqs, captured{r.Header.Clone(), b})
		if r.URL.Path != "/api/v1/agent/report" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		io.WriteString(w, `{"ok":true,"interval_seconds":120}`)
	}))
	defer srv.Close()

	log := logger.New(config.LoggingConfig{Level: "error"})
	a := auth.New("agent-1", "key-123", "secret-456")
	r := New(srv.URL, "1.2.3", "monitor", a, time.Minute, func(context.Context) (Metrics, []protocol.ServiceCheck) {
		return Metrics{CPUPercent: 1.5}, nil
	}, log)
	for i := 0; i < 3; i++ {
		if err := r.SendOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.Interval != 2*time.Minute {
		t.Errorf("interval not adopted from reply: %v", r.Interval)
	}
	seen := map[string]bool{}
	for _, c := range reqs {
		if c.hdr.Get("X-Agent-Key") != "key-123" {
			t.Error("missing X-Agent-Key")
		}
		ts, nonce := c.hdr.Get("X-Timestamp"), c.hdr.Get("X-Nonce")
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			t.Errorf("bad timestamp %q", ts)
		}
		if len(nonce) < 32 { // 16 random bytes hex
			t.Errorf("nonce too short: %q", nonce)
		}
		if seen[nonce] {
			t.Errorf("nonce reused: %s", nonce)
		}
		seen[nonce] = true
		if c.hdr.Get("X-Signature") != Sign("secret-456", ts, nonce, c.body) {
			t.Error("signature does not match contract formula")
		}
		var b map[string]interface{}
		if err := json.Unmarshal(c.body, &b); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"agent_id", "agent_version", "permission_level", "sent_at", "interval_seconds", "metrics", "service_checks"} {
			if _, ok := b[k]; !ok {
				t.Errorf("body missing %s", k)
			}
		}
		if b["permission_level"] != "monitor" {
			t.Errorf("level = %v", b["permission_level"])
		}
	}
}

func TestSendOnceRejectsBadReply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"ok":false}`)
	}))
	defer srv.Close()
	log := logger.New(config.LoggingConfig{Level: "error"})
	r := New(srv.URL, "v", "monitor", auth.New("a", "k", "s"), time.Minute, func(context.Context) (Metrics, []protocol.ServiceCheck) { return Metrics{}, nil }, log)
	if err := r.SendOnce(context.Background()); err == nil {
		t.Fatal("expected error for ok:false")
	}
	if r.IsConnected() {
		t.Fatal("must not be connected after a rejected report")
	}
}

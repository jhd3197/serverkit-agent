// Package report is monitor mode's only link to the panel: signed, outbound
// HTTPS POSTs to /api/v1/agent/report. It opens no websocket, no poll
// session and no listener, and it ignores everything in the reply except the
// suggested interval — the reply can never carry commands.
package report

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

const (
	path        = "/api/v1/agent/report"
	minInterval = 15 * time.Second
	maxInterval = time.Hour
)

// Metrics is the "metrics" object of the report body.
type Metrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	UptimeSeconds uint64  `json:"uptime_seconds"`
	Load1         float64 `json:"load1"`
}

// Body is the JSON report payload.
type Body struct {
	AgentID         string                  `json:"agent_id"`
	AgentVersion    string                  `json:"agent_version"`
	PermissionLevel string                  `json:"permission_level"`
	SentAt          string                  `json:"sent_at"`
	IntervalSeconds int                     `json:"interval_seconds"`
	Metrics         Metrics                 `json:"metrics"`
	ServiceChecks   []protocol.ServiceCheck `json:"service_checks"`
}

// CollectFunc gathers the current metrics and service checks.
type CollectFunc func(ctx context.Context) (Metrics, []protocol.ServiceCheck)

// Reporter sends periodic signed reports.
type Reporter struct {
	BaseURL  string
	AgentID  string
	Version  string
	Level    string
	Auth     *auth.Authenticator
	Collect  CollectFunc
	HTTP     *http.Client
	Log      *logger.Logger
	Interval time.Duration
	Now      func() time.Time
	NewNonce func() string
	// mu guards lastOK and Interval, touched by Run and IsConnected callers.
	mu     sync.Mutex
	lastOK time.Time
}

// New builds a Reporter. baseURL is the panel's http(s) origin.
func New(baseURL, version, level string, a *auth.Authenticator, interval time.Duration, collect CollectFunc, log *logger.Logger) *Reporter {
	c := &http.Client{Timeout: 30 * time.Second}
	if os.Getenv("SERVERKIT_INSECURE_TLS") == "true" {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	if interval <= 0 {
		interval = time.Minute
	}
	return &Reporter{BaseURL: baseURL, AgentID: a.AgentID(), Version: version, Level: level, Auth: a,
		Collect: collect, HTTP: c, Log: log.WithComponent("report"), Interval: clamp(interval),
		Now: time.Now, NewNonce: auth.GenerateNonce}
}

// Sign implements the contract:
// hex(HMAC_SHA256(secret, timestamp + "." + nonce + "." + hex(sha256(body)))).
func Sign(secret, timestamp, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "." + nonce + "." + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(m.Sum(nil))
}

func clamp(d time.Duration) time.Duration {
	if d < minInterval {
		return minInterval
	}
	if d > maxInterval {
		return maxInterval
	}
	return d
}

// IsConnected reports whether the last report was accepted recently.
func (r *Reporter) IsConnected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.lastOK.IsZero() && r.Now().Sub(r.lastOK) < 3*r.Interval
}

// SendOnce collects and posts one report, adopting the interval the panel
// suggests (clamped).
func (r *Reporter) SendOnce(ctx context.Context) error {
	r.mu.Lock()
	interval := r.Interval
	r.mu.Unlock()
	m, checks := r.Collect(ctx)
	if checks == nil {
		checks = []protocol.ServiceCheck{}
	}
	now := r.Now()
	body, err := json.Marshal(Body{
		AgentID: r.AgentID, AgentVersion: r.Version, PermissionLevel: r.Level,
		SentAt: now.UTC().Format(time.RFC3339), IntervalSeconds: int(interval.Seconds()),
		Metrics: m, ServiceChecks: checks,
	})
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := r.NewNonce()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ServerKit-Agent-Report/"+r.Version)
	req.Header.Set("X-Agent-Key", r.Auth.GetAPIKey())
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", Sign(r.Auth.GetAPISecret(), ts, nonce, body))

	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("report rejected: HTTP %d", resp.StatusCode)
	}
	var reply struct {
		OK              bool `json:"ok"`
		IntervalSeconds int  `json:"interval_seconds"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil || !reply.OK {
		return fmt.Errorf("report not acknowledged")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastOK = now
	if reply.IntervalSeconds > 0 {
		r.Interval = clamp(time.Duration(reply.IntervalSeconds) * time.Second)
	}
	return nil
}

// Run reports immediately, then every Interval until ctx ends. Failures are
// logged and retried on the next tick.
func (r *Reporter) Run(ctx context.Context) {
	for {
		if err := r.SendOnce(ctx); err != nil {
			r.Log.Warn("Monitor report failed", "error", err)
		}
		r.mu.Lock()
		wait := r.Interval
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

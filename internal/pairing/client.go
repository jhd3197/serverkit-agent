package pairing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// EnrollRequest is the body of POST /api/v1/pairing/enroll.
type EnrollRequest struct {
	Pubkey     string                 `json:"pubkey"`
	Passphrase string                 `json:"passphrase"`
	MachineID  string                 `json:"machine_id,omitempty"`
	SystemInfo map[string]interface{} `json:"system_info,omitempty"`
}

// EnrollResponse is what the panel returns on successful enroll.
type EnrollResponse struct {
	EnrollmentID       string `json:"enrollment_id"`
	EnrollmentSecret   string `json:"enrollment_secret"`
	PairCode           string `json:"pair_code"`
	PairCodeFormatted  string `json:"pair_code_formatted"`
	PairCodeExpiresAt  string `json:"pair_code_expires_at"`
	ExpiresAt          string `json:"expires_at"`
	PubkeyFingerprint  string `json:"pubkey_fpr"`
}

// PollResponse is the body of GET /api/v1/pairing/poll.
type PollResponse struct {
	Status            string       `json:"status"` // pending | claimed
	PairCode          string       `json:"pair_code,omitempty"`
	PairCodeExpiresAt string       `json:"pair_code_expires_at,omitempty"`
	Credentials       *Credentials `json:"credentials,omitempty"`
}

// Credentials are returned to the agent once an operator claims it.
type Credentials struct {
	AgentID   string `json:"agent_id"`
	ServerID  string `json:"server_id"`
	Name      string `json:"name"`
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// RefreshResponse is returned from /code/refresh and /code/freeze.
type RefreshResponse struct {
	PairCode          string `json:"pair_code"`
	PairCodeFormatted string `json:"pair_code_formatted"`
	PairCodeExpiresAt string `json:"pair_code_expires_at"`
	PairCodeFrozen    bool   `json:"pair_code_frozen"`
}

// Client talks to the panel pairing API.
type Client struct {
	BaseURL          string
	HTTP             *http.Client
	UserAgent        string
	EnrollmentID     string
	EnrollmentSecret string
	keypair          *KeyPair
	log              *logger.Logger
}

// SetKeyPair attaches the agent's Ed25519 keypair so Poll can prove
// possession of the private key matching the enrolled pubkey. Optional: when
// unset, Poll falls back to bearer-secret-only auth (older behavior).
func (c *Client) SetKeyPair(kp *KeyPair) {
	c.keypair = kp
}

// NewClient constructs a pairing client. baseURL must be the panel HTTPS root.
func NewClient(baseURL string, log *logger.Logger) *Client {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &Client{
		BaseURL: baseURL,
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: os.Getenv("SERVERKIT_INSECURE_TLS") == "true",
				},
			},
		},
		UserAgent: "ServerKit-Agent-Pairing/1.0",
		log:       log.WithComponent("pairing"),
	}
}

// Enroll submits the agent's pubkey + passphrase to obtain an enrollment + pair code.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	var resp EnrollResponse
	if err := c.do(ctx, "POST", "/api/v1/pairing/enroll", req, nil, &resp); err != nil {
		return nil, err
	}
	c.EnrollmentID = resp.EnrollmentID
	c.EnrollmentSecret = resp.EnrollmentSecret
	return &resp, nil
}

// RotateCode requests a new pair code (no-op if frozen unless force=true).
func (c *Client) RotateCode(ctx context.Context, force bool) (*RefreshResponse, error) {
	body := map[string]bool{"force": force}
	var resp RefreshResponse
	if err := c.do(ctx, "POST", "/api/v1/pairing/code/refresh", body, c.enrollHeaders(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetFreeze freezes or unfreezes the rotating pair code.
func (c *Client) SetFreeze(ctx context.Context, frozen bool) (*RefreshResponse, error) {
	body := map[string]bool{"frozen": frozen}
	var resp RefreshResponse
	if err := c.do(ctx, "POST", "/api/v1/pairing/code/freeze", body, c.enrollHeaders(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Poll waits up to ~30s for an operator to claim this enrollment.
// Returns (claimed, credentials, err). If err is nil and claimed is false the
// caller should reconnect immediately for another long-poll.
func (c *Client) Poll(ctx context.Context) (bool, *Credentials, error) {
	headers := c.enrollHeaders()
	// Prove possession of the enrolled private key by signing the
	// enrollment_id. The panel verifies this against the pubkey we submitted at
	// enroll() time, so a stolen enrollment_secret alone can't claim our creds.
	if c.keypair != nil && c.EnrollmentID != "" {
		sig := base64.StdEncoding.EncodeToString(c.keypair.Sign([]byte(c.EnrollmentID)))
		headers.Set("X-Enrollment-Signature", sig)
	}
	var resp PollResponse
	if err := c.do(ctx, "GET", "/api/v1/pairing/poll", nil, headers, &resp); err != nil {
		return false, nil, err
	}
	if resp.Status == "claimed" && resp.Credentials != nil {
		return true, resp.Credentials, nil
	}
	return false, nil, nil
}

// WaitForClaim blocks until the agent is claimed, retrying long-polls and
// occasionally rotating the pair code (every ~5 minutes) so codes never get stale.
//
// onCode is invoked whenever the visible pair code changes — typically wired
// into the tray UI. It may be nil for headless operation.
func (c *Client) WaitForClaim(ctx context.Context, onCode func(code, formatted string, expiresAt string)) (*Credentials, error) {
	codeRotateTicker := time.NewTicker(4 * time.Minute)
	defer codeRotateTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-codeRotateTicker.C:
			if rr, err := c.RotateCode(ctx, false); err == nil && onCode != nil {
				onCode(rr.PairCode, formatPairCode(rr.PairCode), rr.PairCodeExpiresAt)
			}
		default:
		}

		pollCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
		claimed, creds, err := c.Poll(pollCtx)
		cancel()
		if err != nil {
			c.log.Warn("pairing poll failed; retrying", "error", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		if claimed {
			return creds, nil
		}
	}
}

// ----- internals -----

func (c *Client) enrollHeaders() http.Header {
	h := http.Header{}
	if c.EnrollmentID != "" {
		h.Set("X-Enrollment-Id", c.EnrollmentID)
	}
	if c.EnrollmentSecret != "" {
		h.Set("X-Enrollment-Secret", c.EnrollmentSecret)
	}
	return h
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, extraHeaders http.Header, out interface{}) error {
	url := c.BaseURL + path

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	for k, v := range extraHeaders {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var er struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &er)
		if er.Error != "" {
			return fmt.Errorf("%s %s: %s (status %d)", method, path, er.Error, resp.StatusCode)
		}
		return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func formatPairCode(code string) string {
	if len(code) < 2 {
		return code
	}
	half := len(code) / 2
	return code[:half] + "-" + code[half:]
}

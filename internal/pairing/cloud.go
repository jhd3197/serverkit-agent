package pairing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudClient pairs this agent straight to ServerKit Cloud, with no panel in
// between (Helm plan 01 M6).
//
// It is the same three calls the panel's `serverkit connect` makes — enrol,
// poll, and wait for a person to approve the code in a browser — against the
// same endpoints, with one difference: the enrolment says `kind: "agent"`, so
// Cloud creates one server rather than a panel and the hosts it manages, and
// offers only the consents an agent can act on. An agent has no panel behind
// it, so it can be watched and updated; deployments, backups and container
// work belong to a panel and Cloud refuses them here by name.
//
// Proof of possession is the same too: every poll carries an Ed25519
// signature over `<enrollment_id>|<unix seconds>` made with the key that
// enrolled. A stolen pairing code alone is worth nothing.
type CloudClient struct {
	// BaseURL is the Cloud root, e.g. https://app.serverkit.ai.
	BaseURL   string
	HTTP      *http.Client
	UserAgent string

	keypair *KeyPair
}

// CloudEnrollRequest is the body of POST /api/pair/enroll.
type CloudEnrollRequest struct {
	Pubkey       string `json:"pubkey"`
	Fingerprint  string `json:"fingerprint"`
	Hostname     string `json:"hostname,omitempty"`
	Proto        int    `json:"proto"`
	Kind         string `json:"kind"`
	AgentID      string `json:"agent_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	MachineID    string `json:"machine_id,omitempty"`
}

// CloudEnrollment is what Cloud returns from enrol. The secret is shown once
// and only its hash is stored on the other side, so it is kept in memory and
// written nowhere but the agent's own credential file.
type CloudEnrollment struct {
	EnrollmentID     string `json:"enrollment_id"`
	EnrollmentSecret string `json:"enrollment_secret"`
	Code             string `json:"code"`
	Kind             string `json:"kind"`
	ExpiresAt        string `json:"expires_at"`
}

// CloudClaim is what Cloud returns once somebody has approved the code.
type CloudClaim struct {
	DeviceID string   `json:"device_id"`
	OrgSlug  string   `json:"org_slug"`
	Name     string   `json:"name"`
	RelayURL string   `json:"relay_url"`
	Scopes   []string `json:"scopes"`
}

// NewCloudClient builds a client for the given Cloud root.
func NewCloudClient(baseURL string, kp *KeyPair) *CloudClient {
	return &CloudClient{
		BaseURL:   strings.TrimSuffix(baseURL, "/"),
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		UserAgent: "serverkit-agent",
		keypair:   kp,
	}
}

func (c *CloudClient) post(ctx context.Context, path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach ServerKit Cloud: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return &CloudError{Status: resp.StatusCode, Detail: detailOf(raw, resp.StatusCode)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// CloudError carries Cloud's own words. They are written to be read by the
// person at the keyboard — a plan limit, a clock that is off, a host that is
// already connected somewhere else — so they are passed through rather than
// flattened into "pairing failed".
type CloudError struct {
	Status int
	Detail string
}

func (e *CloudError) Error() string { return e.Detail }

func detailOf(raw []byte, status int) string {
	var body struct {
		Detail any `json:"detail"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && body.Detail != nil {
		switch d := body.Detail.(type) {
		case string:
			return d
		case map[string]any:
			if msg, ok := d["error"].(string); ok {
				return msg
			}
		}
	}
	return fmt.Sprintf("ServerKit Cloud returned %d", status)
}

// Enroll asks Cloud for a pairing code. Nothing is connected until somebody
// approves that code in a browser and confirms the fingerprint printed here.
func (c *CloudClient) Enroll(ctx context.Context, req CloudEnrollRequest) (*CloudEnrollment, error) {
	if c.keypair == nil {
		return nil, fmt.Errorf("no keypair: load or create one before enrolling")
	}
	req.Pubkey = c.keypair.PublicKeyHex()
	req.Fingerprint = strings.ToLower(c.keypair.Fingerprint)
	req.Kind = "agent"
	if req.Proto == 0 {
		req.Proto = 1
	}
	var out CloudEnrollment
	if err := c.post(ctx, "/api/pair/enroll", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Poll asks whether the code has been approved. It returns (nil, nil) while
// the answer is "not yet", so a caller can loop without treating waiting as
// an error.
func (c *CloudClient) Poll(ctx context.Context, enr *CloudEnrollment) (*CloudClaim, error) {
	if c.keypair == nil {
		return nil, fmt.Errorf("no keypair: pairing needs the key that enrolled")
	}
	ts := time.Now().UTC().Unix()
	sig := c.keypair.Sign([]byte(fmt.Sprintf("%s|%d", enr.EnrollmentID, ts)))
	body := map[string]any{
		"enrollment_id":     enr.EnrollmentID,
		"enrollment_secret": enr.EnrollmentSecret,
		"ts":                ts,
		"sig":               fmt.Sprintf("%x", sig),
	}
	var out CloudClaim
	if err := c.post(ctx, "/api/pair/poll", body, &out); err != nil {
		return nil, err
	}
	if out.DeviceID == "" {
		// Cloud answers 202 with the code while nobody has approved it yet.
		// Waiting is not a failure, so it does not come back as one.
		return nil, nil
	}
	return &out, nil
}

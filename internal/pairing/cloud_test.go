package pairing

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return kp
}

// An agent says what it is at enrolment, because Cloud shows the person
// approving the code a different page for an agent than for a panel.
func TestEnrollSaysItIsAnAgent(t *testing.T) {
	var got CloudEnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/pair/enroll" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"enrollment_id": "enr_1", "enrollment_secret": "s3cret",
			"code": "J7KM-PQ42", "kind": "agent", "expires_at": "2026-09-04T10:00:00Z",
		})
	}))
	defer srv.Close()

	kp := testKeyPair(t)
	c := NewCloudClient(srv.URL, kp)
	enr, err := c.Enroll(context.Background(), CloudEnrollRequest{
		Hostname: "worker-1", AgentID: "agt-1", AgentVersion: "0.9.4",
		MachineID: "mach-1",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if got.Kind != "agent" {
		t.Errorf("kind = %q, want agent", got.Kind)
	}
	if got.Pubkey != kp.PublicKeyHex() {
		t.Errorf("pubkey not the enrolling key")
	}
	if got.Proto != 1 {
		t.Errorf("proto = %d, want 1", got.Proto)
	}
	if enr.Code != "J7KM-PQ42" {
		t.Errorf("code = %q", enr.Code)
	}
}

// The pairing code alone is worth nothing: every poll proves possession of
// the key that enrolled.
func TestPollProvesPossessionOfTheEnrolledKey(t *testing.T) {
	kp := testKeyPair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			EnrollmentID string  `json:"enrollment_id"`
			Ts           float64 `json:"ts"`
			Sig          string  `json:"sig"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		sig, err := hex.DecodeString(body.Sig)
		if err != nil {
			t.Fatalf("signature is not hex: %v", err)
		}
		message := []byte(fmt.Sprintf("%s|%d", body.EnrollmentID, int64(body.Ts)))
		if !ed25519.Verify(kp.Public, message, sig) {
			t.Errorf("signature does not verify against the enrolled key")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"device_id": "dev_1", "org_slug": "acme", "name": "worker-1",
			"relay_url": "wss://relay.serverkit.ai",
			"scopes":    []string{"metrics.read", "update.agent"},
		})
	}))
	defer srv.Close()

	c := NewCloudClient(srv.URL, kp)
	claim, err := c.Poll(context.Background(), &CloudEnrollment{
		EnrollmentID: "enr_1", EnrollmentSecret: "s3cret"})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if claim == nil || claim.DeviceID != "dev_1" {
		t.Fatalf("claim = %+v", claim)
	}
	if claim.RelayURL != "wss://relay.serverkit.ai" {
		t.Errorf("relay url = %q", claim.RelayURL)
	}
}

// Waiting for a person to approve the code is not a failure.
func TestPollIsQuietWhileNobodyHasApprovedYet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "pending", "code": "J7KM-PQ42",
		})
	}))
	defer srv.Close()

	c := NewCloudClient(srv.URL, testKeyPair(t))
	claim, err := c.Poll(context.Background(), &CloudEnrollment{EnrollmentID: "enr_1"})
	if err != nil {
		t.Fatalf("pending should not be an error: %v", err)
	}
	if claim != nil {
		t.Errorf("claim = %+v, want nil while pending", claim)
	}
}

// Cloud's refusals are written for the person at the keyboard, so they are
// passed through rather than flattened into "pairing failed".
func TestCloudRefusalKeepsItsOwnWords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"detail": "This server is already connected to another organization",
		})
	}))
	defer srv.Close()

	c := NewCloudClient(srv.URL, testKeyPair(t))
	_, err := c.Enroll(context.Background(), CloudEnrollRequest{Hostname: "worker-1"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if err.Error() != "This server is already connected to another organization" {
		t.Errorf("error = %q", err.Error())
	}
	cloudErr, ok := err.(*CloudError)
	if !ok || cloudErr.Status != http.StatusConflict {
		t.Errorf("want a CloudError carrying 409, got %#v", err)
	}
}

// A plan limit arrives as a structured detail; the sentence inside it is the
// one to show.
func TestAPlanRefusalShowsTheSentenceInsideIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"error": "Developer includes 3 servers and this organisation has 3.",
				"check": map[string]any{"upgrade_to": "pro"},
			},
		})
	}))
	defer srv.Close()

	c := NewCloudClient(srv.URL, testKeyPair(t))
	_, err := c.Enroll(context.Background(), CloudEnrollRequest{Hostname: "worker-1"})
	if err == nil || err.Error() != "Developer includes 3 servers and this organisation has 3." {
		t.Fatalf("error = %v", err)
	}
}

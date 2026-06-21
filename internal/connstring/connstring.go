// Package connstring decodes the panel's "connection string" — a single
// URL-shaped string the user copies from the ServerKit panel and pastes
// into the agent's pairing wizard. It bundles the panel host plus a
// single-use registration token plus an optional expiry, replacing the
// older flow where the user typed those into separate fields.
//
// Format: ``sk1://<host>[:<port>]/<token>[?exp=<ISO8601>][&insecure=1]``
//
// The ``sk1://`` scheme self-identifies the format (you can recognise a
// ServerKit connection string at a glance) and gives us a version
// lever: any future format change goes out as ``sk2://``. The host is
// visible up front so the user can sanity-check which panel they're
// pointing at before pasting. ``insecure=1`` flips the implied scheme
// from https to http for dev / local-network use; absent it, https is
// implied. Older agents reject newer-versioned payloads cleanly with
// ErrUnknownVersion instead of mis-parsing them.
package connstring

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// SchemePrefix is the scheme + separator that introduces every v1
	// connection string. Used to fail fast on legacy or unrelated input
	// before we try to parse it as a URL.
	SchemePrefix = "sk1://"
)

// Decoded is the data extracted from a connection string.
type Decoded struct {
	URL          string    // reconstructed http/https URL of the panel
	Token        string    // single-use registration token
	ExpiresAt    time.Time // zero value means "never" or "unparseable"
	ExpiresAtRaw string    // panel's exact expiry string (or "" if none)
}

// ErrUnknownVersion is returned when the prefix is missing or names a
// version this build doesn't understand. Callers should surface this as
// "your panel is newer than this agent" rather than a generic decode
// error — it's almost always the cause.
var ErrUnknownVersion = errors.New("connstring: unknown version prefix")

// Decode parses a connection string. Whitespace surrounding the input
// is stripped (paste-from-clipboard often picks up a trailing newline).
func Decode(s string) (*Decoded, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("connstring: empty input")
	}
	if !strings.HasPrefix(s, SchemePrefix) {
		return nil, ErrUnknownVersion
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("connstring: parse: %w", err)
	}
	if u.Scheme != "sk1" {
		return nil, ErrUnknownVersion
	}
	if u.Host == "" {
		return nil, errors.New("connstring: missing host")
	}

	token := strings.TrimPrefix(u.Path, "/")
	if token == "" {
		return nil, errors.New("connstring: missing token")
	}
	// Tokens are url-safe by construction (panel uses secrets.token_urlsafe);
	// a stray slash means the user mangled the string. Better to fail
	// loudly than silently truncate.
	if strings.Contains(token, "/") {
		return nil, errors.New("connstring: token must not contain '/'")
	}

	q := u.Query()
	scheme := "https"
	switch q.Get("insecure") {
	case "1", "true", "yes":
		scheme = "http"
	}

	out := &Decoded{
		URL:   scheme + "://" + u.Host,
		Token: token,
	}
	if exp := q.Get("exp"); exp != "" {
		out.ExpiresAtRaw = exp
		// Best-effort parse — if the panel sends a format we don't
		// understand we still surface the raw value, and the panel
		// remains the source of truth on whether the token is good.
		if t, perr := time.Parse(time.RFC3339, exp); perr == nil {
			out.ExpiresAt = t
		}
	}
	return out, nil
}

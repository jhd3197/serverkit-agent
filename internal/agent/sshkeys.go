package agent

// Pure authorized_keys helpers for the ssh:keys:* handlers. Nothing here
// touches the filesystem or runs a command, so it is unit-testable on any
// OS; sshkeys_handlers.go does the privileged I/O.
//
// Keys are matched on their material (type + base64 blob), never on the
// whole line: an admin editing a comment, or the panel re-issuing the
// same key with new options (a longer expiry), must still find it.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sshKeyTypes are the public key algorithms the handlers accept.
var sshKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var (
	// sshUsernameRe is the portable POSIX login shape useradd accepts.
	// Rejects anything that could walk a path or smuggle a flag.
	sshUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sshBlobRe     = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	// sshOptionRe is one authorized_keys option: a bare flag
	// (no-pty) or name="value" with no quote or newline in the value.
	sshOptionRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*(="[^"\r\n]*")?$`)
	sshVersionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
	sshCommentRe = regexp.MustCompile(`^[^\r\n]{0,200}$`)
)

// sshKey is a parsed public key: material plus an optional comment.
type sshKey struct {
	Type    string
	Blob    string
	Comment string
}

func (k sshKey) material() string { return k.Type + " " + k.Blob }

// fingerprint is the OpenSSH-style SHA256 fingerprint of the key blob.
func (k sshKey) fingerprint() string {
	raw, err := base64.StdEncoding.DecodeString(k.Blob)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func validateSSHUsername(user string) error {
	if !sshUsernameRe.MatchString(user) {
		return fmt.Errorf("invalid username %q", user)
	}
	return nil
}

// parsePublicKey validates a bare "<type> <blob> [comment]" key (no
// options — those are passed separately so they can be validated).
func parsePublicKey(line string) (sshKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return sshKey{}, fmt.Errorf("public key must be a single line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return sshKey{}, fmt.Errorf(`public key must be "<type> <base64-blob> [comment]"`)
	}
	if !sshKeyTypes[fields[0]] {
		return sshKey{}, fmt.Errorf("unsupported key type %q", fields[0])
	}
	if !sshBlobRe.MatchString(fields[1]) {
		return sshKey{}, fmt.Errorf("key blob is not valid base64")
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return sshKey{}, fmt.Errorf("key blob is not valid base64")
	}
	return sshKey{Type: fields[0], Blob: fields[1], Comment: strings.Join(fields[2:], " ")}, nil
}

func validateSSHOptions(options []string) error {
	for _, opt := range options {
		if !sshOptionRe.MatchString(opt) {
			return fmt.Errorf("invalid authorized_keys option %q", opt)
		}
	}
	return nil
}

// parseAuthorizedKeysLine extracts the key from one authorized_keys line,
// skipping a leading options field (which may hold quoted spaces). ok is
// false for blank lines, comments and anything unparseable — those lines
// are always preserved verbatim.
func parseAuthorizedKeysLine(line string) (key sshKey, options string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return sshKey{}, "", false
	}
	rest := trimmed
	first := strings.Fields(rest)[0]
	if !sshKeyTypes[first] {
		// Options field: runs to the first whitespace outside quotes.
		inQuote := false
		end := -1
		for i, r := range rest {
			if r == '"' {
				inQuote = !inQuote
			} else if !inQuote && (r == ' ' || r == '\t') {
				end = i
				break
			}
		}
		if end < 0 {
			return sshKey{}, "", false
		}
		options = rest[:end]
		rest = strings.TrimSpace(rest[end:])
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 || !sshKeyTypes[fields[0]] {
		return sshKey{}, "", false
	}
	return sshKey{Type: fields[0], Blob: fields[1], Comment: strings.Join(fields[2:], " ")}, options, true
}

// formatAuthorizedKeysLine renders options + key + comment as one line.
func formatAuthorizedKeysLine(key sshKey, options []string) string {
	var b strings.Builder
	if len(options) > 0 {
		b.WriteString(strings.Join(options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(key.material())
	if key.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(key.Comment)
	}
	return b.String()
}

// authorizedKeysUpsert returns content with exactly one line for key's
// material, rendered as newLine. An existing line for the same material
// is replaced in place (so re-issuing with a later expiry works); every
// other line is kept verbatim. changed is false when the file already
// holds exactly newLine.
func authorizedKeysUpsert(content string, key sshKey, newLine string) (string, bool) {
	lines := splitLines(content)
	out := make([]string, 0, len(lines)+1)
	found, changed := false, false
	for _, line := range lines {
		k, _, ok := parseAuthorizedKeysLine(line)
		if ok && k.material() == key.material() {
			if found {
				changed = true // drop duplicates of the same key
				continue
			}
			found = true
			if line != newLine {
				changed = true
			}
			out = append(out, newLine)
			continue
		}
		out = append(out, line)
	}
	if !found {
		out = append(out, newLine)
		changed = true
	}
	return joinLines(out), changed
}

// authorizedKeysRemove drops every line carrying key's material.
func authorizedKeysRemove(content string, key sshKey) (string, bool) {
	lines := splitLines(content)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if k, _, ok := parseAuthorizedKeysLine(line); ok && k.material() == key.material() {
			continue
		}
		out = append(out, line)
	}
	if len(out) == len(lines) {
		return content, false
	}
	return joinLines(out), true
}

func splitLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// parseOpenSSHVersion pulls (major, minor) out of `ssh -V` output.
func parseOpenSSHVersion(out string) (int, int, bool) {
	m := sshVersionRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major, minor, true
}

// supportsExpiryTime reports whether this OpenSSH honors the
// expiry-time= key option (added in 8.2). An sshd that doesn't know an
// option ignores the whole line, so it must never be sent to one.
func supportsExpiryTime(major, minor int) bool {
	return major > 8 || (major == 8 && minor >= 2)
}

// expiryTimeOption renders expiry-time= in the host's local zone, the
// form every OpenSSH >= 8.2 accepts (the Z suffix came later).
func expiryTimeOption(t time.Time) string {
	return fmt.Sprintf(`expiry-time="%s"`, t.Local().Format("200601021504"))
}

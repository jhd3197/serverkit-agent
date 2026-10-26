package agent

import (
	"strings"
	"testing"
	"time"
)

const (
	testBlobA = "AAAAC3NzaC1lZDI1NTE5AAAAIJ5x0Qm0VbI8tq3F7sLx0Wl5mJ7C8u5c1QwQ7mY3a2Zb"
	testBlobB = "AAAAC3NzaC1lZDI1NTE5AAAAIK9yZ0x8Yv2Qm1Wn3Rt4Uo5Ip6Lk7Jh8Gf9Ds0Aq1Zc2"
)

func mustKey(t *testing.T, line string) sshKey {
	t.Helper()
	k, err := parsePublicKey(line)
	if err != nil {
		t.Fatalf("parsePublicKey(%q): %v", line, err)
	}
	return k
}

func TestValidateSSHUsername(t *testing.T) {
	for _, ok := range []string{"root", "deploy", "faro_grant", "a-b1"} {
		if err := validateSSHUsername(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc", "Root", "-rf", "a b", "a/b", strings.Repeat("a", 33)} {
		if err := validateSSHUsername(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestParsePublicKeyRejectsJunk(t *testing.T) {
	for _, bad := range []string{
		"",
		"ssh-ed25519",
		"ssh-dss " + testBlobA,
		"ssh-ed25519 not*base64",
		"ssh-ed25519 " + testBlobA + "\nssh-ed25519 " + testBlobB,
	} {
		if _, err := parsePublicKey(bad); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
	k := mustKey(t, "  ssh-ed25519   "+testBlobA+"  faro grant 7 ")
	if k.Comment != "faro grant 7" {
		t.Errorf("comment = %q", k.Comment)
	}
	if !strings.HasPrefix(k.fingerprint(), "SHA256:") {
		t.Errorf("fingerprint = %q", k.fingerprint())
	}
}

func TestValidateSSHOptions(t *testing.T) {
	good := []string{"no-pty", `permitopen="10.0.0.5:22"`, `from="1.2.3.4"`}
	if err := validateSSHOptions(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`command="a"b"`, "no pty", "x=\"a\nb\"", `,no-pty`} {
		if err := validateSSHOptions([]string{bad}); err == nil {
			t.Errorf("expected rejection for %q", bad)
		}
	}
}

func TestParseAuthorizedKeysLineSkipsQuotedOptions(t *testing.T) {
	line := `command="echo hi there",no-pty ssh-ed25519 ` + testBlobA + ` me@host`
	k, opts, ok := parseAuthorizedKeysLine(line)
	if !ok {
		t.Fatal("expected a key")
	}
	if k.Blob != testBlobA || k.Comment != "me@host" {
		t.Errorf("got %+v", k)
	}
	if opts != `command="echo hi there",no-pty` {
		t.Errorf("opts = %q", opts)
	}
	for _, skip := range []string{"", "   ", "# ssh-ed25519 " + testBlobA, "garbage"} {
		if _, _, ok := parseAuthorizedKeysLine(skip); ok {
			t.Errorf("%q should not parse as a key", skip)
		}
	}
}

func TestUpsertPreservesOtherLinesAndReplacesOptions(t *testing.T) {
	owner := "ssh-ed25519 " + testBlobB + " owner@laptop"
	existing := "# managed by hand\n" + owner + "\nno-pty ssh-ed25519 " + testBlobA + " old\n"
	key := mustKey(t, "ssh-ed25519 "+testBlobA+" faro-grant:7")
	newLine := formatAuthorizedKeysLine(key, []string{"no-agent-forwarding", expiryTimeOption(time.Unix(0, 0))})

	out, changed := authorizedKeysUpsert(existing, key, newLine)
	if !changed {
		t.Fatal("expected a change")
	}
	if !strings.Contains(out, owner+"\n") || !strings.HasPrefix(out, "# managed by hand\n") {
		t.Errorf("owner lines lost:\n%s", out)
	}
	if strings.Count(out, testBlobA) != 1 || !strings.Contains(out, newLine) {
		t.Errorf("grant key not replaced exactly once:\n%s", out)
	}

	again, changed := authorizedKeysUpsert(out, key, newLine)
	if changed || again != out {
		t.Error("second upsert should be a no-op")
	}
}

func TestUpsertIntoEmptyAndCRLF(t *testing.T) {
	key := mustKey(t, "ssh-ed25519 "+testBlobA)
	out, changed := authorizedKeysUpsert("", key, key.material())
	if !changed || out != key.material()+"\n" {
		t.Errorf("got %q", out)
	}
	crlf := "ssh-ed25519 " + testBlobB + " a\r\n"
	out, _ = authorizedKeysUpsert(crlf, key, key.material())
	if out != "ssh-ed25519 "+testBlobB+" a\n"+key.material()+"\n" {
		t.Errorf("got %q", out)
	}
}

func TestRemoveMatchesMaterialIgnoringOptionsAndComment(t *testing.T) {
	owner := "ssh-ed25519 " + testBlobB + " owner"
	content := owner + "\n" + `from="1.2.3.4" ssh-ed25519 ` + testBlobA + " edited comment\n"
	key := mustKey(t, "ssh-ed25519 "+testBlobA+" faro-grant:7")

	out, changed := authorizedKeysRemove(content, key)
	if !changed || out != owner+"\n" {
		t.Errorf("got %q", out)
	}
	same, changed := authorizedKeysRemove(out, key)
	if changed || same != out {
		t.Error("removing an absent key should be a no-op")
	}
	empty, _ := authorizedKeysRemove(`no-pty ssh-ed25519 `+testBlobA+"\n", key)
	if empty != "" {
		t.Errorf("got %q", empty)
	}
}

func TestOpenSSHVersionGate(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13", true},
		{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", true},
		{"OpenSSH_8.1p1", false},
		{"OpenSSH_7.6p1 Ubuntu-4ubuntu0.7", false},
		{"OpenSSH_10.0p2", true},
	}
	for _, c := range cases {
		major, minor, ok := parseOpenSSHVersion(c.out)
		if !ok {
			t.Fatalf("no version in %q", c.out)
		}
		if got := supportsExpiryTime(major, minor); got != c.want {
			t.Errorf("%q: got %v want %v", c.out, got, c.want)
		}
	}
	if _, _, ok := parseOpenSSHVersion("dropbear v2022.83"); ok {
		t.Error("dropbear should not parse")
	}
}

func TestExpiryTimeOptionShape(t *testing.T) {
	opt := expiryTimeOption(time.Date(2026, 10, 29, 15, 4, 0, 0, time.Local))
	if opt != `expiry-time="202610291504"` {
		t.Errorf("got %s", opt)
	}
	if err := validateSSHOptions([]string{opt}); err != nil {
		t.Errorf("expiry option fails our own validation: %v", err)
	}
}

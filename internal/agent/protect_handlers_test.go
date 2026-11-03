package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

type recorder struct {
	calls  [][]string
	tools  map[string]bool
	outFor func(call []string) string
	fail   func(call []string) bool
}

// install swaps the exec seams for the test and restores them afterwards.
func (r *recorder) install(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("security handlers are linux-only")
	}
	oRun, oLook, oFetch := secRun, secLookPath, secFetch
	t.Cleanup(func() { secRun, secLookPath, secFetch = oRun, oLook, oFetch })
	secLookPath = func(n string) (string, error) {
		if r.tools[n] {
			return "/usr/bin/" + n, nil
		}
		return "", exec.ErrNotFound
	}
	secRun = func(_ context.Context, name string, args ...string) ([]byte, error) {
		call := append([]string{name}, args...)
		r.calls = append(r.calls, call)
		if r.fail != nil && r.fail(call) {
			return []byte("boom"), errors.New("exit 1")
		}
		if r.outFor != nil {
			return []byte(r.outFor(call)), nil
		}
		return nil, nil
	}
	secFetch = func(context.Context, string) (string, error) { return "", errors.New("offline") }
}

func (r *recorder) called(prefix ...string) bool {
	for _, c := range r.calls {
		if len(c) >= len(prefix) && strings.Join(c[:len(prefix)], " ") == strings.Join(prefix, " ") {
			return true
		}
	}
	return false
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestIPValidation(t *testing.T) {
	good := []string{"1.2.3.4", "10.0.0.0/24", "2001:db8::1", "2001:db8::/48"}
	for _, s := range good {
		if _, err := parseBanTarget(s); err != nil {
			t.Errorf("parseBanTarget(%q): %v", s, err)
		}
	}
	bad := []string{"", "1.2.3", "1.2.3.4; rm -rf /", "-1.2.3.4", "0.0.0.0", "0.0.0.0/0", "::/0", "::", "1.2.3.4/33",
		"127.0.0.1", "::1", "224.0.0.1", "fe80::1%eth0", "10.0.0.0/8", "$(id)", "1.2.3.4 -j DROP", "1.2.3.4\n5.6.7.8"}
	for _, s := range bad {
		if _, err := parseBanTarget(s); err == nil {
			t.Errorf("parseBanTarget(%q) should fail", s)
		}
	}
	p, _ := parseBanTarget("10.0.0.77/24")
	if p.String() != "10.0.0.0/24" {
		t.Errorf("not canonicalised: %s", p)
	}
}

func TestJailAndDurationValidation(t *testing.T) {
	for _, ok := range []string{"sshd", "nginx-http-auth", "a_b-1", strings.Repeat("a", 40)} {
		if _, err := parseJail(ok); err != nil {
			t.Errorf("jail %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "ssh d", "a;b", "../x", "-sshd ", strings.Repeat("a", 41), "jail\n", "ja$il"} {
		if _, err := parseJail(bad); err == nil {
			t.Errorf("jail %q accepted", bad)
		}
	}
	if d, err := parseDuration(0); err != nil || d != defaultBanSecs {
		t.Errorf("default duration: %d %v", d, err)
	}
	for _, bad := range []int{-1, maxBanSeconds + 1} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("duration %d accepted", bad)
		}
	}
	if _, err := parseDuration(maxBanSeconds); err != nil {
		t.Error("max duration should be accepted")
	}
	if _, err := parsePortProto(0, "tcp"); err == nil {
		t.Error("port 0 accepted")
	}
	if _, err := parsePortProto(80, "icmp"); err == nil {
		t.Error("bad proto accepted")
	}
}

func TestFail2banFixedArgv(t *testing.T) {
	r := &recorder{tools: map[string]bool{"fail2ban-client": true}}
	r.install(t)
	a := &Agent{}
	if _, err := a.handleFail2banBan(context.Background(), raw(`{"jail":"sshd","ip":"203.0.113.9"}`)); err != nil {
		t.Fatal(err)
	}
	want := []string{"fail2ban-client", "set", "sshd", "banip", "203.0.113.9"}
	if len(r.calls) != 1 || strings.Join(r.calls[0], "|") != strings.Join(want, "|") {
		t.Fatalf("argv = %v", r.calls)
	}
	// invalid input must never reach exec
	r.calls = nil
	for _, p := range []string{
		`{"jail":"ss d","ip":"203.0.113.9"}`, `{"jail":"sshd","ip":"203.0.113.9; id"}`,
		`{"jail":"sshd","ip":"203.0.113.0/24"}`, `{"jail":"","ip":"203.0.113.9"}`, `not json`,
	} {
		if _, err := a.handleFail2banUnban(context.Background(), raw(p)); err == nil {
			t.Errorf("accepted %s", p)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("exec reached with invalid input: %v", r.calls)
	}
}

func TestFail2banMissingTool(t *testing.T) {
	r := &recorder{tools: map[string]bool{}}
	r.install(t)
	_, err := (&Agent{}).handleFail2banStatus(context.Background(), raw(`{}`))
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("err = %v", err)
	}
}

func TestCrowdsecArgv(t *testing.T) {
	r := &recorder{tools: map[string]bool{"cscli": true}}
	r.install(t)
	a := &Agent{}
	if _, err := a.handleCrowdsecBan(context.Background(), raw(`{"ip":"203.0.113.0/24","duration_seconds":600,"reason":"; rm -rf /"}`)); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(r.calls[0], " ")
	if got != "cscli decisions add --range 203.0.113.0/24 --duration 600s --reason serverkit ban" {
		t.Fatalf("argv = %s", got)
	}
	r.calls = nil
	if _, err := a.handleCrowdsecBan(context.Background(), raw(`{"ip":"203.0.113.9","duration_seconds":99999999}`)); err == nil {
		t.Error("unbounded duration accepted")
	}
	if _, err := a.handleCrowdsecUnban(context.Background(), raw(`{"ip":"203.0.113.9"}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.calls[0], " ") != "cscli decisions delete --ip 203.0.113.9" {
		t.Fatalf("argv = %v", r.calls[0])
	}
	r.outFor = func([]string) string { return "null" }
	res, err := a.handleCrowdsecDecisionsList(context.Background(), nil)
	if err != nil || string(res.(map[string]interface{})["decisions"].(json.RawMessage)) != "[]" {
		t.Fatalf("list: %v %v", res, err)
	}
}

func TestFirewallIPRules(t *testing.T) {
	r := &recorder{tools: map[string]bool{"ufw": true}}
	r.install(t)
	a := &Agent{}
	if _, err := a.handleFirewallDenyIP(context.Background(), raw(`{"ip":"198.51.100.7"}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.calls[0], " ") != "ufw insert 1 deny from 198.51.100.7" {
		t.Fatalf("argv = %v", r.calls[0])
	}
	r.calls = nil
	if _, err := a.handleFirewallAllowIP(context.Background(), raw(`{"ip":"198.51.100.0/24","port":443,"protocol":"tcp"}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.calls[0], " ") != "ufw allow from 198.51.100.0/24 to any port 443 proto tcp" {
		t.Fatalf("argv = %v", r.calls[0])
	}
	r.calls = nil
	for _, p := range []string{`{"ip":"0.0.0.0/0"}`, `{"ip":"1.2.3.4","port":70000}`, `{"ip":"1.2.3.4","port":80,"protocol":"x"}`} {
		if _, err := a.handleFirewallAllowIP(context.Background(), raw(p)); err == nil {
			t.Errorf("accepted %s", p)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("exec reached with invalid input: %v", r.calls)
	}
	r.tools = map[string]bool{}
	if _, err := a.handleFirewallDenyIP(context.Background(), raw(`{"ip":"198.51.100.7"}`)); err == nil || !strings.Contains(err.Error(), "ufw") {
		t.Errorf("want ufw-missing error, got %v", err)
	}
}

func TestOriginLockRefusesWithoutUfw(t *testing.T) {
	r := &recorder{tools: map[string]bool{}}
	r.install(t)
	a := &Agent{}
	for name, h := range map[string]CommandHandler{"apply": a.handleOriginLockApply, "remove": a.handleOriginLockRemove, "status": a.handleOriginLockStatus} {
		_, err := h(context.Background(), raw(`{}`))
		if err == nil || !strings.Contains(err.Error(), "ufw") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("ran commands without ufw: %v", r.calls)
	}
}

func TestOriginLockRefusesInactiveUfwAndPort22(t *testing.T) {
	r := &recorder{tools: map[string]bool{"ufw": true}, outFor: func([]string) string { return "Status: inactive" }}
	r.install(t)
	a := &Agent{}
	if _, err := a.handleOriginLockApply(context.Background(), raw(`{}`)); err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.handleOriginLockApply(context.Background(), raw(`{"ports":[22]}`)); err == nil {
		t.Fatal("port 22 accepted")
	}
	for _, c := range r.calls {
		if len(c) > 1 && c[1] != "status" {
			t.Fatalf("mutating call made: %v", c)
		}
	}
}

func TestOriginLockApplyOrderAndSSHUntouched(t *testing.T) {
	r := &recorder{tools: map[string]bool{"ufw": true}, outFor: func(c []string) string {
		if len(c) == 2 && c[1] == "status" {
			return "Status: active"
		}
		return ""
	}}
	r.install(t)
	res, err := (&Agent{}).handleOriginLockApply(context.Background(), raw(`{"refresh":false}`))
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]interface{})
	if m["source"] != "embedded" || m["ranges"].(int) != len(cloudflareFallbackV4)+len(cloudflareFallbackV6) {
		t.Fatalf("result = %v", m)
	}
	lastAdd, firstDel := -1, -1
	for i, c := range r.calls {
		j := strings.Join(c, " ")
		for _, tok := range c {
			if tok == "22" || tok == "22/tcp" || tok == "ssh" || tok == "OpenSSH" {
				t.Errorf("call touches ssh: %s", j)
			}
		}
		if c[1] == "allow" && strings.HasSuffix(j, "comment "+originLockTag) {
			lastAdd = i
		}
		if c[1] == "--force" && c[2] == "delete" && firstDel < 0 {
			firstDel = i
		}
	}
	if lastAdd < 0 || firstDel < 0 || lastAdd > firstDel {
		t.Fatalf("public rules must only be deleted after every allow (lastAdd=%d firstDel=%d)", lastAdd, firstDel)
	}
	if !r.called("ufw", "--force", "delete", "allow", "80/tcp") || !r.called("ufw", "--force", "delete", "allow", "Nginx Full") {
		t.Error("public 80/443 rules not removed")
	}
}

func TestOriginLockAbortsBeforeClosingOnAddFailure(t *testing.T) {
	r := &recorder{tools: map[string]bool{"ufw": true},
		outFor: func(c []string) string {
			if len(c) == 2 && c[1] == "status" {
				return "Status: active"
			}
			return ""
		},
		fail: func(c []string) bool {
			return c[1] == "allow" && strings.Contains(strings.Join(c, " "), "104.16.0.0/13")
		}}
	r.install(t)
	if _, err := (&Agent{}).handleOriginLockApply(context.Background(), raw(`{"refresh":false}`)); err == nil {
		t.Fatal("expected failure")
	}
	for _, c := range r.calls {
		if c[1] == "--force" {
			t.Fatalf("public rules deleted after a failed allow: %v", c)
		}
	}
}

func TestCloudflareRangesLiveAndFallback(t *testing.T) {
	r := &recorder{}
	r.install(t)
	secFetch = func(_ context.Context, u string) (string, error) {
		if strings.HasSuffix(u, "ips-v4") {
			return "173.245.48.0/20\n103.21.244.0/22\n", nil
		}
		return "2400:cb00::/32\n", nil
	}
	got, src := cloudflareRanges(context.Background(), true)
	if src != "cloudflare.com" || len(got) != 3 {
		t.Fatalf("live: %v %s", got, src)
	}
	secFetch = func(context.Context, string) (string, error) { return "<html>nope</html>", nil }
	got, src = cloudflareRanges(context.Background(), true)
	if src != "embedded" || len(got) != len(cloudflareFallbackV4)+len(cloudflareFallbackV6) {
		t.Fatalf("garbage must fall back: %s %d", src, len(got))
	}
	for _, p := range got {
		if p.Bits() == 0 {
			t.Fatal("fallback contains /0")
		}
	}
}

func TestOriginLockRemoveParsesTaggedRulesOnly(t *testing.T) {
	added := `ufw allow 22/tcp
ufw allow from 173.245.48.0/20 to any port 443 proto tcp comment 'serverkit-origin-lock'
ufw allow from 10.0.0.0/8 to any port 443 proto tcp comment 'other'
ufw allow from 1.1.1.1; id to any port 443 proto tcp comment 'serverkit-origin-lock'
ufw allow from 2400:cb00::/32 to any port 80 proto tcp comment 'serverkit-origin-lock'`
	rules := taggedLockRules(added)
	if len(rules) != 2 {
		t.Fatalf("rules = %v", rules)
	}
	r := &recorder{tools: map[string]bool{"ufw": true}, outFor: func(c []string) string {
		if len(c) > 2 && c[1] == "show" {
			return added
		}
		return ""
	}}
	r.install(t)
	res, err := (&Agent{}).handleOriginLockRemove(context.Background(), raw(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.(map[string]interface{})["rules_removed"].(int) != 2 {
		t.Fatalf("res = %v", res)
	}
	if !r.called("ufw", "allow", "80/tcp") || !r.called("ufw", "allow", "443/tcp") {
		t.Error("remove must reopen 80/443 first")
	}
	if r.called("ufw", "--force", "delete", "allow", "22/tcp") {
		t.Error("touched ssh rule")
	}
}

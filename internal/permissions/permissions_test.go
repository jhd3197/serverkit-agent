package permissions

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// protocolActions parses pkg/protocol and returns every `Action*` string
// constant, so a new action without a table entry fails this test.
func protocolActions(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../pkg/protocol/messages.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "Action") || i >= len(vs.Values) {
				continue
			}
			if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				v, _ := strconv.Unquote(lit.Value)
				out[name.Name] = v
			}
		}
		return true
	})
	return out
}

func TestEveryActionClassified(t *testing.T) {
	acts := protocolActions(t)
	if len(acts) < 100 {
		t.Fatalf("parsed only %d actions; parser broken?", len(acts))
	}
	for name, v := range acts {
		if _, ok := Required(v); !ok {
			t.Errorf("protocol.%s (%q) has no entry in the permissions table", name, v)
		}
	}
	// and no stale table entries
	known := map[string]bool{}
	for _, v := range acts {
		known[v] = true
	}
	for _, a := range KnownActions() {
		if !known[a] {
			t.Errorf("table entry %q is not a protocol Action constant", a)
		}
	}
}

func TestAllowedMatrix(t *testing.T) {
	cases := []struct {
		level  Level
		action string
		want   bool
	}{
		{Monitor, "firewall:status", false},
		{Monitor, "system:metrics", false},
		{Protect, "firewall:allow_port", true},
		{Protect, "fail2ban:ban", true},
		{Protect, "crowdsec:decisions:list", true},
		{Protect, "cloudflare:origin_lock:apply", true},
		{Protect, "system:exec", false},
		{Protect, "docker:container:list", false},
		{Protect, "terminal:create", false},
		{Protect, "file:read", false},
		{Protect, "ssh:keys:add", false},
		{Protect, "agent:update", false},
		{Protect, "totally:unknown", false},
		{Full, "system:exec", true},
		{Full, "fail2ban:ban", true},
		{Full, "totally:unknown", true}, // handler lookup will say "unknown action"
		{Level("bogus"), "firewall:status", false},
	}
	for _, c := range cases {
		if got := Allowed(c.level, c.action); got != c.want {
			t.Errorf("Allowed(%s, %s) = %v, want %v", c.level, c.action, got, c.want)
		}
	}
}

func TestCheckMessage(t *testing.T) {
	err := Check(Protect, "system:exec")
	want := "action system:exec requires permission level full; this agent is configured as protect"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if Check(Full, "system:exec") != nil {
		t.Fatal("full must allow")
	}
}

func TestParse(t *testing.T) {
	for _, ok := range []string{"monitor", "PROTECT", " full "} {
		if _, err := Parse(ok); err != nil {
			t.Errorf("Parse(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "root", "admin"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestChannelAllowed(t *testing.T) {
	if !ChannelAllowed(Protect, "metrics") || ChannelAllowed(Protect, "terminal:abc") || ChannelAllowed(Protect, "job:1") {
		t.Error("protect channel gating wrong")
	}
	if ChannelAllowed(Monitor, "metrics") || !ChannelAllowed(Full, "terminal:abc") {
		t.Error("monitor/full channel gating wrong")
	}
}

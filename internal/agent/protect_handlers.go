package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Security handlers available at permission level protect (and full):
// firewall ip/status, fail2ban, CrowdSec (cscli) and the Cloudflare origin
// lock. Every external call is exec with a fixed argv — never a shell — and
// every operator-supplied value is validated first: IPs/CIDRs through
// net/netip (re-rendered from the parsed value), ports as integers, jail
// names against jailNameRe, ban durations bounded.

const (
	originLockTag   = "serverkit-origin-lock"
	maxBanSeconds   = 30 * 24 * 3600
	defaultBanSecs  = 3600
	cloudflareV4URL = "https://www.cloudflare.com/ips-v4"
	cloudflareV6URL = "https://www.cloudflare.com/ips-v6"
)

var jailNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)

// Seams replaced by tests.
var (
	secRun = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	secLookPath = exec.LookPath
	secFetch    = func(ctx context.Context, url string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return string(b), err
	}
)

// parseNetwork validates an IP or CIDR and returns it in canonical masked
// form. minBits rejects blanket ranges (0 = only reject /0).
func parseNetwork(s string, minBitsV4, minBitsV6 int) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("invalid CIDR %q", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return p, fmt.Errorf("invalid IP address %q", s)
		}
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	}
	if p.Addr().Zone() != "" {
		return p, fmt.Errorf("IPv6 zones are not allowed")
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	if p.Addr().IsUnspecified() || p.Bits() == 0 {
		return p, fmt.Errorf("refusing unspecified/any address %q", s)
	}
	min := minBitsV6
	if p.Addr().Is4() {
		min = minBitsV4
	}
	if p.Bits() < min {
		return p, fmt.Errorf("range %s is too broad (minimum /%d)", p, min)
	}
	return p, nil
}

// parseBanTarget is parseNetwork plus the extra refusals for bans: never
// ban loopback, link-local or multicast space.
func parseBanTarget(s string) (netip.Prefix, error) {
	p, err := parseNetwork(s, 16, 32)
	if err != nil {
		return p, err
	}
	a := p.Addr()
	if a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return p, fmt.Errorf("refusing to act on loopback/multicast/link-local address %s", p)
	}
	return p, nil
}

func parseJail(s string) (string, error) {
	if !jailNameRe.MatchString(s) {
		return "", fmt.Errorf("invalid jail name %q", s)
	}
	return s, nil
}

func parseDuration(secs int) (int, error) {
	if secs == 0 {
		return defaultBanSecs, nil
	}
	if secs < 1 || secs > maxBanSeconds {
		return 0, fmt.Errorf("duration_seconds must be between 1 and %d", maxBanSeconds)
	}
	return secs, nil
}

func parsePortProto(port int, proto string) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d", port)
	}
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("invalid protocol %q", proto)
	}
	return proto, nil
}

func requireLinux() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this action is only supported on Linux agents")
	}
	return nil
}

func requireTool(name string) error {
	if _, err := secLookPath(name); err != nil {
		return fmt.Errorf("%s is not installed on this host", name)
	}
	return nil
}

func runTool(ctx context.Context, name string, args ...string) (string, error) {
	out, err := secRun(ctx, name, args...)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w (%s)", name, args[0], err, text)
	}
	return text, nil
}

func decodeParams(params json.RawMessage, v interface{}) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, v); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	return nil
}

// ---- firewall: status / ip rules (ufw) ----

func (a *Agent) handleFirewallStatus(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if secHas("ufw") {
		out, err := runTool(ctx, "ufw", "status", "verbose")
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"method": "ufw", "active": ufwActive(out), "output": out}, nil
	}
	if secHas("firewall-cmd") {
		out, err := runTool(ctx, "firewall-cmd", "--list-all")
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"method": "firewalld", "active": true, "output": out}, nil
	}
	return nil, fmt.Errorf("no supported firewall found (ufw / firewalld)")
}

func secHas(tool string) bool { _, err := secLookPath(tool); return err == nil }

func ufwActive(statusOut string) bool {
	return strings.Contains(strings.ToLower(statusOut), "status: active")
}

type ipRuleParams struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (a *Agent) handleFirewallAllowIP(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return firewallIP(ctx, params, true)
}

func (a *Agent) handleFirewallDenyIP(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return firewallIP(ctx, params, false)
}

func firewallIP(ctx context.Context, params json.RawMessage, allow bool) (interface{}, error) {
	var p ipRuleParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	var net netip.Prefix
	var err error
	if allow {
		net, err = parseNetwork(p.IP, 8, 16)
	} else {
		net, err = parseBanTarget(p.IP)
	}
	if err != nil {
		return nil, err
	}
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("ufw"); err != nil {
		return nil, fmt.Errorf("per-IP firewall rules need ufw: %w", err)
	}
	var args []string
	if allow {
		args = []string{"allow", "from", ipArg(net)}
	} else {
		// insert at the top so the deny wins over broader allow rules
		args = []string{"insert", "1", "deny", "from", ipArg(net)}
	}
	if p.Port != 0 {
		proto, err := parsePortProto(p.Port, p.Protocol)
		if err != nil {
			return nil, err
		}
		args = append(args, "to", "any", "port", strconv.Itoa(p.Port), "proto", proto)
	}
	if _, err := runTool(ctx, "ufw", args...); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "method": "ufw", "ip": ipArg(net), "allow": allow}, nil
}

// ---- fail2ban ----

func (a *Agent) handleFail2banStatus(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Jail string `json:"jail"`
	}
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	args := []string{"status"}
	if p.Jail != "" {
		jail, err := parseJail(p.Jail)
		if err != nil {
			return nil, err
		}
		args = append(args, jail)
	}
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("fail2ban-client"); err != nil {
		return nil, err
	}
	out, err := runTool(ctx, "fail2ban-client", args...)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"jail": p.Jail, "output": out}, nil
}

type fail2banParams struct {
	Jail string `json:"jail"`
	IP   string `json:"ip"`
}

func (a *Agent) handleFail2banBan(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return fail2banSet(ctx, params, "banip")
}

func (a *Agent) handleFail2banUnban(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return fail2banSet(ctx, params, "unbanip")
}

// fail2ban bans use the jail's own bantime; there is no per-ban duration.
func fail2banSet(ctx context.Context, params json.RawMessage, verb string) (interface{}, error) {
	var p fail2banParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	jail, err := parseJail(p.Jail)
	if err != nil {
		return nil, err
	}
	// fail2ban's banip takes single addresses only.
	pre, err := parseBanTarget(p.IP)
	if err != nil {
		return nil, err
	}
	if pre.Bits() != pre.Addr().BitLen() {
		return nil, fmt.Errorf("fail2ban acts on single IP addresses, not ranges")
	}
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("fail2ban-client"); err != nil {
		return nil, err
	}
	out, err := runTool(ctx, "fail2ban-client", "set", jail, verb, pre.Addr().String())
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "jail": jail, "ip": pre.Addr().String(), "output": out}, nil
}

// ---- CrowdSec ----

func (a *Agent) handleCrowdsecDecisionsList(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("cscli"); err != nil {
		return nil, err
	}
	out, err := runTool(ctx, "cscli", "decisions", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var decisions json.RawMessage
	if out == "" || out == "null" {
		decisions = json.RawMessage("[]")
	} else if json.Valid([]byte(out)) {
		decisions = json.RawMessage(out)
	} else {
		return nil, fmt.Errorf("cscli returned non-JSON output")
	}
	return map[string]interface{}{"decisions": decisions}, nil
}

type crowdsecParams struct {
	IP       string `json:"ip"`
	Duration int    `json:"duration_seconds"`
	Reason   string `json:"reason"`
}

// ipArg renders a single host as a bare address and a range as CIDR.
func ipArg(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

func cscliTarget(p netip.Prefix) []string {
	if p.Bits() == p.Addr().BitLen() {
		return []string{"--ip", p.Addr().String()}
	}
	return []string{"--range", p.String()}
}

func (a *Agent) handleCrowdsecBan(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p crowdsecParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	target, err := parseBanTarget(p.IP)
	if err != nil {
		return nil, err
	}
	secs, err := parseDuration(p.Duration)
	if err != nil {
		return nil, err
	}
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("cscli"); err != nil {
		return nil, err
	}
	// The reason is a fixed string: never pass operator text to argv.
	args := append([]string{"decisions", "add"}, cscliTarget(target)...)
	args = append(args, "--duration", strconv.Itoa(secs)+"s", "--reason", "serverkit ban")
	out, err := runTool(ctx, "cscli", args...)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "target": target.String(), "duration_seconds": secs, "output": out}, nil
}

func (a *Agent) handleCrowdsecUnban(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p crowdsecParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	target, err := parseBanTarget(p.IP)
	if err != nil {
		return nil, err
	}
	if err := requireLinux(); err != nil {
		return nil, err
	}
	if err := requireTool("cscli"); err != nil {
		return nil, err
	}
	args := append([]string{"decisions", "delete"}, cscliTarget(target)...)
	out, err := runTool(ctx, "cscli", args...)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "target": target.String(), "output": out}, nil
}

// ---- Cloudflare origin lock (ufw) ----

type originLockParams struct {
	Ports   []int `json:"ports"`
	Refresh *bool `json:"refresh"`
}

func originLockPorts(in []int) ([]int, error) {
	if len(in) == 0 {
		return []int{80, 443}, nil
	}
	if len(in) > 8 {
		return nil, fmt.Errorf("too many ports")
	}
	for _, p := range in {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d", p)
		}
		if p == 22 {
			return nil, fmt.Errorf("refusing to lock port 22: SSH access is never touched")
		}
	}
	return in, nil
}

// cloudflareRanges returns the live published ranges when they validate,
// otherwise the embedded fallback.
func cloudflareRanges(ctx context.Context, refresh bool) (ranges []netip.Prefix, source string) {
	if refresh {
		var live []netip.Prefix
		ok := true
		for _, u := range []string{cloudflareV4URL, cloudflareV6URL} {
			body, err := secFetch(ctx, u)
			if err != nil {
				ok = false
				break
			}
			got, err := parseCIDRLines(body)
			if err != nil || len(got) == 0 {
				ok = false
				break
			}
			live = append(live, got...)
		}
		if ok {
			return live, "cloudflare.com"
		}
	}
	for _, s := range append(append([]string{}, cloudflareFallbackV4...), cloudflareFallbackV6...) {
		ranges = append(ranges, netip.MustParsePrefix(s))
	}
	return ranges, "embedded"
}

func parseCIDRLines(body string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || p.Bits() == 0 {
			return nil, fmt.Errorf("bad range %q", line)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func originLockPreflight(ctx context.Context) (statusOut string, err error) {
	if err := requireLinux(); err != nil {
		return "", err
	}
	if err := requireTool("ufw"); err != nil {
		return "", fmt.Errorf("origin lock needs ufw, which is not installed; install and enable ufw (allow SSH first) and retry")
	}
	out, err := runTool(ctx, "ufw", "status")
	if err != nil {
		return "", err
	}
	return out, nil
}

func lockRuleArgs(c netip.Prefix, port int) []string {
	return []string{"allow", "from", c.String(), "to", "any", "port", strconv.Itoa(port), "proto", "tcp", "comment", originLockTag}
}

// ufw app profiles that open 80/443 broadly; removed only when the default
// web ports are being locked.
var webAppProfiles = []string{"Nginx Full", "Nginx HTTP", "Nginx HTTPS", "Apache Full", "Apache", "Apache Secure"}

func (a *Agent) handleOriginLockApply(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p originLockParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	ports, err := originLockPorts(p.Ports)
	if err != nil {
		return nil, err
	}
	status, err := originLockPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if !ufwActive(status) {
		return nil, fmt.Errorf("ufw is installed but inactive; refusing to apply origin lock (enabling ufw could cut off SSH). Enable ufw with SSH allowed first")
	}
	ranges, source := cloudflareRanges(ctx, p.Refresh == nil || *p.Refresh)

	// Allow Cloudflare first; only if every allow succeeds do we close the
	// public rules, so a failure can never leave the ports unreachable.
	for _, c := range ranges {
		for _, port := range ports {
			if _, err := runTool(ctx, "ufw", lockRuleArgs(c, port)...); err != nil {
				return nil, fmt.Errorf("aborted before closing public access: %w", err)
			}
		}
	}
	removed := 0
	for _, port := range ports {
		for _, spec := range []string{fmt.Sprintf("%d/tcp", port), strconv.Itoa(port)} {
			if _, err := runTool(ctx, "ufw", "--force", "delete", "allow", spec); err == nil {
				removed++
			}
		}
	}
	if len(p.Ports) == 0 {
		for _, prof := range webAppProfiles {
			if _, err := runTool(ctx, "ufw", "--force", "delete", "allow", prof); err == nil {
				removed++
			}
		}
	}
	return map[string]interface{}{
		"success": true, "ports": ports, "ranges": len(ranges), "source": source,
		"public_rules_delete_attempts": removed,
	}, nil
}

// taggedLockRules extracts previously applied origin-lock rules from
// `ufw show added`, as argv usable with `ufw delete`.
func taggedLockRules(out string) [][]string {
	var rules [][]string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, originLockTag) {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 3 || f[0] != "ufw" || f[1] != "allow" {
			continue
		}
		var args []string
		for _, t := range f[1:] {
			if t == "comment" {
				break
			}
			args = append(args, strings.Trim(t, "'\""))
		}
		// Only accept rules shaped exactly like the ones we create.
		if len(args) == 9 && args[0] == "allow" && args[1] == "from" && args[3] == "to" && args[4] == "any" &&
			args[5] == "port" && args[7] == "proto" && args[8] == "tcp" {
			if _, err := netip.ParsePrefix(args[2]); err != nil {
				continue
			}
			if n, err := strconv.Atoi(args[6]); err != nil || n < 1 || n > 65535 {
				continue
			}
			rules = append(rules, args)
		}
	}
	return rules
}

func (a *Agent) handleOriginLockRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p originLockParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	ports, err := originLockPorts(p.Ports)
	if err != nil {
		return nil, err
	}
	if _, err := originLockPreflight(ctx); err != nil {
		return nil, err
	}
	// Reopen first so removal never leaves the ports closed.
	for _, port := range ports {
		if _, err := runTool(ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", port)); err != nil {
			return nil, err
		}
	}
	added, err := runTool(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, err
	}
	removed := 0
	for _, args := range taggedLockRules(added) {
		if _, err := runTool(ctx, "ufw", append([]string{"--force", "delete"}, args...)...); err == nil {
			removed++
		}
	}
	return map[string]interface{}{"success": true, "ports": ports, "rules_removed": removed}, nil
}

func (a *Agent) handleOriginLockStatus(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	status, err := originLockPreflight(ctx)
	if err != nil {
		return nil, err
	}
	added, err := runTool(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, err
	}
	rules := taggedLockRules(added)
	ports := map[int]bool{}
	for _, r := range rules {
		n, _ := strconv.Atoi(r[6])
		ports[n] = true
	}
	var locked []int
	for n := range ports {
		locked = append(locked, n)
	}
	return map[string]interface{}{
		"ufw_active": ufwActive(status), "applied": len(rules) > 0,
		"rule_count": len(rules), "locked_ports": locked,
	}, nil
}

package survey

// The FIXED allowlist of read-only primitives (docs/AGENT_SURVEY_SPEC.md,
// Decision 2). Everything the catalog interpreter is allowed to do reduces
// to one of these. None of them run a shell, none return whole-file
// contents, and none read private keys.
//
//   fileExists   — does a path exist (and is it a dir)?
//   globPaths    — expand a glob to a bounded list of paths.
//   parseLight   — read a text file, return ONLY whitelisted directive
//                  lines (never comments, never secrets, never whole file).
//   parseVhosts  — parse-light specialization: web-server vhosts.
//   certMeta     — subject/SAN domains + notAfter from a PEM cert.
//   UnitActive / Listeners / ProcessNames — host state (LiveProbes).

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	gopsutilnet "github.com/shirou/gopsutil/v3/net"
	gopsutilprocess "github.com/shirou/gopsutil/v3/process"
)

// fileExists reports whether path exists and whether it is a directory.
func fileExists(path string) (exists, isDir bool) {
	info, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	return true, info.IsDir()
}

// binOnPath reports whether a binary is reachable via $PATH.
func binOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// globPaths expands a shell glob to a sorted, bounded list of paths.
func globPaths(pattern string, limit int) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

// parseLight reads a text file and returns only the lines whose first
// token matches one of `directives` (case-insensitive). Comments and
// blank lines are dropped; the whole file never leaves the box. Reads are
// byte-capped so a pathological file can't blow the response budget.
func parseLight(path string, directives []string) []string {
	f, err := os.Open(path) // #nosec G304 — path comes from a catalog glob, read-only
	if err != nil {
		return nil
	}
	defer f.Close()

	lower := make(map[string]bool, len(directives))
	for _, d := range directives {
		lower[strings.ToLower(d)] = true
	}

	var out []string
	r := bufio.NewReader(io.LimitReader(f, maxParseFileBytes))
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if lower[strings.ToLower(fields[0])] {
			out = append(out, line)
		}
	}
	return out
}

// parseVhosts is a parse-light specialization for web-server configs. It
// scans for the ordered directive triple [name, root, upstream]
// (server_name/root/proxy_pass for nginx, ServerName/DocumentRoot/ProxyPass
// for apache) and groups them into vhosts. Line-based, block-agnostic: a
// new name directive starts a new vhost. Never returns comments or any
// non-directive line.
func parseVhosts(path string, directives []string) []Vhost {
	if len(directives) != 3 {
		return nil
	}
	nameDir := strings.ToLower(directives[0])
	rootDir := strings.ToLower(directives[1])
	upstreamDir := strings.ToLower(directives[2])

	lines := parseLight(path, directives)
	var vhosts []Vhost
	var cur *Vhost
	flush := func() {
		if cur != nil && (cur.ServerName != "" || cur.Root != "" || cur.Upstream != "") {
			vhosts = append(vhosts, *cur)
		}
		cur = nil
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := directiveValue(line)
		switch key {
		case nameDir:
			flush()
			cur = &Vhost{ServerName: firstToken(val)}
		case rootDir:
			if cur == nil {
				cur = &Vhost{}
			}
			cur.Root = truncateStr(val)
		case upstreamDir:
			if cur == nil {
				cur = &Vhost{}
			}
			cur.Upstream = truncateStr(firstToken(val))
		}
	}
	flush()
	return vhosts
}

// directiveValue returns everything after the first token, stripped of a
// trailing ';' and surrounding quotes.
func directiveValue(line string) string {
	parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
	if len(parts) < 2 {
		// handle tab-separated
		parts = strings.SplitN(strings.TrimSpace(line), "\t", 2)
		if len(parts) < 2 {
			return ""
		}
	}
	v := strings.TrimSpace(parts[1])
	v = strings.TrimRight(v, ";")
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	return v
}

func firstToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func truncateStr(s string) string {
	r := []rune(s)
	if len(r) > maxStringFieldRunes {
		return string(r[:maxStringFieldRunes])
	}
	return s
}

// certMeta extracts {domain, expires_at} from a PEM certificate. If path
// is a directory (e.g. /etc/letsencrypt/live/<domain>), it looks for
// cert.pem then fullchain.pem inside. Private keys are NEVER read — only
// files explicitly named cert.pem / fullchain.pem / a *.pem that is not a
// key. Returns (cert, true) on success.
func certMeta(path string) (Cert, bool) {
	certPath := path
	if _, isDir := fileExists(path); isDir {
		found := ""
		for _, name := range []string{"cert.pem", "fullchain.pem"} {
			cand := filepath.Join(path, name)
			if ok, _ := fileExists(cand); ok {
				found = cand
				break
			}
		}
		if found == "" {
			return Cert{}, false
		}
		certPath = found
	}
	// Never parse key material even if a catalog glob points at one.
	base := strings.ToLower(filepath.Base(certPath))
	if strings.Contains(base, "privkey") || strings.HasSuffix(base, ".key") {
		return Cert{}, false
	}

	data, err := os.ReadFile(certPath) // #nosec G304 — read-only cert path from catalog
	if err != nil {
		return Cert{}, false
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return Cert{}, false
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Cert{}, false
	}
	domain := crt.Subject.CommonName
	if domain == "" && len(crt.DNSNames) > 0 {
		domain = crt.DNSNames[0]
	}
	if domain == "" {
		domain = filepath.Base(filepath.Dir(certPath))
	}
	return Cert{
		Domain:    truncateStr(domain),
		ExpiresAt: crt.NotAfter.UTC().Format(time.RFC3339),
	}, true
}

// currentUsername returns the agent process's username (best-effort).
func currentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// agentCrontabLines returns the schedule lines from the AGENT USER's
// crontab (parse-light: only lines that look like a cron schedule; env
// assignments and comments are dropped). v1 does not read other users'
// tables — that needs root. Off-Linux / no crontab ⇒ nil.
func agentCrontabLines(ctx context.Context, limit int) []string {
	if _, err := exec.LookPath("crontab"); err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "crontab", "-l").Output()
	if err != nil {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !looksLikeCronSchedule(line) {
			continue // skip env assignments etc.
		}
		lines = append(lines, truncateStr(line))
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

// looksLikeCronSchedule is a cheap heuristic: a standard 5-field schedule
// followed by a command. Special @-directives (@reboot, @daily) also pass.
func looksLikeCronSchedule(line string) bool {
	if strings.HasPrefix(line, "@") {
		return len(strings.Fields(line)) >= 2
	}
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return false
	}
	for _, f := range fields[:5] {
		for _, r := range f {
			if !(r >= '0' && r <= '9') && r != '*' && r != ',' && r != '-' && r != '/' {
				return false
			}
		}
	}
	return true
}

// ─────────────────────── LiveProbes (host state) ───────────────────────

// DockerLister returns running containers; supplied by the agent (which
// owns the docker client). nil ⇒ docker unavailable.
type DockerLister func(ctx context.Context) []Container

// LiveProbes is the production HostProbes implementation.
type LiveProbes struct {
	docker DockerLister
}

// NewLiveProbes builds a LiveProbes. docker may be nil on hosts without a
// docker client.
func NewLiveProbes(docker DockerLister) *LiveProbes {
	return &LiveProbes{docker: docker}
}

// UnitActive runs the unprivileged `systemctl is-active <unit>` and
// returns (active, ActiveState-word). Off-Linux / no systemctl ⇒
// (false, "").
func (l *LiveProbes) UnitActive(ctx context.Context, unit string) (bool, string) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, ""
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	if i := strings.IndexAny(state, "\r\n"); i >= 0 {
		state = state[:i]
	}
	return state == "active" || state == "activating", state
}

// Listeners returns listening TCP/UDP sockets → {port, proto, process}.
// The process NAME only, never its command line (Decision 2). Deduped by
// (port, proto).
func (l *LiveProbes) Listeners(ctx context.Context) []Listener {
	conns, err := gopsutilnet.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil
	}
	nameCache := map[int32]string{}
	seen := map[string]bool{}
	var out []Listener
	for _, c := range conns {
		// TCP listeners have Status LISTEN; UDP sockets have no TCP state,
		// so include SOCK_DGRAM (Type 2) sockets with a bound local port.
		proto := ""
		switch c.Type {
		case 1: // SOCK_STREAM
			if c.Status != "LISTEN" {
				continue
			}
			proto = "tcp"
		case 2: // SOCK_DGRAM
			proto = "udp"
		default:
			continue
		}
		if c.Laddr.Port == 0 {
			continue
		}
		port := int(c.Laddr.Port)
		key := proto + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true

		name := ""
		if c.Pid > 0 {
			if n, ok := nameCache[c.Pid]; ok {
				name = n
			} else if p, err := gopsutilprocess.NewProcessWithContext(ctx, c.Pid); err == nil {
				name, _ = p.NameWithContext(ctx)
				nameCache[c.Pid] = name
			}
		}
		out = append(out, Listener{Port: port, Proto: proto, Process: name})
		if len(out) >= maxListeners {
			break
		}
	}
	return out
}

// ProcessNames returns deduped running process names (names only).
func (l *LiveProbes) ProcessNames(ctx context.Context) []string {
	procs, err := gopsutilprocess.ProcessesWithContext(ctx)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range procs {
		name, err := p.NameWithContext(ctx)
		if err != nil || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
		if len(out) >= maxProcessNames {
			break
		}
	}
	sort.Strings(out)
	return out
}

// DockerContainers delegates to the injected lister (nil ⇒ no docker).
func (l *LiveProbes) DockerContainers(ctx context.Context) []Container {
	if l.docker == nil {
		return nil
	}
	containers := l.docker(ctx)
	if len(containers) > maxContainers {
		containers = containers[:maxContainers]
	}
	return containers
}

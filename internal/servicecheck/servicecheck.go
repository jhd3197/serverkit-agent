// Package servicecheck detects the web server, PHP-FPM and database services
// on a host and reports whether they are healthy. It never uses a shell and
// needs no credentials: systemd state comes from fixed `systemctl` argv and
// databases are probed with a plain local TCP connect.
package servicecheck

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// ExecFunc runs a fixed command and returns stdout. Injected for tests.
type ExecFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// DialFunc opens a TCP connection. Injected for tests.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Resources are the already-collected host usage percentages.
type Resources struct {
	CPU, Memory, Disk float64
}

// Checker runs the checks. The zero value is not usable; call New.
type Checker struct {
	Exec   ExecFunc
	Dial   DialFunc
	Custom []config.MonitorCheck
	OS     string
	Now    func() time.Time
}

// New returns a Checker wired to the real exec/dial.
func New(custom []config.MonitorCheck) *Checker {
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &Checker{
		Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		},
		Dial:   d.DialContext,
		Custom: custom,
		OS:     runtime.GOOS,
		Now:    time.Now,
	}
}

const (
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
	StatusUnknown  = "unknown"
)

var (
	webUnits = []string{"nginx", "apache2", "httpd", "caddy"}
	dbUnits  = []struct {
		unit string
		port string
	}{{"mysql", "3306"}, {"mysqld", "3306"}, {"mariadb", "3306"}, {"postgresql", "5432"}}
)

// Run returns the checks for services that are installed/detected plus the
// resource threshold checks.
func (c *Checker) Run(ctx context.Context, res Resources) []protocol.ServiceCheck {
	var out []protocol.ServiceCheck
	if c.OS == "linux" {
		out = append(out, c.web(ctx)...)
		out = append(out, c.phpFPM(ctx)...)
		out = append(out, c.databases(ctx)...)
	}
	out = append(out, c.threshold("disk", "disk", res.Disk), c.threshold("cpu", "cpu", res.CPU), c.threshold("memory", "memory", res.Memory))
	out = append(out, c.custom(ctx)...)
	return out
}

func (c *Checker) mk(name, kind, status, detail string) protocol.ServiceCheck {
	return protocol.ServiceCheck{Name: name, Kind: kind, Status: status, Detail: detail,
		CheckedAt: c.Now().UTC().Format(time.RFC3339)}
}

func (c *Checker) threshold(name, kind string, pct float64) protocol.ServiceCheck {
	detail := fmt.Sprintf("%.1f%% used", pct)
	switch {
	case pct >= 98:
		return c.mk(name, kind, StatusDown, detail)
	case pct >= 90:
		return c.mk(name, kind, StatusDegraded, detail)
	}
	return c.mk(name, kind, StatusUp, detail)
}

type unitInfo struct{ id, load, active string }

// unitState asks systemd about one unit. found is false if the unit does not
// exist on this host.
func (c *Checker) unitState(ctx context.Context, unit string) (u unitInfo, found bool) {
	out, err := c.Exec(ctx, "systemctl", "show", unit+".service", "-p", "Id", "-p", "LoadState", "-p", "ActiveState")
	if err != nil && len(out) == 0 {
		return u, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			u.id = v
		case "LoadState":
			u.load = v
		case "ActiveState":
			u.active = v
		}
	}
	return u, u.load == "loaded"
}

func (c *Checker) listening(ctx context.Context, port string) bool {
	conn, err := c.Dial(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (c *Checker) web(ctx context.Context) []protocol.ServiceCheck {
	var out []protocol.ServiceCheck
	listening := c.listening(ctx, "80") || c.listening(ctx, "443")
	seen := map[string]bool{}
	for _, unit := range webUnits {
		u, ok := c.unitState(ctx, unit)
		if !ok || seen[u.id] {
			continue
		}
		seen[u.id] = true
		switch {
		case u.active == "active":
			out = append(out, c.mk(unit, "web", StatusUp, "systemd unit active"))
		case listening:
			out = append(out, c.mk(unit, "web", StatusUp, "unit "+u.active+" but listening on 80/443"))
		default:
			out = append(out, c.mk(unit, "web", StatusDown, "systemd unit "+u.active))
		}
	}
	if len(out) == 0 && listening {
		out = append(out, c.mk("web", "web", StatusUp, "listening on 80/443"))
	}
	return out
}

func (c *Checker) phpFPM(ctx context.Context) []protocol.ServiceCheck {
	raw, err := c.Exec(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "php*-fpm.service")
	if err != nil && len(raw) == 0 {
		return nil
	}
	return c.parsePHP(string(raw))
}

// parsePHP parses `systemctl list-units --no-legend --plain` rows:
// UNIT LOAD ACTIVE SUB DESCRIPTION.
func (c *Checker) parsePHP(raw string) []protocol.ServiceCheck {
	var out []protocol.ServiceCheck
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.HasPrefix(f[0], "php") || !strings.HasSuffix(f[0], "-fpm.service") || f[1] != "loaded" {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		if f[2] == "active" {
			out = append(out, c.mk(name, "php_fpm", StatusUp, "systemd unit active"))
		} else {
			out = append(out, c.mk(name, "php_fpm", StatusDown, "systemd unit "+f[2]))
		}
	}
	return out
}

func (c *Checker) databases(ctx context.Context) []protocol.ServiceCheck {
	var out []protocol.ServiceCheck
	seen := map[string]bool{}
	for _, db := range dbUnits {
		u, ok := c.unitState(ctx, db.unit)
		if !ok || seen[u.id] {
			continue
		}
		seen[u.id] = true
		switch {
		case u.active != "active":
			out = append(out, c.mk(db.unit, "database", StatusDown, "systemd unit "+u.active))
		case c.listening(ctx, db.port):
			out = append(out, c.mk(db.unit, "database", StatusUp, "unit active, accepting connections on "+db.port))
		default:
			out = append(out, c.mk(db.unit, "database", StatusDegraded, "unit active but port "+db.port+" refused connections"))
		}
	}
	return out
}

func (c *Checker) custom(ctx context.Context) []protocol.ServiceCheck {
	var out []protocol.ServiceCheck
	for _, ck := range c.Custom {
		name := ck.Name
		if name == "" {
			name = ck.Target
		}
		switch strings.ToLower(ck.Type) {
		case "tcp":
			host, port, err := net.SplitHostPort(ck.Target)
			if err != nil {
				out = append(out, c.mk(name, "custom", StatusUnknown, "invalid tcp target "+ck.Target))
				continue
			}
			conn, err := c.Dial(ctx, "tcp", net.JoinHostPort(host, port))
			if err != nil {
				out = append(out, c.mk(name, "custom", StatusDown, "connect failed"))
				continue
			}
			conn.Close()
			out = append(out, c.mk(name, "custom", StatusUp, "tcp connect ok"))
		case "systemd":
			if c.OS != "linux" || !validUnit(ck.Target) {
				out = append(out, c.mk(name, "custom", StatusUnknown, "unsupported systemd target"))
				continue
			}
			u, ok := c.unitState(ctx, strings.TrimSuffix(ck.Target, ".service"))
			switch {
			case !ok:
				out = append(out, c.mk(name, "custom", StatusUnknown, "unit not found"))
			case u.active == "active":
				out = append(out, c.mk(name, "custom", StatusUp, "systemd unit active"))
			default:
				out = append(out, c.mk(name, "custom", StatusDown, "systemd unit "+u.active))
			}
		default:
			out = append(out, c.mk(name, "custom", StatusUnknown, "unknown check type "+ck.Type))
		}
	}
	return out
}

// validUnit keeps operator-supplied unit names from being parsed as flags.
func validUnit(s string) bool {
	if s == "" || len(s) > 100 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@-:", r)) {
			return false
		}
	}
	return true
}

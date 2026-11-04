package servicecheck

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

type fakeHost struct {
	units map[string]string // unit -> "Id|LoadState|ActiveState"
	php   string
	ports map[string]bool
	calls [][]string
}

func (h *fakeHost) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	h.calls = append(h.calls, append([]string{name}, args...))
	if name != "systemctl" {
		return nil, errors.New("unexpected command " + name)
	}
	switch args[0] {
	case "list-units":
		return []byte(h.php), nil
	case "show":
		unit := strings.TrimSuffix(args[1], ".service")
		v, ok := h.units[unit]
		if !ok {
			return []byte("Id=" + args[1] + "\nLoadState=not-found\nActiveState=inactive\n"), nil
		}
		p := strings.Split(v, "|")
		return []byte("Id=" + p[0] + "\nLoadState=" + p[1] + "\nActiveState=" + p[2] + "\n"), nil
	}
	return nil, errors.New("unexpected systemctl " + args[0])
}

func (h *fakeHost) dial(_ context.Context, _, addr string) (net.Conn, error) {
	_, port, _ := net.SplitHostPort(addr)
	if h.ports[port] {
		c, _ := net.Pipe()
		return c, nil
	}
	return nil, errors.New("refused")
}

func (h *fakeHost) checker(custom ...config.MonitorCheck) *Checker {
	return &Checker{Exec: h.exec, Dial: h.dial, Custom: custom, OS: "linux",
		Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }}
}

func run(t *testing.T, c *Checker, res Resources) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, sc := range c.Run(context.Background(), res) {
		if sc.CheckedAt != "2026-01-02T03:04:05Z" {
			t.Errorf("checked_at = %q", sc.CheckedAt)
		}
		out[sc.Kind+":"+sc.Name] = sc.Status
	}
	return out
}

func TestDetectsOnlyInstalledServices(t *testing.T) {
	h := &fakeHost{
		units: map[string]string{
			"nginx":      "nginx.service|loaded|active",
			"mariadb":    "mariadb.service|loaded|active",
			"mysql":      "mariadb.service|loaded|active", // alias: must dedupe
			"postgresql": "postgresql.service|loaded|inactive",
		},
		php:   "php8.2-fpm.service loaded active running PHP 8.2 FastCGI\nphp7.4-fpm.service loaded failed failed PHP 7.4\n",
		ports: map[string]bool{"3306": true},
	}
	got := run(t, h.checker(), Resources{})
	want := map[string]string{
		"web:nginx":           "up",
		"php_fpm:php8.2-fpm":  "up",
		"php_fpm:php7.4-fpm":  "down",
		"database:mysql":      "up",
		"database:postgresql": "down",
		"disk:disk":           "up",
		"cpu:cpu":             "up",
		"memory:memory":       "up",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	for k := range got {
		if strings.Contains(k, "apache") || strings.Contains(k, "caddy") || strings.Contains(k, "httpd") {
			t.Errorf("reported uninstalled service %s", k)
		}
	}
	if _, dup := got["database:mariadb"]; dup {
		t.Error("alias not deduped")
	}
}

func TestDatabaseActiveButPortClosedIsDegraded(t *testing.T) {
	h := &fakeHost{units: map[string]string{"postgresql": "postgresql.service|loaded|active"}, ports: map[string]bool{}}
	if got := run(t, h.checker(), Resources{})["database:postgresql"]; got != "degraded" {
		t.Fatalf("got %q", got)
	}
}

func TestWebFallsBackToListening(t *testing.T) {
	h := &fakeHost{units: map[string]string{}, ports: map[string]bool{"443": true}}
	if got := run(t, h.checker(), Resources{})["web:web"]; got != "up" {
		t.Fatalf("got %q", got)
	}
	h = &fakeHost{units: map[string]string{}, ports: map[string]bool{}}
	for k := range run(t, h.checker(), Resources{}) {
		if strings.HasPrefix(k, "web:") {
			t.Fatalf("nothing detected but reported %s", k)
		}
	}
}

func TestStoppedWebserverDown(t *testing.T) {
	h := &fakeHost{units: map[string]string{"apache2": "apache2.service|loaded|inactive"}, ports: map[string]bool{}}
	if got := run(t, h.checker(), Resources{})["web:apache2"]; got != "down" {
		t.Fatalf("got %q", got)
	}
}

func TestThresholds(t *testing.T) {
	h := &fakeHost{units: map[string]string{}, ports: map[string]bool{}}
	got := run(t, h.checker(), Resources{Disk: 91, CPU: 99, Memory: 10})
	if got["disk:disk"] != "degraded" || got["cpu:cpu"] != "down" || got["memory:memory"] != "up" {
		t.Fatalf("thresholds wrong: %v", got)
	}
}

func TestCustomChecks(t *testing.T) {
	h := &fakeHost{
		units: map[string]string{"redis": "redis.service|loaded|active"},
		ports: map[string]bool{"6379": true},
	}
	c := h.checker(
		config.MonitorCheck{Name: "redis-port", Type: "tcp", Target: "127.0.0.1:6379"},
		config.MonitorCheck{Name: "dead-port", Type: "tcp", Target: "127.0.0.1:1"},
		config.MonitorCheck{Name: "redis-unit", Type: "systemd", Target: "redis"},
		config.MonitorCheck{Name: "evil", Type: "systemd", Target: "--help"},
		config.MonitorCheck{Name: "bad", Type: "tcp", Target: "nonsense"},
	)
	got := run(t, c, Resources{})
	for k, v := range map[string]string{
		"custom:redis-port": "up", "custom:dead-port": "down", "custom:redis-unit": "up",
		"custom:evil": "unknown", "custom:bad": "unknown",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestNonLinuxSkipsSystemd(t *testing.T) {
	h := &fakeHost{}
	c := h.checker()
	c.OS = "windows"
	run(t, c, Resources{})
	if len(h.calls) != 0 {
		t.Fatalf("exec called on non-linux: %v", h.calls)
	}
}

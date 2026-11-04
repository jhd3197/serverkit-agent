package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/events"
	"github.com/jhd3197/serverkit-agent/internal/gui"
	"github.com/jhd3197/serverkit-agent/internal/jobs"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/permissions"
	"github.com/jhd3197/serverkit-agent/internal/servicecheck"
	"github.com/jhd3197/serverkit-agent/internal/transport"
	"github.com/jhd3197/serverkit-agent/internal/transport/report"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

type fakeTransport struct {
	mu      sync.Mutex
	runs    int32
	results []result
	errs    []string
}

type result struct {
	id, errMsg string
	ok         bool
}

func (f *fakeTransport) SetHandler(transport.MessageHandler) {}
func (f *fakeTransport) Run(context.Context) error           { atomic.AddInt32(&f.runs, 1); return nil }
func (f *fakeTransport) IsConnected() bool                   { return false }
func (f *fakeTransport) Send(interface{}) error              { return nil }
func (f *fakeTransport) SendHeartbeat(protocol.HeartbeatMetrics) error {
	return nil
}
func (f *fakeTransport) SendCommandResult(id string, ok bool, _ interface{}, e string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, result{id, e, ok})
	return nil
}
func (f *fakeTransport) SendStream(string, interface{}) error { return nil }
func (f *fakeTransport) SendError(code, d string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, code+": "+d)
	return nil
}
func (f *fakeTransport) Session() *auth.SessionToken { return nil }
func (f *fakeTransport) Close() error                { return nil }
func (f *fakeTransport) Mode() transport.Mode        { return transport.ModeWS }

func newLevelAgent(t *testing.T, level permissions.Level) (*Agent, *fakeTransport) {
	t.Helper()
	log := logger.New(config.LoggingConfig{Level: "error"})
	ft := &fakeTransport{}
	a := &Agent{
		cfg: &config.Config{}, log: log, ws: ft, level: level,
		gui: gui.New(log), jobs: jobs.NewRegistry(4), events: events.NewStore(50, ""),
		subscriptions: map[string]context.CancelFunc{}, handlers: map[string]CommandHandler{},
		checker: servicecheck.New(nil), restartCh: make(chan struct{}, 1),
	}
	a.registerHandlers()
	return a, ft
}

func cmdJSON(id, action string) []byte {
	b, _ := json.Marshal(protocol.CommandMessage{
		Message: protocol.Message{Type: protocol.TypeCommand, ID: id}, Action: action, Params: json.RawMessage(`{}`),
	})
	return b
}

func TestRegisterHandlersPrunedByLevel(t *testing.T) {
	a, _ := newLevelAgent(t, permissions.Monitor)
	if len(a.handlers) != 0 {
		t.Errorf("monitor must register no handlers, got %d", len(a.handlers))
	}
	a, _ = newLevelAgent(t, permissions.Protect)
	if len(a.handlers) != len(permissions.ProtectActions()) {
		t.Errorf("protect registered %d handlers, want %d", len(a.handlers), len(permissions.ProtectActions()))
	}
	for act := range a.handlers {
		if !permissions.Allowed(permissions.Protect, act) {
			t.Errorf("protect agent registered %s", act)
		}
	}
	a, _ = newLevelAgent(t, permissions.Full)
	if _, ok := a.handlers[protocol.ActionSystemdStatus]; !ok {
		t.Error("full must register systemd:status")
	}
}

func TestHandleCommandRejectionPerLevel(t *testing.T) {
	cases := []struct {
		level  permissions.Level
		action string
		reject bool
	}{
		{permissions.Monitor, protocol.ActionFirewallStatus, true},
		{permissions.Monitor, protocol.ActionSystemExec, true},
		{permissions.Protect, protocol.ActionSystemExec, true},
		{permissions.Protect, protocol.ActionDockerContainerList, true},
		{permissions.Protect, protocol.ActionTerminalCreate, true},
		{permissions.Protect, protocol.ActionFileWrite, true},
		{permissions.Protect, protocol.ActionAgentUpdate, true},
		{permissions.Protect, "never:heard:of:it", true},
		{permissions.Protect, protocol.ActionFirewallStatus, false},
		{permissions.Full, protocol.ActionSystemdStatus, false},
	}
	for _, c := range cases {
		t.Run(string(c.level)+"/"+c.action, func(t *testing.T) {
			a, ft := newLevelAgent(t, c.level)
			// Even if a handler were present above the level, the central
			// gate must stop it before it runs.
			var ran atomic.Bool
			if c.reject && c.action != "never:heard:of:it" {
				a.handlers[c.action] = func(context.Context, json.RawMessage) (interface{}, error) {
					ran.Store(true)
					return nil, nil
				}
			}
			a.handleCommand(cmdJSON("c1", c.action))
			if len(ft.results) != 1 {
				t.Fatalf("want 1 result, got %d", len(ft.results))
			}
			r := ft.results[0]
			if c.reject {
				if r.ok || ran.Load() {
					t.Fatalf("command was not rejected (ok=%v ran=%v)", r.ok, ran.Load())
				}
				want := "action " + c.action + " requires permission level"
				if !strings.Contains(r.errMsg, want) || !strings.Contains(r.errMsg, "configured as "+string(c.level)) {
					t.Errorf("error %q lacks %q", r.errMsg, want)
				}
				if len(a.events.Snapshot(0)) == 0 {
					t.Error("rejection not recorded in events store")
				}
			} else if strings.Contains(r.errMsg, "requires permission level") {
				t.Errorf("allowed action rejected: %s", r.errMsg)
			}
		})
	}
}

func TestSubscribeGatedByLevel(t *testing.T) {
	sub := func(ch string) []byte {
		b, _ := json.Marshal(protocol.SubscribeMessage{Message: protocol.Message{Type: protocol.TypeSubscribe}, Channel: ch})
		return b
	}
	a, ft := newLevelAgent(t, permissions.Protect)
	a.handleSubscribe(sub("terminal:abc"))
	if len(ft.errs) != 1 || len(a.subscriptions) != 0 {
		t.Fatalf("terminal subscribe must be rejected at protect: errs=%v subs=%d", ft.errs, len(a.subscriptions))
	}
	a, ft = newLevelAgent(t, permissions.Monitor)
	a.handleSubscribe(sub("metrics"))
	if len(ft.errs) != 1 || len(a.subscriptions) != 0 {
		t.Fatal("monitor must reject every subscription")
	}
}

func TestMonitorModeStartsNoCommandTransport(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/report" {
			hits.Add(1)
		}
		w.Write([]byte(`{"ok":true,"interval_seconds":3600}`))
	}))
	defer srv.Close()

	a, ft := newLevelAgent(t, permissions.Monitor)
	a.cfg.Server.PingInterval = time.Second
	a.cfg.Server.URL = srv.URL
	au := auth.New("agent-1", "key", "secret")
	a.reporter = report.New(srv.URL, "test", "monitor", au, time.Minute, a.collectReport, a.log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if atomic.LoadInt32(&ft.runs) != 0 {
		t.Fatal("monitor mode started the ws/poll command transport")
	}
	if hits.Load() == 0 {
		t.Fatal("monitor mode never posted a report")
	}
}

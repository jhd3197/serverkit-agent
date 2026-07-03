package agent

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/auth"
	"github.com/jhd3197/serverkit-agent/internal/capabilities"
	"github.com/jhd3197/serverkit-agent/internal/cloudflared"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/cron"
	"github.com/jhd3197/serverkit-agent/internal/docker"
	"github.com/jhd3197/serverkit-agent/internal/events"
	"github.com/jhd3197/serverkit-agent/internal/gui"
	"github.com/jhd3197/serverkit-agent/internal/ipc"
	"github.com/jhd3197/serverkit-agent/internal/jobs"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/metrics"
	"github.com/jhd3197/serverkit-agent/internal/terminal"
	"github.com/jhd3197/serverkit-agent/internal/transport"
	"github.com/jhd3197/serverkit-agent/internal/transport/poll"
	"github.com/jhd3197/serverkit-agent/internal/updater"
	"github.com/jhd3197/serverkit-agent/internal/wireguard"
	"github.com/jhd3197/serverkit-agent/internal/ws"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// Agent is the main agent that coordinates all components
type Agent struct {
	cfg  *config.Config
	log  *logger.Logger
	auth *auth.Authenticator
	// ws is the active transport — either the WS client directly or the
	// fallback Manager that wraps WS+poll. Named "ws" for compatibility
	// with the dozens of existing call sites in this file.
	ws          transport.Transport
	docker      *docker.Client
	metrics     *metrics.Collector
	terminal    *terminal.Manager
	cron        cron.Manager
	cloudflared cloudflared.Manager
	wireguard   wireguard.Manager
	ipc         *ipc.Server
	sampler     *metricSampler
	events      *events.Store
	gui         *gui.SDK
	jobs        *jobs.Registry

	// pkgLock serializes package-manager mutations (install / remove /
	// upgrade / update_cache) inside a single agent so two concurrent
	// requests don't race on dpkg/rpm locks. Reads (list_installed,
	// search, info) don't take the lock.
	pkgLock sync.Mutex

	// Active subscriptions
	subscriptions map[string]context.CancelFunc
	subMu         sync.Mutex

	// Command handlers
	handlers map[string]CommandHandler

	// Capabilities probed at startup, refreshable via
	// agent:recapabilities. Sent to the panel each time the transport
	// reconnects (so a panel restart picks them up without waiting for
	// the agent to also restart). capMu guards reads/writes during a
	// re-probe so we don't ship a half-mutated payload.
	capabilities protocol.CapabilitiesMessage
	capMu        sync.Mutex
	reprobing    bool

	// sudoMode is the agent's privilege-escalation mode (root /
	// passwordless / unavailable). Probed once at startup; if the user
	// adds sudoers config later, agent:recapabilities re-probes.
	sudoMode SudoMode

	// systemdJSON tracks whether `systemctl --output=json` is supported
	// on this host (systemd >= 244). Probed lazily on first use.
	systemdJSON     bool
	systemdJSONOnce sync.Once

	// Lifecycle tracking
	startTime      time.Time
	restartCh      chan struct{}
	lastConnected  time.Time
	reconnectCount int
}

// CommandHandler is a function that handles a command
type CommandHandler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// New creates a new Agent
func New(cfg *config.Config, log *logger.Logger) (*Agent, error) {
	// Create authenticator
	authenticator := auth.New(cfg.Agent.ID, cfg.Auth.APIKey, cfg.Auth.APISecret)

	// Build the transport: a Manager wrapping the WS client (primary) and
	// a polling client (fallback for tunnels that mangle WS frames). The
	// Manager presents the same Transport surface as the bare WS client
	// did, so the rest of the agent doesn't care which is active.
	wsClient := ws.NewClient(cfg.Server, authenticator, log)
	pollClient := poll.NewClient(cfg.Server, authenticator, log)
	transportClient := transport.NewManager(wsClient, pollClient, log)

	// Create Docker client if enabled
	var dockerClient *docker.Client
	if cfg.Features.Docker {
		var err error
		dockerClient, err = docker.NewClient(cfg.Docker, log)
		if err != nil {
			log.Warn("Failed to create Docker client", "error", err)
			// Don't fail - Docker may not be available
		}
	}

	// Create metrics collector if enabled
	var metricsCollector *metrics.Collector
	if cfg.Features.Metrics {
		metricsCollector = metrics.NewCollector(cfg.Metrics, log)
	}

	// Create terminal manager if exec is enabled
	var termManager *terminal.Manager
	if cfg.Features.Exec {
		termManager = terminal.NewManager()
		log.Info("Terminal/PTY support enabled")
	}

	// Persist the event store next to the existing config so it survives
	// service restarts. Falls back to in-memory only if we can't infer a
	// data directory (shouldn't happen on a normal install).
	dataDir := ""
	if cfg.Logging.File != "" {
		dataDir = filepath.Dir(cfg.Logging.File)
	}
	eventStore := events.NewStore(200, events.DefaultPath(dataDir))

	// WireGuard private keys live in a root-only subdir of the agent's
	// data dir; empty dataDir falls back to a system default inside the
	// wireguard package.
	wgKeyDir := ""
	if dataDir != "" {
		wgKeyDir = filepath.Join(dataDir, "wireguard")
	}

	agent := &Agent{
		cfg:           cfg,
		log:           log,
		auth:          authenticator,
		ws:            transportClient,
		docker:        dockerClient,
		metrics:       metricsCollector,
		terminal:      termManager,
		cron:          cron.New(),
		cloudflared:   cloudflared.New(),
		wireguard:     wireguard.New(wgKeyDir),
		sampler:       newMetricSampler(300), // 5 min @ 1 Hz
		events:        eventStore,
		gui:           gui.New(log),
		jobs:          jobs.NewRegistry(64),
		subscriptions: make(map[string]context.CancelFunc),
		handlers:      make(map[string]CommandHandler),
		startTime:     time.Now(),
		// Buffered so an IPC restart fired before the agent's main
		// select{} reaches the receive doesn't hang the IPC handler.
		// At most one restart can be in-flight at a time anyway —
		// Restart() uses a non-blocking send and returns "already in
		// progress" if the slot is full.
		restartCh: make(chan struct{}, 1),
	}

	// Probe capabilities up-front so connectionWatcher can ship them on
	// every reconnect without re-probing. Docker availability is taken
	// from whether NewClient succeeded above; the capability layer
	// doesn't redo that work.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	agent.capabilities = capabilities.Probe(
		probeCtx,
		log,
		dockerClient != nil,
		cfg.Features.FileAccess,
		cfg.Security.AllowedPaths,
	)
	agent.sudoMode = probeSudoMode(probeCtx)
	agent.capabilities.Sudo = string(agent.sudoMode)
	agent.capabilities.RuntimeManagers = map[string]string{
		"python": pyenvManagerKind(),
	}
	agent.capabilities.ProbedAt = time.Now().UnixMilli()
	probeCancel()
	log.Info("Sudo probe complete", "mode", agent.sudoMode)

	// Register command handlers
	agent.registerHandlers()

	// Install the message handler on the transport (manager fans this
	// out to both backends so a fallback switch doesn't drop the
	// binding).
	transportClient.SetHandler(agent.handleMessage)

	// Create IPC server if enabled
	if cfg.IPC.Enabled {
		agent.ipc = ipc.NewServer(cfg.IPC, log, agent)
	}

	return agent, nil
}

// registerHandlers registers all command handlers
func (a *Agent) registerHandlers() {
	// Docker container commands
	if a.docker != nil {
		a.handlers[protocol.ActionDockerContainerList] = a.handleDockerContainerList
		a.handlers[protocol.ActionDockerContainerInspect] = a.handleDockerContainerInspect
		a.handlers[protocol.ActionDockerContainerCreate] = a.handleDockerContainerCreate
		a.handlers[protocol.ActionDockerContainerStart] = a.handleDockerContainerStart
		a.handlers[protocol.ActionDockerContainerStop] = a.handleDockerContainerStop
		a.handlers[protocol.ActionDockerContainerRestart] = a.handleDockerContainerRestart
		a.handlers[protocol.ActionDockerContainerRemove] = a.handleDockerContainerRemove
		a.handlers[protocol.ActionDockerContainerStats] = a.handleDockerContainerStats
		a.handlers[protocol.ActionDockerContainerLogs] = a.handleDockerContainerLogs
		a.handlers[protocol.ActionDockerContainerExec] = a.handleDockerContainerExec

		// Docker image commands
		a.handlers[protocol.ActionDockerImageList] = a.handleDockerImageList
		a.handlers[protocol.ActionDockerImagePull] = a.handleDockerImagePull
		a.handlers[protocol.ActionDockerImageRemove] = a.handleDockerImageRemove
		a.handlers[protocol.ActionDockerImageBuild] = a.handleDockerImageBuild

		// Docker volume commands
		a.handlers[protocol.ActionDockerVolumeList] = a.handleDockerVolumeList
		a.handlers[protocol.ActionDockerVolumeCreate] = a.handleDockerVolumeCreate
		a.handlers[protocol.ActionDockerVolumeRemove] = a.handleDockerVolumeRemove

		// Docker network commands
		a.handlers[protocol.ActionDockerNetworkList] = a.handleDockerNetworkList
		a.handlers[protocol.ActionDockerNetworkCreate] = a.handleDockerNetworkCreate
		a.handlers[protocol.ActionDockerNetworkRemove] = a.handleDockerNetworkRemove

		// Docker compose commands
		a.handlers[protocol.ActionDockerComposeList] = a.handleDockerComposeList
		a.handlers[protocol.ActionDockerComposePs] = a.handleDockerComposePs
		a.handlers[protocol.ActionDockerComposeUp] = a.handleDockerComposeUp
		a.handlers[protocol.ActionDockerComposeDown] = a.handleDockerComposeDown
		a.handlers[protocol.ActionDockerComposeLogs] = a.handleDockerComposeLogs
		a.handlers[protocol.ActionDockerComposeRestart] = a.handleDockerComposeRestart
		a.handlers[protocol.ActionDockerComposePull] = a.handleDockerComposePull
	}

	// System commands
	if a.metrics != nil {
		a.handlers[protocol.ActionSystemMetrics] = a.handleSystemMetrics
		a.handlers[protocol.ActionSystemInfo] = a.handleSystemInfo
		a.handlers[protocol.ActionSystemProcesses] = a.handleSystemProcesses
	}

	// File commands
	if a.cfg.Features.FileAccess {
		a.handlers[protocol.ActionFileRead] = a.handleFileRead
		a.handlers[protocol.ActionFileWrite] = a.handleFileWrite
		a.handlers[protocol.ActionFileList] = a.handleFileList
	}

	// Terminal commands
	if a.terminal != nil {
		a.handlers[protocol.ActionTerminalCreate] = a.handleTerminalCreate
		a.handlers[protocol.ActionTerminalInput] = a.handleTerminalInput
		a.handlers[protocol.ActionTerminalResize] = a.handleTerminalResize
		a.handlers[protocol.ActionTerminalClose] = a.handleTerminalClose
	}

	// Cron commands — Linux-only, but registered unconditionally so a
	// stub returns a clear error on Windows/macOS instead of "unknown
	// action".
	a.handlers[protocol.ActionCronStatus] = a.handleCronStatus
	a.handlers[protocol.ActionCronList] = a.handleCronList
	a.handlers[protocol.ActionCronAdd] = a.handleCronAdd
	a.handlers[protocol.ActionCronRemove] = a.handleCronRemove
	a.handlers[protocol.ActionCronToggle] = a.handleCronToggle

	// Cloudflared commands — same Linux-only/stub pattern. Auth state
	// (cert.pem present) is exposed via :status, not via the
	// capabilities probe, so the panel can distinguish "binary
	// installed but not logged in" from "not installed at all."
	a.handlers[protocol.ActionCloudflaredStatus] = a.handleCloudflaredStatus
	a.handlers[protocol.ActionCloudflaredLogin] = a.handleCloudflaredLogin
	a.handlers[protocol.ActionCloudflaredTunnelList] = a.handleCloudflaredTunnelList
	a.handlers[protocol.ActionCloudflaredTunnelCreate] = a.handleCloudflaredTunnelCreate
	a.handlers[protocol.ActionCloudflaredTunnelRoute] = a.handleCloudflaredTunnelRoute
	a.handlers[protocol.ActionCloudflaredTunnelDelete] = a.handleCloudflaredTunnelDelete

	// WireGuard tunnel primitives. Registered unconditionally so
	// non-Linux agents return a clear "unsupported" error rather than
	// "unknown action"; the `wireguard` capability gates the panel's
	// Remote Access flow. See docs/REMOTE_ACCESS_ROADMAP.md.
	a.handlers[protocol.ActionWireguardKeygen] = a.handleWireguardKeygen
	a.handlers[protocol.ActionWireguardInterfaceUp] = a.handleWireguardInterfaceUp
	a.handlers[protocol.ActionWireguardInterfaceDown] = a.handleWireguardInterfaceDown
	a.handlers[protocol.ActionWireguardPeerSet] = a.handleWireguardPeerSet
	a.handlers[protocol.ActionWireguardPeerRemove] = a.handleWireguardPeerRemove
	a.handlers[protocol.ActionWireguardStatus] = a.handleWireguardStatus
	a.handlers[protocol.ActionWireguardForward] = a.handleWireguardForward
	a.handlers[protocol.ActionWireguardUnforward] = a.handleWireguardUnforward

	// Firewall — used by the tunnel broker to open the edge's WireGuard
	// UDP port (#10). Linux-only; returns a clear error elsewhere.
	a.handlers[protocol.ActionFirewallAllowPort] = a.handleFirewallAllowPort
	a.handlers[protocol.ActionFirewallDenyPort] = a.handleFirewallDenyPort

	// Phase 4 primitives — packages, systemd, exec. Registered
	// unconditionally so non-Linux agents return a clear error rather
	// than "unknown action"; the capability probe gates the panel's
	// target picker so users don't normally hit this on Windows.
	a.handlers[protocol.ActionPackagesInstall] = a.handlePackagesInstall
	a.handlers[protocol.ActionPackagesRemove] = a.handlePackagesRemove
	a.handlers[protocol.ActionPackagesListInstalled] = a.handlePackagesListInstalled
	a.handlers[protocol.ActionPackagesUpdateCache] = a.handlePackagesUpdateCache
	a.handlers[protocol.ActionPackagesInstallAsync] = a.handlePackagesInstallAsync
	a.handlers[protocol.ActionPackagesUpgrade] = a.handlePackagesUpgrade
	a.handlers[protocol.ActionPackagesSearch] = a.handlePackagesSearch
	a.handlers[protocol.ActionPackagesInfo] = a.handlePackagesInfo
	a.handlers[protocol.ActionSystemdStatus] = a.handleSystemdStatus
	a.handlers[protocol.ActionSystemdStart] = a.handleSystemdStart
	a.handlers[protocol.ActionSystemdStop] = a.handleSystemdStop
	a.handlers[protocol.ActionSystemdRestart] = a.handleSystemdRestart
	a.handlers[protocol.ActionSystemdEnable] = a.handleSystemdEnable
	a.handlers[protocol.ActionSystemdDisable] = a.handleSystemdDisable
	a.handlers[protocol.ActionSystemdDaemonReload] = a.handleSystemdDaemonReload
	a.handlers[protocol.ActionSystemdListUnits] = a.handleSystemdListUnits
	a.handlers[protocol.ActionSystemdLogs] = a.handleSystemdLogs
	a.handlers[protocol.ActionSystemdLogsFollow] = a.handleSystemdLogsFollow

	// system:exec is gated on Features.Exec rather than registered
	// unconditionally — the previous version installed the handler
	// regardless of the feature flag, which made the flag misleading
	// (Exec=false still let the panel run any command). The handler
	// itself enforces this too, but failing fast at registration means
	// the panel sees a clean "unknown action" instead of a runtime
	// error and can disable the feature in its UI.
	if a.cfg.Features.Exec {
		a.handlers[protocol.ActionSystemExec] = a.handleSystemExec
	}

	// Agent commands
	a.handlers[protocol.ActionAgentUpdate] = a.handleAgentUpdate
	a.handlers[protocol.ActionAgentRecapabilities] = a.handleAgentRecapabilities

	// Runtime version managers (Phase 5). pyenv on Linux,
	// pyenv-win on Windows. Always registered so pages that probe
	// runtimes:list can tell "manager not installed" from "unknown
	// action" — bootstrap then becomes a one-click action.
	a.handlers[protocol.ActionRuntimesList] = a.handleRuntimesList
	a.handlers[protocol.ActionRuntimesPyenvBootstrap] = a.handleRuntimesPyenvBootstrap
	a.handlers[protocol.ActionRuntimesPythonInstalled] = a.handleRuntimesPythonInstalled
	a.handlers[protocol.ActionRuntimesPythonAvailable] = a.handleRuntimesPythonAvailable
	a.handlers[protocol.ActionRuntimesPythonInstall] = a.handleRuntimesPythonInstall
	a.handlers[protocol.ActionRuntimesPythonUninstall] = a.handleRuntimesPythonUninstall
	a.handlers[protocol.ActionRuntimesPythonSetGlobal] = a.handleRuntimesPythonSetGlobal
	a.handlers[protocol.ActionRuntimesPythonSetLocal] = a.handleRuntimesPythonSetLocal
	a.handlers[protocol.ActionRuntimesPythonCurrent] = a.handleRuntimesPythonCurrent

	// GUI SDK — primitives that panel extensions (serverkit-gui, etc.)
	// compose into desktop-streaming or synthetic-UI features. Always
	// registered; the SDK reports "none" capability on hosts that can't
	// capture, so plugins can probe instead of failing.
	a.handlers[protocol.ActionGUICapabilities] = a.gui.HandleCapabilities
	a.handlers[protocol.ActionGUIScreenshot] = a.gui.HandleScreenshot
}

// Run starts the agent
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("Starting agent",
		"agent_id", a.cfg.Agent.ID,
		"version", Version,
		"features", fmt.Sprintf("docker=%v metrics=%v ipc=%v exec=%v file_access=%v", a.cfg.Features.Docker, a.cfg.Features.Metrics, a.cfg.IPC.Enabled, a.cfg.Features.Exec, a.cfg.Features.FileAccess),
	)
	// Surface insecure-TLS at WARN every startup so a misconfigured
	// deployment script can't silently disable certificate verification
	// across every TLS dial in the agent (we have four independent
	// tls.Configs respecting this env var). The user explicitly opted
	// in via env var, so don't refuse to start — just make it loud.
	if os.Getenv("SERVERKIT_INSECURE_TLS") == "true" {
		a.log.Warn("SERVERKIT_INSECURE_TLS=true: TLS certificate verification is DISABLED for all panel connections; only use this for local development")
		a.events.Append(events.KindInfo, events.SeverityWarn,
			"Insecure TLS mode enabled (SERVERKIT_INSECURE_TLS)", nil)
	}
	a.events.Append(events.KindServiceStart, events.SeverityInfo,
		"Agent service started",
		map[string]interface{}{"version": Version})

	// Verify Docker connection if enabled
	if a.docker != nil {
		if err := a.docker.Ping(ctx); err != nil {
			a.log.Warn("Docker is not available", "error", err)
		} else {
			version, _ := a.docker.Version(ctx)
			a.log.Info("Docker connected", "version", version)
		}
	}

	// Start IPC server if enabled
	if a.ipc != nil {
		if err := a.ipc.Start(ctx); err != nil {
			a.log.Warn("Failed to start IPC server", "error", err)
		}
	}

	// Start WebSocket connection in background
	go func() {
		if err := a.ws.Run(ctx); err != nil && err != context.Canceled {
			a.log.Error("WebSocket error", "error", err)
		}
	}()

	// Start heartbeat loop
	go a.heartbeatLoop(ctx)

	// Start discovery responder
	go a.discoveryLoop(ctx)

	// Start the desktop-console metrics sampler (1 Hz ring buffer, 5 min)
	if a.sampler != nil {
		go a.samplerLoop(ctx)
	}

	// Watch WS connection state and emit Activity events on transitions.
	// Polling at 1 Hz is fine — the activity tab is a human-readable
	// timeline, not a real-time monitor.
	go a.connectionWatcher(ctx)

	// Wait for context cancellation or restart request
	select {
	case <-ctx.Done():
		a.events.Append(events.KindServiceStop, events.SeverityInfo,
			"Agent stopping (signal)", nil)
	case <-a.restartCh:
		a.log.Info("Restart requested")
		a.events.Append(events.KindRestartRequested, events.SeverityInfo,
			"Restart requested via IPC", nil)
	}

	// Cleanup
	a.cleanup()

	return ctx.Err()
}

// discoveryLoop listens for UDP discovery requests and responds with agent info
func (a *Agent) discoveryLoop(ctx context.Context) {
	// Simple UDP broadcast listener
	// Port 9000 matches DiscoveryService in backend
	port := 9000
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		a.log.Error("Failed to resolve UDP address for discovery", "error", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		a.log.Error("Failed to listen for discovery broadcasts", "error", err)
		return
	}
	defer conn.Close()

	a.log.Info("Agent discovery responder started", "port", port)

	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				// A read deadline timeout is the normal case (no
				// inbound discovery this second) — fall through and
				// wait again. A real socket error (closed FD, ICMP
				// unreachable storms) used to busy-loop here at
				// 100% CPU; sleep briefly so the loop doesn't spin
				// while still being responsive to ctx cancellation.
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				a.log.Debug("UDP discovery read error", "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
				continue
			}

			var req struct {
				Type      string `json:"type"`
				Timestamp int64  `json:"timestamp"`
				Signature string `json:"signature"`
			}
			if err := json.Unmarshal(buf[:n], &req); err != nil || (req.Type != "discovery_request" && req.Type != string(protocol.TypeDiscoveryRequest)) {
				continue
			}

			// If agent has no credentials (not registered), don't respond to discovery
			if a.cfg.Auth.APIKey == "" {
				continue
			}

			// Validate timestamp is within 60 seconds
			now := time.Now().UnixMilli()
			if req.Timestamp <= 0 || abs(now-req.Timestamp) > 60000 {
				a.log.Debug("Ignoring discovery request with stale timestamp")
				continue
			}

			// Verify HMAC signature
			if req.Signature == "" {
				a.log.Debug("Ignoring discovery request without signature")
				continue
			}
			expectedMessage := fmt.Sprintf("discovery:%d", req.Timestamp)
			mac := hmac.New(sha256.New, []byte(a.cfg.Auth.APIKey))
			mac.Write([]byte(expectedMessage))
			expectedSignature := hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(req.Signature), []byte(expectedSignature)) {
				a.log.Debug("Ignoring discovery request with invalid signature")
				continue
			}

			// Respond with minimal agent info (no detailed hardware specs)
			hostname, _ := os.Hostname()
			resp := struct {
				Type         string `json:"type"`
				AgentID      string `json:"agent_id"`
				Hostname     string `json:"hostname"`
				Status       string `json:"status"`
				AgentVersion string `json:"agent_version"`
				Timestamp    int64  `json:"timestamp"`
			}{
				Type:         "discovery",
				AgentID:      a.cfg.Agent.ID,
				Hostname:     hostname,
				Status:       "online",
				AgentVersion: Version,
				Timestamp:    time.Now().UnixMilli(),
			}

			data, _ := json.Marshal(resp)

			// Send response to remoteAddr on port+1
			respAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteAddr.IP.String(), port+1))
			conn.WriteToUDP(data, respAddr)
		}
	}
}

// abs returns the absolute value of an int64
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// connectionWatcher polls the WS connection flag and emits Activity events
// on each transition. Avoids dragging events.Store into the ws package or
// adding a new callback API for one consumer.
//
// Also doubles as the "send capabilities on connect" hook: each time the
// transport flips from down→up, we re-ship the capability map so the
// panel's record stays current after a panel restart.
//
// On top of the transition trigger, we also re-send capabilities on a
// 60-second cadence whenever the transport is up. The transition path
// is fragile when the WS-then-poll fallback dance briefly raises
// IsConnected() against a backend that's about to be replaced — the
// message can land on a transport whose Send() silently drops it
// (or buffers it forever). Periodic re-sends mean a single missed
// transition doesn't leave the panel with an empty capability map for
// the lifetime of the agent process; the worst case is a 60-second
// gap before the next refresh.
func (a *Agent) connectionWatcher(ctx context.Context) {
	transitionTicker := time.NewTicker(1 * time.Second)
	defer transitionTicker.Stop()
	// Aggressive cadence for the first minute so a cold-boot agent
	// populates the panel within ~5s of the first successful transport
	// connect. Aaron's law: the WS-then-poll fallback dance can land
	// the transition's send on a backend that's about to be replaced,
	// and the panel ends up with an empty capability map until the
	// next steady-state tick fires.
	resendTicker := time.NewTicker(5 * time.Second)
	defer resendTicker.Stop()
	resendTicks := 0

	prev := false
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-resendTicker.C:
			// Idempotent re-send. The panel's update_capabilities is a
			// pure overwrite, so re-shipping the same payload costs us
			// nothing; the panel just rewrites the same row.
			if a.ws.IsConnected() {
				a.sendCapabilities()
				a.sendSystemInfo(ctx)
			}
			resendTicks++
			// After ~60 seconds (12 ticks at 5s), back the cadence off
			// to once a minute. The first minute is the only window
			// where transport churn is likely; long-lived connections
			// don't need the heavier pulse.
			if resendTicks == 12 {
				resendTicker.Reset(60 * time.Second)
			}
		case <-transitionTicker.C:
			now := a.ws.IsConnected()
			if now == prev && !first {
				continue
			}
			first = false
			if now {
				a.events.Append(events.KindWSConnected, events.SeverityInfo,
					"Connected to panel",
					map[string]interface{}{"url": a.cfg.Server.URL})
				a.sendCapabilities()
				a.sendSystemInfo(ctx)
			} else if prev {
				// Only log disconnect after we'd previously been up — avoids
				// a spurious "lost connection" on cold-start before the
				// first connect ever succeeds.
				a.events.Append(events.KindWSDisconnected, events.SeverityWarn,
					"Connection lost", nil)
			}
			prev = now
		}
	}
}

// sendSystemInfo collects the host's system info (CPU, memory, disk,
// hostname, OS, kernel) and pushes it to the panel as a typed
// SystemInfoMessage so it lands in update_system_info → DB. The agent
// previously only answered system:info synchronously, which meant the
// panel never persisted the values — Overview would show "N/A" for
// CPU/memory/disk whenever the page was loaded against a server whose
// info hadn't been queried yet (or if the query timed out).
//
// Also surfaces the agent's local IPv4 (first non-loopback) so the
// panel can show *which* host is reporting in, separate from the
// public IP it sees on the inbound connection.
func (a *Agent) sendSystemInfo(ctx context.Context) {
	if a.metrics == nil {
		return
	}
	infoCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := a.metrics.GetSystemInfo(infoCtx)
	if err != nil || info == nil {
		a.log.Debug("system info collect failed", "error", err)
		return
	}
	// Build the protocol shape — different field names than the metrics
	// package's SystemInfo (CPUCores vs CPUThreads, etc.). Send the
	// most useful subset and let the panel's update_system_info pick
	// the keys it cares about.
	payload := protocol.SystemInfoMessage{
		Message: protocol.NewMessage(protocol.TypeSystemInfo, auth.GenerateNonce()),
		Info: protocol.SystemInfo{
			Hostname:      info.Hostname,
			OS:            info.OS,
			OSVersion:     info.PlatformVersion,
			Platform:      info.Platform,
			Architecture:  info.Architecture,
			CPUModel:      info.CPUModel,
			CPUCores:      info.CPUThreads, // surface threads as "cores" — matches the panel's existing column
			TotalMemory:   info.TotalMemory,
			TotalDisk:     info.TotalDisk,
			DockerVersion: a.dockerVersion(),
			AgentVersion:  Version,
			InstallDir:    a.installDir(),
			ConfigDir:     a.configDir(),
		},
	}
	if err := a.ws.Send(payload); err != nil {
		a.log.Debug("system info send failed", "error", err)
	}
}

// installDir is the running binary's directory — self-reported so the panel
// never has to assume the installer's default location. Empty ("") when the
// executable path can't be resolved; the panel keeps its previous value.
func (a *Agent) installDir() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return ""
	}
	return filepath.Dir(exe)
}

// configDir is the directory of the config file this agent was started with
// (also home to agent.key). Falls back to the platform default when the
// config didn't come from disk (tests, programmatic construction).
func (a *Agent) configDir() string {
	if a.cfg != nil && a.cfg.SourcePath != "" {
		return filepath.Dir(a.cfg.SourcePath)
	}
	return filepath.Dir(config.DefaultConfigPath())
}

// dockerVersion returns the running Docker daemon version, or "" if
// docker isn't reachable (which the capability probe already
// surfaces). Best-effort — we don't want a dockerd hiccup to block
// system_info delivery.
func (a *Agent) dockerVersion() string {
	if a.docker == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v, err := a.docker.Version(ctx)
	if err != nil {
		return ""
	}
	return v
}

// sendCapabilities ships the cached capability probe to the panel.
// Failures are logged and ignored — capabilities are best-effort
// metadata; missing ones just mean an agent doesn't show up in feature
// pickers until the next reconnect.
func (a *Agent) sendCapabilities() {
	a.capMu.Lock()
	caps := a.capabilities
	a.capMu.Unlock()
	msg := protocol.CapabilitiesMessage{
		Message:         protocol.NewMessage(protocol.TypeCapabilities, auth.GenerateNonce()),
		Capabilities:    caps.Capabilities,
		Platform:        caps.Platform,
		Distro:          caps.Distro,
		DistroVersion:   caps.DistroVersion,
		Runtimes:        caps.Runtimes,
		AllowedPaths:    caps.AllowedPaths,
		Sudo:            caps.Sudo,
		RuntimeManagers: caps.RuntimeManagers,
		SystemdJSON:     caps.SystemdJSON,
		ProbedAt:        caps.ProbedAt,
	}
	a.log.Info("Sending capabilities to panel",
		"sudo", caps.Sudo,
		"cap_count", len(caps.Capabilities),
		"runtime_count", len(caps.Runtimes),
	)
	if err := a.ws.Send(msg); err != nil {
		a.log.Warn("Failed to send capabilities", "error", err)
		return
	}
	a.log.Debug("Sent capabilities to panel",
		"platform", caps.Platform,
		"distro", caps.Distro,
		"sudo", caps.Sudo,
	)
}

// heartbeatLoop sends periodic heartbeats
func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.Server.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.ws.IsConnected() {
				continue
			}

			heartbeatMetrics := protocol.HeartbeatMetrics{}

			// Collect basic metrics for heartbeat
			if a.metrics != nil {
				sysMetrics, err := a.metrics.Collect(ctx)
				if err == nil {
					heartbeatMetrics.CPUPercent = sysMetrics.CPUPercent
					heartbeatMetrics.MemoryPercent = sysMetrics.MemoryPercent
					heartbeatMetrics.DiskPercent = sysMetrics.DiskPercent
				}
			}

			// Get container counts if Docker is available
			if a.docker != nil {
				total, running, err := a.docker.GetContainerCount(ctx)
				if err == nil {
					heartbeatMetrics.ContainerCount = total
					heartbeatMetrics.ContainerRunning = running
				}
			}

			if err := a.ws.SendHeartbeat(heartbeatMetrics); err != nil {
				a.log.Warn("Failed to send heartbeat", "error", err)
			} else {
				a.log.Debug("Heartbeat sent",
					"cpu", fmt.Sprintf("%.1f%%", heartbeatMetrics.CPUPercent),
					"mem", fmt.Sprintf("%.1f%%", heartbeatMetrics.MemoryPercent),
				)
			}
		}
	}
}

// handleMessage handles incoming WebSocket messages
func (a *Agent) handleMessage(msgType protocol.MessageType, data []byte) {
	a.log.Debug("Received message", "type", msgType)

	switch msgType {
	case protocol.TypeCommand:
		a.handleCommand(data)
	case protocol.TypeSubscribe:
		a.handleSubscribe(data)
	case protocol.TypeUnsubscribe:
		a.handleUnsubscribe(data)
	case protocol.TypeCredentialUpdate:
		a.handleCredentialUpdate(data)
	default:
		a.log.Warn("Unknown message type", "type", msgType)
	}
}

// handleCommand handles command messages
func (a *Agent) handleCommand(data []byte) {
	var cmd protocol.CommandMessage
	if err := json.Unmarshal(data, &cmd); err != nil {
		a.log.Error("Failed to parse command", "error", err)
		return
	}

	a.log.Info("Executing command",
		"id", cmd.ID,
		"action", cmd.Action,
	)

	// Find handler
	handler, ok := a.handlers[cmd.Action]
	if !ok {
		a.log.Warn("Unknown command action", "action", cmd.Action)
		a.ws.SendCommandResult(cmd.ID, false, nil, "unknown action: "+cmd.Action, 0)
		return
	}

	// Execute command with enforced maximum timeout. The ceiling is
	// configurable via Security.MaxExecTimeout; resolveMaxExecTimeout
	// returns the operator's value or the default safety net.
	start := time.Now()
	maxTimeout := a.resolveMaxExecTimeout()
	cmdTimeout := time.Duration(cmd.Timeout) * time.Millisecond

	if cmdTimeout <= 0 || cmdTimeout > maxTimeout {
		cmdTimeout = maxTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	result, err := handler(ctx, cmd.Params)
	duration := time.Since(start)

	if err != nil {
		a.log.Error("Command failed",
			"id", cmd.ID,
			"action", cmd.Action,
			"error", err,
			"duration", duration,
		)
		a.ws.SendCommandResult(cmd.ID, false, nil, err.Error(), duration)
		return
	}

	a.log.Info("Command completed",
		"id", cmd.ID,
		"action", cmd.Action,
		"duration", duration,
	)
	a.ws.SendCommandResult(cmd.ID, true, result, "", duration)
}

// handleSubscribe handles subscription requests
func (a *Agent) handleSubscribe(data []byte) {
	var sub protocol.SubscribeMessage
	if err := json.Unmarshal(data, &sub); err != nil {
		a.log.Error("Failed to parse subscribe message", "error", err)
		return
	}

	a.log.Info("Subscribing to channel", "channel", sub.Channel)

	// Replay any buffered events for job channels so a panel that
	// subscribed mid-flight (or just after the job finished) still sees
	// the full progress history. Replay before installing the
	// subscription record so a brand-new "live" event can't get
	// interleaved before the replay.
	if job := a.jobs.LookupByChannel(sub.Channel); job != nil {
		for _, ev := range job.Replay() {
			if err := a.ws.SendStream(sub.Channel, ev); err != nil {
				a.log.Warn("Failed to replay job event", "channel", sub.Channel, "error", err)
				break
			}
		}
	}

	// Create cancellable context for this subscription
	ctx, cancel := context.WithCancel(context.Background())

	a.subMu.Lock()
	// Cancel existing subscription if any
	if existingCancel, ok := a.subscriptions[sub.Channel]; ok {
		existingCancel()
	}
	a.subscriptions[sub.Channel] = cancel
	a.subMu.Unlock()

	// Start streaming based on channel type
	go a.streamData(ctx, sub.Channel)
}

// handleUnsubscribe handles unsubscription requests
func (a *Agent) handleUnsubscribe(data []byte) {
	var unsub protocol.UnsubscribeMessage
	if err := json.Unmarshal(data, &unsub); err != nil {
		a.log.Error("Failed to parse unsubscribe message", "error", err)
		return
	}

	a.log.Info("Unsubscribing from channel", "channel", unsub.Channel)

	a.subMu.Lock()
	if cancel, ok := a.subscriptions[unsub.Channel]; ok {
		cancel()
		delete(a.subscriptions, unsub.Channel)
	}
	a.subMu.Unlock()
}

// streamData streams data for a subscription
func (a *Agent) streamData(ctx context.Context, channel string) {
	// Determine what to stream based on channel
	switch channel {
	case protocol.ChannelMetrics:
		a.streamMetrics(ctx, channel)
	default:
		a.log.Warn("Unknown stream channel", "channel", channel)
	}
}

// streamMetrics streams system metrics
func (a *Agent) streamMetrics(ctx context.Context, channel string) {
	ticker := time.NewTicker(a.cfg.Metrics.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.metrics == nil {
				continue
			}

			sysMetrics, err := a.metrics.Collect(ctx)
			if err != nil {
				a.log.Warn("Failed to collect metrics", "error", err)
				continue
			}

			if err := a.ws.SendStream(channel, sysMetrics); err != nil {
				a.log.Warn("Failed to send metrics stream", "error", err)
			}
		}
	}
}

// handleCredentialUpdate handles credential rotation from server.
//
// Before applying the rotation we verify an HMAC over the new
// credentials computed with the agent's current secret. The session-
// level WS auth alone is not sufficient: the panel is a large surface
// and a session token leak (or a panel-side bug that lets an
// authenticated user cross server boundaries) would otherwise let an
// attacker rotate any agent's credentials to ones they control. The
// extra check means an attacker has to also know the agent's current
// secret — which is exactly what we're trying to protect.
func (a *Agent) handleCredentialUpdate(data []byte) {
	var msg protocol.CredentialUpdateMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		a.log.Error("Failed to parse credential update", "error", err)
		return
	}

	a.log.Info("Received credential update request", "rotation_id", msg.RotationID)

	if err := a.verifyCredentialRotation(msg); err != nil {
		a.log.Warn("Rejecting credential rotation", "rotation_id", msg.RotationID, "error", err)
		a.events.Append(events.KindAuthFailed, events.SeverityWarn,
			"Credential rotation rejected: "+err.Error(),
			map[string]interface{}{"rotation_id": msg.RotationID})
		ack := protocol.CredentialUpdateAck{
			Message:    protocol.NewMessage(protocol.TypeCredentialUpdateAck, auth.GenerateNonce()),
			RotationID: msg.RotationID,
			Success:    false,
			Error:      err.Error(),
		}
		a.ws.Send(ack)
		return
	}

	// Update authenticator with new credentials
	a.auth.UpdateCredentials(msg.APIKey, msg.APISecret)

	// Save new credentials to config file
	err := a.saveCredentials(msg.APIKey, msg.APISecret)

	// Send acknowledgment
	ack := protocol.CredentialUpdateAck{
		Message:    protocol.NewMessage(protocol.TypeCredentialUpdateAck, auth.GenerateNonce()),
		RotationID: msg.RotationID,
		Success:    err == nil,
	}
	if err != nil {
		ack.Error = err.Error()
		a.log.Error("Failed to save new credentials", "error", err)
	} else {
		a.log.Info("Credentials updated successfully", "rotation_id", msg.RotationID)
	}

	a.ws.Send(ack)
}

// verifyCredentialRotation checks the HMAC the panel attaches to a
// rotation message against the agent's current secret. Returns nil
// only when the signature is present, well-formed, and matches.
//
// The panel must compute hex(HMAC-SHA256(
//
//	"rotation_id:agent_id:new_api_key:new_api_secret",
//	current_api_secret)).
func (a *Agent) verifyCredentialRotation(msg protocol.CredentialUpdateMessage) error {
	if msg.RotationID == "" || msg.APIKey == "" || msg.APISecret == "" {
		return fmt.Errorf("rotation message missing required fields")
	}
	if msg.HMACSig == "" {
		return fmt.Errorf("rotation message missing hmac signature")
	}
	currentSecret := a.auth.GetAPISecret()
	if currentSecret == "" {
		return fmt.Errorf("agent has no current secret; refusing to rotate")
	}
	payload := fmt.Sprintf("%s:%s:%s:%s",
		msg.RotationID, a.cfg.Agent.ID, msg.APIKey, msg.APISecret)
	mac := hmac.New(sha256.New, []byte(currentSecret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(msg.HMACSig), []byte(expected)) {
		return fmt.Errorf("hmac signature mismatch")
	}
	return nil
}

// saveCredentials saves new credentials to the key file
func (a *Agent) saveCredentials(apiKey, apiSecret string) error {
	// Update config with new credentials
	a.cfg.Auth.APIKey = apiKey
	a.cfg.Auth.APISecret = apiSecret

	// Save using existing secure method
	return a.cfg.SaveCredentials()
}

func (a *Agent) cleanup() {
	a.log.Info("Cleaning up...")

	// Cancel all subscriptions
	a.subMu.Lock()
	for _, cancel := range a.subscriptions {
		cancel()
	}
	a.subscriptions = make(map[string]context.CancelFunc)
	a.subMu.Unlock()

	// Close all terminal sessions
	if a.terminal != nil {
		a.terminal.CloseAll()
	}

	// Stop IPC server
	if a.ipc != nil {
		a.ipc.Stop()
	}

	// Close WebSocket
	a.ws.Close()

	// Close Docker client
	if a.docker != nil {
		a.docker.Close()
	}
}

// Docker command handlers

func (a *Agent) handleDockerContainerList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		All bool `json:"all"`
	}
	if len(params) > 0 {
		json.Unmarshal(params, &p)
	}
	return a.docker.ListContainers(ctx, p.All)
}

func (a *Agent) handleDockerContainerInspect(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return a.docker.InspectContainer(ctx, p.ID)
}

func (a *Agent) handleDockerContainerStart(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.StartContainer(ctx, p.ID)
}

func (a *Agent) handleDockerContainerStop(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID      string `json:"id"`
		Timeout *int   `json:"timeout"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.StopContainer(ctx, p.ID, p.Timeout)
}

func (a *Agent) handleDockerContainerRestart(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID      string `json:"id"`
		Timeout *int   `json:"timeout"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.RestartContainer(ctx, p.ID, p.Timeout)
}

func (a *Agent) handleDockerContainerRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID            string `json:"id"`
		Force         bool   `json:"force"`
		RemoveVolumes bool   `json:"remove_volumes"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.RemoveContainer(ctx, p.ID, p.Force, p.RemoveVolumes)
}

func (a *Agent) handleDockerContainerStats(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return a.docker.ContainerStats(ctx, p.ID)
}

func (a *Agent) handleDockerContainerLogs(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID         string `json:"id"`
		Tail       string `json:"tail"`
		Since      string `json:"since"`
		Timestamps bool   `json:"timestamps"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// Set defaults
	if p.Tail == "" {
		p.Tail = "100"
	}

	reader, err := a.docker.ContainerLogs(ctx, p.ID, p.Tail, p.Since, false)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Drain the stream up to a 1 MB cap. The previous implementation
	// did a single Read() and dropped the error — Docker's stream
	// framing means one Read returns whatever happens to be in the
	// first chunk (often a few KB), so the panel's "logs" command
	// got a tiny prefix of the requested tail. io.ReadAll over a
	// LimitReader gives the panel the full payload it asked for.
	const maxLogBytes = 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(reader, maxLogBytes))
	if err != nil {
		return nil, fmt.Errorf("read docker logs: %w", err)
	}

	return map[string]interface{}{
		"logs": string(data),
	}, nil
}

func (a *Agent) handleDockerImageList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.docker.ListImages(ctx)
}

func (a *Agent) handleDockerImagePull(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Image string `json:"image"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	reader, err := a.docker.PullImage(ctx, p.Image)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read the output to completion
	var output []map[string]interface{}
	decoder := json.NewDecoder(reader)
	for decoder.More() {
		var msg map[string]interface{}
		if err := decoder.Decode(&msg); err != nil {
			break
		}
		output = append(output, msg)
	}

	return map[string]interface{}{
		"success": true,
		"output":  output,
	}, nil
}

func (a *Agent) handleDockerImageRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID    string `json:"id"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.RemoveImage(ctx, p.ID, p.Force)
}

func (a *Agent) handleDockerVolumeList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.docker.ListVolumes(ctx)
}

func (a *Agent) handleDockerVolumeRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.RemoveVolume(ctx, p.Name, p.Force)
}

func (a *Agent) handleDockerNetworkList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.docker.ListNetworks(ctx)
}

func (a *Agent) handleDockerNetworkRemove(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	return map[string]bool{"success": true}, a.docker.RemoveNetwork(ctx, p.ID)
}

// System command handlers

func (a *Agent) handleSystemMetrics(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.metrics.Collect(ctx)
}

func (a *Agent) handleSystemInfo(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.metrics.GetSystemInfo(ctx)
}

func (a *Agent) handleSystemProcesses(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.metrics.ListProcesses(ctx)
}

// File command handlers live in file_handlers.go.

// Docker Compose command handlers

func (a *Agent) handleDockerComposeList(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return a.docker.ComposeList(ctx)
}

func (a *Agent) handleDockerComposePs(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath string `json:"project_path"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}
	return a.docker.ComposePsProject(ctx, p.ProjectPath)
}

func (a *Agent) handleDockerComposeUp(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath string `json:"project_path"`
		Detach      bool   `json:"detach"`
		Build       bool   `json:"build"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}

	// Default to detached mode
	if !p.Detach {
		p.Detach = true
	}

	output, err := a.docker.ComposeUp(ctx, p.ProjectPath, p.Detach, p.Build)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"output":  output,
			"error":   err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"success": true,
		"output":  output,
	}, nil
}

func (a *Agent) handleDockerComposeDown(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath   string `json:"project_path"`
		Volumes       bool   `json:"volumes"`
		RemoveOrphans bool   `json:"remove_orphans"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}

	output, err := a.docker.ComposeDown(ctx, p.ProjectPath, p.Volumes, p.RemoveOrphans)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"output":  output,
			"error":   err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"success": true,
		"output":  output,
	}, nil
}

func (a *Agent) handleDockerComposeLogs(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath string `json:"project_path"`
		Service     string `json:"service"`
		Tail        int    `json:"tail"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}

	// Default tail to 100
	if p.Tail == 0 {
		p.Tail = 100
	}

	logs, err := a.docker.ComposeLogs(ctx, p.ProjectPath, p.Service, p.Tail)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"logs": logs,
	}, nil
}

func (a *Agent) handleDockerComposeRestart(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath string `json:"project_path"`
		Service     string `json:"service"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}

	output, err := a.docker.ComposeRestart(ctx, p.ProjectPath, p.Service)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"output":  output,
			"error":   err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"success": true,
		"output":  output,
	}, nil
}

func (a *Agent) handleDockerComposePull(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		ProjectPath string `json:"project_path"`
		Service     string `json:"service"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if err := a.validateFileAccess(p.ProjectPath); err != nil {
		return nil, err
	}

	output, err := a.docker.ComposePull(ctx, p.ProjectPath, p.Service)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"output":  output,
			"error":   err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"success": true,
		"output":  output,
	}, nil
}

// Terminal command handlers

func (a *Agent) handleTerminalCreate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		SessionID string `json:"session_id"`
		Cols      uint16 `json:"cols"`
		Rows      uint16 `json:"rows"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if p.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}

	// Default terminal size
	if p.Cols == 0 {
		p.Cols = 80
	}
	if p.Rows == 0 {
		p.Rows = 24
	}

	// Create terminal session
	session, err := a.terminal.CreateSession(p.SessionID, p.Cols, p.Rows)
	if err != nil {
		return nil, fmt.Errorf("failed to create terminal session: %w", err)
	}

	// Set up output handler to stream data back
	channel := fmt.Sprintf(protocol.ChannelTerminal, p.SessionID)
	session.SetOutputHandler(func(data []byte) {
		// Encode as base64 for safe transport
		encoded := base64.StdEncoding.EncodeToString(data)
		if err := a.ws.SendStream(channel, map[string]interface{}{
			"type": "output",
			"data": encoded,
		}); err != nil {
			a.log.Warn("Failed to send terminal output", "error", err)
		}
	})

	// Set up close handler
	session.SetCloseHandler(func() {
		if err := a.ws.SendStream(channel, map[string]interface{}{
			"type": "closed",
		}); err != nil {
			a.log.Warn("Failed to send terminal close event", "error", err)
		}
		// Clean up session
		a.terminal.CloseSession(p.SessionID)
	})

	a.log.Info("Terminal session created",
		"session_id", p.SessionID,
		"cols", p.Cols,
		"rows", p.Rows,
		"shell", session.Shell,
	)

	return map[string]interface{}{
		"success":    true,
		"session_id": p.SessionID,
		"shell":      session.Shell,
		"cols":       session.Cols,
		"rows":       session.Rows,
	}, nil
}

func (a *Agent) handleTerminalInput(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		SessionID string `json:"session_id"`
		Data      string `json:"data"` // base64 encoded
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	session, ok := a.terminal.GetSession(p.SessionID)
	if !ok {
		return nil, fmt.Errorf("terminal session not found: %s", p.SessionID)
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 data: %w", err)
	}

	// Write to terminal
	_, err = session.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write to terminal: %w", err)
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

func (a *Agent) handleTerminalResize(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		SessionID string `json:"session_id"`
		Cols      uint16 `json:"cols"`
		Rows      uint16 `json:"rows"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	session, ok := a.terminal.GetSession(p.SessionID)
	if !ok {
		return nil, fmt.Errorf("terminal session not found: %s", p.SessionID)
	}

	if err := session.Resize(p.Cols, p.Rows); err != nil {
		return nil, fmt.Errorf("failed to resize terminal: %w", err)
	}

	a.log.Debug("Terminal resized",
		"session_id", p.SessionID,
		"cols", p.Cols,
		"rows", p.Rows,
	)

	return map[string]interface{}{
		"success": true,
		"cols":    p.Cols,
		"rows":    p.Rows,
	}, nil
}

func (a *Agent) handleTerminalClose(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if err := a.terminal.CloseSession(p.SessionID); err != nil {
		return nil, fmt.Errorf("failed to close terminal: %w", err)
	}

	a.log.Info("Terminal session closed", "session_id", p.SessionID)

	return map[string]interface{}{
		"success": true,
	}, nil
}

// IPC StatusProvider implementation

// GetStatus returns the current agent status for the IPC API
func (a *Agent) GetStatus() ipc.AgentStatus {
	status := ipc.AgentStatus{
		Running:    true,
		Connected:  a.ws.IsConnected(),
		Registered: a.cfg.Agent.ID != "",
		AgentID:    a.cfg.Agent.ID,
		AgentName:  a.cfg.Agent.Name,
		ServerURL:  a.cfg.Server.URL,
		Uptime:     int64(time.Since(a.startTime).Seconds()),
		Version:    Version,
		Transport:  string(a.ws.Mode()),
	}

	// Collect current metrics if available
	if a.metrics != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sysMetrics, err := a.metrics.Collect(ctx); err == nil {
			status.CPUPercent = sysMetrics.CPUPercent
			status.MemPercent = sysMetrics.MemoryPercent
			status.DiskPercent = sysMetrics.DiskPercent
		}
	}

	return status
}

// GetDetailedMetrics returns detailed system metrics for the IPC API
func (a *Agent) GetDetailedMetrics() *ipc.DetailedMetrics {
	if a.metrics == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sysMetrics, err := a.metrics.Collect(ctx)
	if err != nil {
		return nil
	}

	cores := 0
	if sysMetrics.CPUPerCore != nil {
		cores = len(sysMetrics.CPUPerCore)
	}

	return &ipc.DetailedMetrics{
		CPU: ipc.CPUMetrics{
			UsagePercent: sysMetrics.CPUPercent,
			PerCPU:       sysMetrics.CPUPerCore,
			Cores:        cores,
		},
		Memory: ipc.MemoryMetrics{
			Total:        sysMetrics.MemoryTotal,
			Used:         sysMetrics.MemoryUsed,
			Free:         sysMetrics.MemoryTotal - sysMetrics.MemoryUsed,
			UsagePercent: sysMetrics.MemoryPercent,
		},
		Disk: ipc.DiskMetrics{
			Total:        sysMetrics.DiskTotal,
			Used:         sysMetrics.DiskUsed,
			Free:         sysMetrics.DiskTotal - sysMetrics.DiskUsed,
			UsagePercent: sysMetrics.DiskPercent,
		},
		Network: ipc.NetworkMetrics{
			BytesSent:   sysMetrics.NetworkTx,
			BytesRecv:   sysMetrics.NetworkRx,
			PacketsSent: 0, // Not tracked in current implementation
			PacketsRecv: 0, // Not tracked in current implementation
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// GetMetricsHistory returns the recent CPU/memory ring buffer for the
// desktop console's sparkline charts. Returns an empty slice (not nil) when
// metrics are disabled or the sampler hasn't run yet, so the JSON shape
// stays stable.
func (a *Agent) GetMetricsHistory() []ipc.MetricSample {
	if a.sampler == nil {
		return []ipc.MetricSample{}
	}
	return a.sampler.snapshot()
}

// GetEvents returns recent activity events newer than `since` (unix ms).
// Pass 0 to get all events currently held in the ring buffer.
func (a *Agent) GetEvents(since int64) []events.Event {
	if a.events == nil {
		return []events.Event{}
	}
	return a.events.Snapshot(since)
}

// ClearLogs rotates agent.log so the desktop console can start with a
// clean tail. Existing content moves to an automatic backup file. Records
// the action in the activity log so the user has an audit trail.
func (a *Agent) ClearLogs() error {
	if err := a.log.Rotate(); err != nil {
		return err
	}
	if a.events != nil {
		a.events.Append(events.KindInfo, events.SeverityInfo,
			"Logs cleared from console", nil)
	}
	return nil
}

// GetConnectionInfo returns WebSocket connection information for the IPC API
func (a *Agent) GetConnectionInfo() ipc.ConnectionInfo {
	info := ipc.ConnectionInfo{
		Connected:      a.ws.IsConnected(),
		ServerURL:      a.cfg.Server.URL,
		ReconnectCount: a.reconnectCount,
	}

	if !a.lastConnected.IsZero() {
		info.LastConnected = a.lastConnected.UnixMilli()
	}

	if session := a.ws.Session(); session != nil {
		info.SessionExpires = session.ExpiresAt.UnixMilli()
	}

	return info
}

// GetRecentLogs returns recent log lines from the log file
func (a *Agent) GetRecentLogs(lines int) []string {
	logFile := a.cfg.Logging.File
	if logFile == "" {
		return []string{}
	}

	file, err := os.Open(logFile)
	if err != nil {
		return []string{}
	}
	defer file.Close()

	// Read all lines and keep the last N
	var allLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	// Return the last N lines
	if len(allLines) <= lines {
		return allLines
	}
	return allLines[len(allLines)-lines:]
}

// Restart initiates a graceful restart of the agent
func (a *Agent) Restart() error {
	a.log.Info("Restart requested via IPC")
	select {
	case a.restartCh <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("restart already in progress")
	}
}

// handleAgentUpdate handles agent upgrade commands
func (a *Agent) handleAgentUpdate(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p struct {
		Version      string `json:"version"`
		DownloadURL  string `json:"download_url"`
		ChecksumsURL string `json:"checksums_url"`
		Force        bool   `json:"force"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if p.Version == "" {
		return nil, fmt.Errorf("version is required")
	}

	a.log.Info("Agent update triggered via panel", "version", p.Version)

	// Create updater
	u := updater.New(a.cfg, a.log, Version)

	// Trigger update in background so we can respond to the command
	go func() {
		// Small delay to allow command result to be sent
		time.Sleep(2 * time.Second)

		// Download and install
		// In a real implementation, we would use the provided URLs
		// For now, we'll let the updater handle it using its default logic
		// or extend it to use the provided URLs.

		err := u.UpdateTo(context.Background(), p.Version, p.DownloadURL, p.ChecksumsURL)
		if err != nil {
			a.log.Error("Update failed", "error", err)
			return
		}

		a.log.Info("Update successful, restarting...")
		a.Restart()
	}()

	return map[string]interface{}{
		"success": true,
		"message": "Update triggered",
		"version": p.Version,
	}, nil
}

package protocol

import (
	"encoding/json"
	"time"
)

// MessageType defines the type of message
type MessageType string

const (
	// Authentication
	TypeAuth     MessageType = "auth"
	TypeAuthOK   MessageType = "auth_ok"
	TypeAuthFail MessageType = "auth_fail"

	// Heartbeat
	TypeHeartbeat    MessageType = "heartbeat"
	TypeHeartbeatAck MessageType = "heartbeat_ack"

	// Commands
	TypeCommand       MessageType = "command"
	TypeCommandResult MessageType = "command_result"

	// Streaming
	TypeSubscribe   MessageType = "subscribe"
	TypeUnsubscribe MessageType = "unsubscribe"
	TypeStream      MessageType = "stream"

	// Errors
	TypeError MessageType = "error"

	// System
	TypeSystemInfo MessageType = "system_info"

	// Capabilities — agent reports which feature surfaces it can drive
	// (cron, docker, systemd, …) so the panel can gate target pickers
	// without round-tripping each click.
	TypeCapabilities MessageType = "capabilities"

	// Discovery
	TypeDiscovery        MessageType = "discovery"
	TypeDiscoveryRequest MessageType = "discovery_request"

	// Credential Rotation
	TypeCredentialUpdate    MessageType = "credential_update"
	TypeCredentialUpdateAck MessageType = "credential_update_ack"
)

// Message is the base message structure
type Message struct {
	Type      MessageType `json:"type"`
	ID        string      `json:"id"`
	Timestamp int64       `json:"timestamp"`
	Signature string      `json:"signature,omitempty"`
}

// NewMessage creates a new message with timestamp
func NewMessage(msgType MessageType, id string) Message {
	return Message{
		Type:      msgType,
		ID:        id,
		Timestamp: time.Now().UnixMilli(),
	}
}

// AuthMessage is sent by agent to authenticate
type AuthMessage struct {
	Message
	AgentID      string `json:"agent_id"`
	APIKeyPrefix string `json:"api_key_prefix"`
	Nonce        string `json:"nonce,omitempty"` // Unique nonce for replay protection
}

// AuthResponse is sent by server after authentication
type AuthResponse struct {
	Message
	SessionToken string `json:"session_token,omitempty"`
	Expires      int64  `json:"expires,omitempty"`
	Error        string `json:"error,omitempty"`
}

// HeartbeatMessage is sent periodically by agent
type HeartbeatMessage struct {
	Message
	Metrics HeartbeatMetrics `json:"metrics"`
}

// HeartbeatMetrics contains basic system metrics
type HeartbeatMetrics struct {
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryPercent    float64 `json:"memory_percent"`
	DiskPercent      float64 `json:"disk_percent"`
	ContainerCount   int     `json:"container_count"`
	ContainerRunning int     `json:"container_running"`
}

// HeartbeatAck is sent by server to acknowledge heartbeat
type HeartbeatAck struct {
	Message
}

// CommandMessage is sent by server to execute a command
type CommandMessage struct {
	Message
	Action  string          `json:"action"`
	Params  json.RawMessage `json:"params"`
	Timeout int             `json:"timeout,omitempty"` // milliseconds
}

// CommandResult is sent by agent after executing a command
type CommandResult struct {
	Message
	CommandID string          `json:"command_id"`
	Success   bool            `json:"success"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Duration  int64           `json:"duration"` // milliseconds
}

// SubscribeMessage requests subscription to a data stream
type SubscribeMessage struct {
	Message
	Channel string `json:"channel"`
}

// UnsubscribeMessage cancels a subscription
type UnsubscribeMessage struct {
	Message
	Channel string `json:"channel"`
}

// StreamMessage contains streaming data
type StreamMessage struct {
	Message
	Channel string          `json:"channel"`
	Data    json.RawMessage `json:"data"`
}

// ErrorMessage represents an error
type ErrorMessage struct {
	Message
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
}

// SystemInfoMessage contains system information
type SystemInfoMessage struct {
	Message
	Info SystemInfo `json:"info"`
}

// Capabilities is a flat dict of feature → bool reported by the agent on
// connect. The panel uses this to gate target pickers: an agent shows up
// in the Cron page's picker only if Capabilities["cron"] is true.
//
// Format is intentionally a map[string]bool rather than a struct so new
// keys can be added on the agent side and ignored by older panels (and
// vice versa) without protocol breakage.
type Capabilities map[string]bool

// CapabilitiesMessage is sent by the agent to advertise which feature
// surfaces it can drive. Panel echo-saves this on the in-memory
// ConnectedAgent record.
type CapabilitiesMessage struct {
	Message
	Capabilities  Capabilities `json:"capabilities"`
	Platform      string       `json:"platform"`                 // "linux", "windows", "darwin"
	Distro        string       `json:"distro,omitempty"`         // "ubuntu", "debian", "rhel", ...
	DistroVersion string       `json:"distro_version,omitempty"` // "22.04"
	// Runtimes is a name → version map for language runtimes the agent
	// detected at startup ("python": "3.11.4", "node": "20.10.0").
	// Missing keys mean "not installed"; an empty string value means
	// "installed but the version probe failed." Forward-compatible —
	// new keys just light up in the panel without protocol changes.
	Runtimes map[string]string `json:"runtimes,omitempty"`
	// AllowedPaths advertises the file-access roots the agent is willing
	// to expose. Sent only when capabilities["files"] is true so the
	// panel's file manager can render the available browse roots without
	// guessing. Empty/missing => the panel must hide remote file features.
	AllowedPaths []string `json:"allowed_paths,omitempty"`
	// Sudo describes how the agent escalates privileges for handlers
	// that need root (systemd, packages). Values: "root" (already root),
	// "passwordless" (sudo -n works), "unavailable" (no escalation —
	// privileged handlers will fail). Empty/missing means the panel
	// should treat it as "unavailable" for safety.
	Sudo string `json:"sudo,omitempty"`
	// RuntimeManagers reports which version manager (if any) is
	// installed for each runtime, e.g. {"python": "pyenv"} on Linux or
	// {"python": "pyenv-win"} on Windows. Empty/missing key means no
	// manager installed; the panel can offer the bootstrap action.
	RuntimeManagers map[string]string `json:"runtime_managers,omitempty"`
	// SystemdJSON indicates whether `systemctl --output=json` is
	// supported (systemd >= 244). When false, list_units falls back to
	// parsing the plain --no-legend table.
	SystemdJSON bool `json:"systemd_json,omitempty"`
	// ProbedAt is the unix milliseconds timestamp when the capabilities
	// payload was computed. Lets the panel distinguish a fresh re-probe
	// from a cached set replayed on reconnect.
	ProbedAt int64 `json:"probed_at,omitempty"`
}

// SystemInfo contains detailed system information
type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	Platform      string `json:"platform,omitempty"`
	Architecture  string `json:"architecture"`
	CPUModel      string `json:"cpu_model,omitempty"`
	CPUCores      int    `json:"cpu_cores"`
	TotalMemory   uint64 `json:"total_memory"`
	TotalDisk     uint64 `json:"total_disk"`
	DockerVersion string `json:"docker_version,omitempty"`
	AgentVersion  string `json:"agent_version"`
}

// Command actions
const (
	// Docker container actions
	ActionDockerContainerList    = "docker:container:list"
	ActionDockerContainerInspect = "docker:container:inspect"
	ActionDockerContainerCreate  = "docker:container:create"
	ActionDockerContainerStart   = "docker:container:start"
	ActionDockerContainerStop    = "docker:container:stop"
	ActionDockerContainerRestart = "docker:container:restart"
	ActionDockerContainerRemove  = "docker:container:remove"
	ActionDockerContainerLogs    = "docker:container:logs"
	ActionDockerContainerStats   = "docker:container:stats"
	ActionDockerContainerExec    = "docker:container:exec"

	// Docker image actions
	ActionDockerImageList   = "docker:image:list"
	ActionDockerImagePull   = "docker:image:pull"
	ActionDockerImageRemove = "docker:image:remove"
	ActionDockerImageBuild  = "docker:image:build"

	// Docker volume actions
	ActionDockerVolumeList   = "docker:volume:list"
	ActionDockerVolumeCreate = "docker:volume:create"
	ActionDockerVolumeRemove = "docker:volume:remove"

	// Docker network actions
	ActionDockerNetworkList   = "docker:network:list"
	ActionDockerNetworkCreate = "docker:network:create"
	ActionDockerNetworkRemove = "docker:network:remove"

	// Docker compose actions
	ActionDockerComposeList    = "docker:compose:list"
	ActionDockerComposePs      = "docker:compose:ps"
	ActionDockerComposeUp      = "docker:compose:up"
	ActionDockerComposeDown    = "docker:compose:down"
	ActionDockerComposeLogs    = "docker:compose:logs"
	ActionDockerComposeRestart = "docker:compose:restart"
	ActionDockerComposePull    = "docker:compose:pull"

	// System actions
	ActionSystemMetrics   = "system:metrics"
	ActionSystemInfo      = "system:info"
	ActionSystemProcesses = "system:processes"
	ActionSystemExec      = "system:exec"

	// Package management actions — Phase 4 primitives the workflow
	// engine sequences for "install Docker", "install LAMP" templates.
	// Linux-only; the agent picks the right manager (apt/dnf/apk/…)
	// based on what's on PATH. Calls are idempotent — installing an
	// already-installed package is a no-op success.
	//
	// Install/Upgrade are long-running and stream progress on the
	// returned job channel ("job:<id>") rather than blocking — the
	// command result returns {job_id, channel} immediately.
	ActionPackagesInstall       = "packages:install"
	ActionPackagesRemove        = "packages:remove"
	ActionPackagesListInstalled = "packages:list_installed"
	ActionPackagesUpdateCache   = "packages:update_cache"
	// ActionPackagesInstallAsync is the streaming variant of
	// ActionPackagesInstall: takes names[] (and/or a single name),
	// returns {job_id, channel} immediately, and emits per-line install
	// progress on the channel. Use this for the Packages tab UI; the
	// synchronous variant is retained for the workflow engine's
	// agent_command nodes which expect a structured result.
	ActionPackagesInstallAsync = "packages:install_async"
	ActionPackagesUpgrade      = "packages:upgrade"
	ActionPackagesSearch       = "packages:search"
	ActionPackagesInfo         = "packages:info"

	// Systemd unit actions. Linux-only and require systemd as PID 1
	// (the capability probe already gates this).
	ActionSystemdStatus       = "systemd:status"
	ActionSystemdStart        = "systemd:start"
	ActionSystemdStop         = "systemd:stop"
	ActionSystemdRestart      = "systemd:restart"
	ActionSystemdEnable       = "systemd:enable"
	ActionSystemdDisable      = "systemd:disable"
	ActionSystemdDaemonReload = "systemd:daemon_reload"
	ActionSystemdListUnits    = "systemd:list_units"
	ActionSystemdLogs         = "systemd:logs"
	ActionSystemdLogsFollow   = "systemd:logs_follow"

	// Runtime version managers (Phase 5). Currently scoped to Python
	// via pyenv on Linux and pyenv-win on Windows. Install/Bootstrap
	// stream on a job channel like packages.
	ActionRuntimesList            = "runtimes:list"
	ActionRuntimesPyenvBootstrap  = "runtimes:pyenv:bootstrap"
	ActionRuntimesPythonInstalled = "runtimes:python:installed"
	ActionRuntimesPythonAvailable = "runtimes:python:available"
	ActionRuntimesPythonInstall   = "runtimes:python:install"
	ActionRuntimesPythonUninstall = "runtimes:python:uninstall"
	ActionRuntimesPythonSetGlobal = "runtimes:python:set_global"
	ActionRuntimesPythonSetLocal  = "runtimes:python:set_local"
	ActionRuntimesPythonCurrent   = "runtimes:python:current"

	// Cron actions — manage entries in the agent host's user crontab.
	// Linux-only; non-Linux agents return an "unsupported" error.
	ActionCronStatus = "cron:status"
	ActionCronList   = "cron:list"
	ActionCronAdd    = "cron:add"
	ActionCronRemove = "cron:remove"
	ActionCronToggle = "cron:toggle"

	// Cloudflared actions — manage Cloudflare named tunnels via the
	// cloudflared CLI. The agent never stores Cloudflare API tokens;
	// the user authenticates once on the host with
	// `cloudflared tunnel login` (approach A from the design notes).
	// Status reflects "is binary installed AND has cert.pem".
	ActionCloudflaredStatus       = "cloudflared:status"
	ActionCloudflaredLogin        = "cloudflared:login"
	ActionCloudflaredTunnelList   = "cloudflared:tunnel:list"
	ActionCloudflaredTunnelCreate = "cloudflared:tunnel:create"
	ActionCloudflaredTunnelRoute  = "cloudflared:tunnel:route"
	ActionCloudflaredTunnelDelete = "cloudflared:tunnel:delete"

	// WireGuard actions — manage a WireGuard interface so the panel can
	// pair two agents into a NAT-traversing tunnel (edge ↔ private). The
	// agent generates its keypair locally and returns ONLY the public
	// key; private keys never reach the panel. Linux-only until the
	// userspace backend (roadmap #6) lands. See
	// docs/REMOTE_ACCESS_ROADMAP.md.
	ActionWireguardKeygen        = "wireguard:keygen"
	ActionWireguardInterfaceUp   = "wireguard:interface:up"
	ActionWireguardInterfaceDown = "wireguard:interface:down"
	ActionWireguardPeerSet       = "wireguard:peer:set"
	ActionWireguardPeerRemove    = "wireguard:peer:remove"
	ActionWireguardStatus        = "wireguard:status"
	// wireguard:forward starts a TCP forwarder on the private peer so a
	// connection arriving over the tunnel reaches the real local service
	// (roadmap #13). Essential for the userspace/netstack backend.
	ActionWireguardForward   = "wireguard:forward"
	ActionWireguardUnforward = "wireguard:unforward"

	// Firewall actions — minimal host-firewall control so the tunnel
	// broker can open the edge's inbound WireGuard UDP port (#10).
	// Linux-only (ufw / firewalld / iptables).
	ActionFirewallAllowPort = "firewall:allow_port"
	ActionFirewallDenyPort  = "firewall:deny_port"

	// File actions
	ActionFileRead  = "file:read"
	ActionFileWrite = "file:write"
	ActionFileList  = "file:list"

	// Terminal/PTY actions
	ActionTerminalCreate = "terminal:create"
	ActionTerminalInput  = "terminal:input"
	ActionTerminalResize = "terminal:resize"
	ActionTerminalClose  = "terminal:close"

	// Agent actions
	ActionAgentUpdate         = "agent:update"
	ActionAgentRecapabilities = "agent:recapabilities"

	// GUI / desktop capture actions. These are the agent-side primitives
	// that panel extensions (e.g. serverkit-gui) call into. Implementation
	// lives in agent/internal/gui — kept minimal so plugins composing
	// remote-desktop / synthetic-UI features don't have to fork the
	// agent.
	ActionGUICapabilities = "gui:capabilities"
	ActionGUIScreenshot   = "gui:screenshot"
)

// Stream channels
const (
	ChannelMetrics        = "metrics"
	ChannelContainerLogs  = "container:%s:logs"
	ChannelContainerStats = "container:%s:stats"
	ChannelTerminal       = "terminal:%s"
	// ChannelSystemdLogs streams journalctl -fu <unit> events. Lifecycle
	// mirrors ChannelContainerLogs: subscribe starts the follow, unsubscribe
	// (or socket close) stops it.
	ChannelSystemdLogs = "systemd:%s:logs"
	// ChannelJob is used for long-running operations (package install,
	// image build, pyenv install) that return {job_id, channel} from
	// their command result and stream progress events on the channel.
	// Late subscribers receive a replay of the last N buffered events.
	ChannelJob = "job:%s"
)

// CredentialUpdateMessage is sent by server to rotate credentials.
//
// HMACSig is computed by the panel as
//
//	hex(HMAC-SHA256("rotation_id:agent_id:new_api_key:new_api_secret",
//	                current_api_secret))
//
// where current_api_secret is the agent's secret prior to rotation.
// The agent recomputes this with its own current secret and rejects
// the rotation if they don't match. This prevents a panel session
// hijack from silently rotating an agent's credential set to ones an
// attacker controls — the existing socket-level auth is necessary but
// not sufficient because the panel has many ways to issue messages
// downward and we want defence-in-depth specifically on the rotation
// path.
type CredentialUpdateMessage struct {
	Message
	RotationID string `json:"rotation_id"`
	APIKey     string `json:"api_key"`
	APISecret  string `json:"api_secret"`
	HMACSig    string `json:"hmac_sig"`
}

// CredentialUpdateAck is sent by agent after updating credentials
type CredentialUpdateAck struct {
	Message
	RotationID string `json:"rotation_id"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

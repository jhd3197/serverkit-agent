// Package permissions defines the agent's local permission levels and the
// single table mapping every panel-issued action to the minimum level that
// may run it. The level is read only from the local config at startup; no
// message from the panel can change it.
package permissions

import (
	"fmt"
	"strings"

	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

// Level is an agent permission level, ordered Monitor < Protect < Full.
type Level string

const (
	// Monitor is report-only: no inbound command channel at all.
	Monitor Level = "monitor"
	// Protect runs only the security allowlist below.
	Protect Level = "protect"
	// Full is the historical behaviour: every registered action.
	Full Level = "full"
)

// Default is used when the config has no permissions.level (legacy installs).
const Default = Full

func (l Level) rank() int {
	switch l {
	case Monitor:
		return 1
	case Protect:
		return 2
	case Full:
		return 3
	}
	return 0
}

// Parse validates a level name (case-insensitive). Empty is an error;
// callers decide whether empty means "default".
func Parse(s string) (Level, error) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	if l.rank() == 0 {
		return "", fmt.Errorf("unknown permission level %q (want monitor, protect or full)", s)
	}
	return l, nil
}

// Describe is the human summary shown by the CLI and installer banners.
func (l Level) Describe() string {
	switch l {
	case Monitor:
		return "report-only: sends metrics and service checks outbound; accepts NO commands from the panel"
	case Protect:
		return "security actions only (firewall, fail2ban, CrowdSec, Cloudflare origin lock); everything else is rejected"
	case Full:
		return "full control: the panel can run any supported action (docker, files, terminal, packages, ...)"
	}
	return "unknown"
}

// protectActions are the only actions that run at level protect.
var protectActions = []string{
	protocol.ActionFirewallAllowPort,
	protocol.ActionFirewallDenyPort,
	protocol.ActionFirewallStatus,
	protocol.ActionFirewallAllowIP,
	protocol.ActionFirewallDenyIP,
	protocol.ActionFail2banStatus,
	protocol.ActionFail2banBan,
	protocol.ActionFail2banUnban,
	protocol.ActionCrowdsecDecisionsList,
	protocol.ActionCrowdsecBan,
	protocol.ActionCrowdsecUnban,
	protocol.ActionCloudflareOriginLockStatus,
	protocol.ActionCloudflareOriginLockApply,
	protocol.ActionCloudflareOriginLockRemove,
}

// fullActions need level full. Every protocol Action constant must appear in
// exactly one of the two lists; TestEveryActionClassified enforces it.
var fullActions = []string{
	protocol.ActionDockerContainerList, protocol.ActionDockerContainerInspect,
	protocol.ActionDockerContainerCreate, protocol.ActionDockerContainerStart,
	protocol.ActionDockerContainerStop, protocol.ActionDockerContainerRestart,
	protocol.ActionDockerContainerRemove, protocol.ActionDockerContainerLogs,
	protocol.ActionDockerContainerStats, protocol.ActionDockerContainerExec,
	protocol.ActionDockerImageList, protocol.ActionDockerImagePull,
	protocol.ActionDockerImageRemove, protocol.ActionDockerImageBuild,
	protocol.ActionDockerVolumeList, protocol.ActionDockerVolumeCreate, protocol.ActionDockerVolumeRemove,
	protocol.ActionDockerNetworkList, protocol.ActionDockerNetworkCreate, protocol.ActionDockerNetworkRemove,
	protocol.ActionDockerComposeList, protocol.ActionDockerComposePs, protocol.ActionDockerComposeUp,
	protocol.ActionDockerComposeDown, protocol.ActionDockerComposeLogs,
	protocol.ActionDockerComposeRestart, protocol.ActionDockerComposePull,
	protocol.ActionSystemMetrics, protocol.ActionSystemInfo, protocol.ActionSystemProcesses, protocol.ActionSystemExec,
	protocol.ActionPackagesInstall, protocol.ActionPackagesRemove, protocol.ActionPackagesListInstalled,
	protocol.ActionPackagesUpdateCache, protocol.ActionPackagesInstallAsync, protocol.ActionPackagesUpgrade,
	protocol.ActionPackagesSearch, protocol.ActionPackagesInfo,
	protocol.ActionSystemdStatus, protocol.ActionSystemdStart, protocol.ActionSystemdStop,
	protocol.ActionSystemdRestart, protocol.ActionSystemdEnable, protocol.ActionSystemdDisable,
	protocol.ActionSystemdDaemonReload, protocol.ActionSystemdListUnits, protocol.ActionSystemdLogs,
	protocol.ActionSystemdLogsFollow,
	protocol.ActionDoctorProbe,
	protocol.ActionRuntimesList, protocol.ActionRuntimesPyenvBootstrap, protocol.ActionRuntimesPythonInstalled,
	protocol.ActionRuntimesPythonAvailable, protocol.ActionRuntimesPythonInstall,
	protocol.ActionRuntimesPythonUninstall, protocol.ActionRuntimesPythonSetGlobal,
	protocol.ActionRuntimesPythonSetLocal, protocol.ActionRuntimesPythonCurrent,
	protocol.ActionCronStatus, protocol.ActionCronList, protocol.ActionCronAdd, protocol.ActionCronRemove,
	protocol.ActionCronToggle, protocol.ActionCronUpdate,
	protocol.ActionCloudflaredStatus, protocol.ActionCloudflaredLogin, protocol.ActionCloudflaredTunnelList,
	protocol.ActionCloudflaredTunnelCreate, protocol.ActionCloudflaredTunnelRoute, protocol.ActionCloudflaredTunnelDelete,
	protocol.ActionWireguardKeygen, protocol.ActionWireguardInterfaceUp, protocol.ActionWireguardInterfaceDown,
	protocol.ActionWireguardPeerSet, protocol.ActionWireguardPeerRemove, protocol.ActionWireguardStatus,
	protocol.ActionWireguardForward, protocol.ActionWireguardUnforward,
	protocol.ActionFileRead, protocol.ActionFileWrite, protocol.ActionFileList,
	protocol.ActionSSHKeysAdd, protocol.ActionSSHKeysRemove, protocol.ActionSSHKeysList,
	protocol.ActionTerminalCreate, protocol.ActionTerminalInput, protocol.ActionTerminalResize, protocol.ActionTerminalClose,
	protocol.ActionAgentUpdate, protocol.ActionAgentRecapabilities,
	protocol.ActionSurveyRead,
	protocol.ActionGUICapabilities, protocol.ActionGUIScreenshot,
}

var required = func() map[string]Level {
	m := make(map[string]Level, len(protectActions)+len(fullActions))
	for _, a := range fullActions {
		m[a] = Full
	}
	for _, a := range protectActions {
		m[a] = Protect
	}
	return m
}()

// Required returns the minimum level for action. Unknown actions need Full
// (default-deny below full); ok reports whether the action is classified.
func Required(action string) (l Level, ok bool) {
	if l, ok = required[action]; ok {
		return l, true
	}
	return Full, false
}

// Allowed reports whether an agent at level may run action. Monitor never
// runs commands. Unknown actions run only at full.
func Allowed(level Level, action string) bool {
	if level == Monitor || level.rank() == 0 {
		return false
	}
	need, _ := Required(action)
	return level.rank() >= need.rank()
}

// Check returns nil if allowed, else the user-facing rejection error.
func Check(level Level, action string) error {
	if Allowed(level, action) {
		return nil
	}
	need, _ := Required(action)
	return fmt.Errorf("action %s requires permission level %s; this agent is configured as %s", action, need, level)
}

// ChannelAllowed gates subscriptions. Only the read-only metrics stream is
// available below full; terminal, logs and job channels need full.
func ChannelAllowed(level Level, channel string) bool {
	switch level {
	case Full:
		return true
	case Protect:
		return channel == protocol.ChannelMetrics
	}
	return false
}

// ProtectActions returns a copy of the protect-level allowlist.
func ProtectActions() []string { return append([]string(nil), protectActions...) }

// KnownActions returns every classified action (for tests and docs).
func KnownActions() []string {
	out := make([]string, 0, len(required))
	for a := range required {
		out = append(out, a)
	}
	return out
}

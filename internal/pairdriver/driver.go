// Package pairdriver runs the agent's pairing protocol: enroll with the
// panel, wait for the operator to claim, persist the resulting credentials.
// It's UI-agnostic — both the legacy walk wizard (setupui) and the
// React-based console wizard (agentui) drive it via callbacks.
package pairdriver

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/metrics"
	"github.com/jhd3197/serverkit-agent/internal/pairing"
)

// passphraseAlphabet excludes confusable characters (0/o/1/i/l) for
// readability. Lowercase so the operator's natural typing matches the
// displayed value — no shift-dance, no caps-lock surprises.
const passphraseAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// GeneratePassphrase returns a fresh 8-char passphrase for an enroll
// request. 8 chars from this 30-char alphabet ≈ 39 bits of entropy, which
// is overkill for a one-shot value that becomes useless once the panel
// claims the agent.
func GeneratePassphrase() (string, error) {
	const n = 8
	max := big.NewInt(int64(len(passphraseAlphabet)))
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = passphraseAlphabet[idx.Int64()]
	}
	return string(buf), nil
}

// Callbacks lets the UI observe state transitions in the pairing driver.
// All callbacks fire on a background goroutine; UI code is responsible for
// marshalling them onto its own thread when relevant.
type Callbacks struct {
	OnEnrolled func(code, formatted string)
	OnClaimed  func(serverName string)
	OnError    func(err error)
}

// Run performs the full enroll → wait-for-claim → save-credentials flow.
// It returns when pairing succeeds, the user cancels (ctx done), or an
// error occurs. All progress is reported via cb.
func Run(
	ctx context.Context,
	log *logger.Logger,
	configPath, panelURL, passphrase, displayName string,
	cb Callbacks,
) {
	panelURL = NormalizePanelURL(panelURL)

	kp, err := pairing.LoadOrCreate(pairing.DefaultKeyPath())
	if err != nil {
		cb.OnError(fmt.Errorf("load keypair: %w", err))
		return
	}

	collector := metrics.NewCollector(config.MetricsConfig{}, log)
	infoCtx, infoCancel := context.WithTimeout(ctx, 8*time.Second)
	sysInfo, _ := collector.GetSystemInfo(infoCtx)
	infoCancel()

	sysMap := buildSystemInfo(sysInfo, displayName)

	client := pairing.NewClient(panelURL, log)
	client.SetKeyPair(kp) // enables Ed25519 proof-of-possession on poll
	enrollCtx, enrollCancel := context.WithTimeout(ctx, 30*time.Second)
	enrollResp, err := client.Enroll(enrollCtx, pairing.EnrollRequest{
		Pubkey:     kp.PublicKeyHex(),
		Passphrase: passphrase,
		MachineID:  config.MachineID(),
		SystemInfo: sysMap,
	})
	enrollCancel()
	if err != nil {
		cb.OnError(fmt.Errorf("enroll: %w", err))
		return
	}

	cb.OnEnrolled(enrollResp.PairCode, enrollResp.PairCodeFormatted)

	creds, err := client.WaitForClaim(ctx, func(code, formatted, _ string) {
		cb.OnEnrolled(code, formatted)
	})
	if err != nil {
		if ctx.Err() != nil {
			return // user cancelled
		}
		cb.OnError(fmt.Errorf("waiting for claim: %w", err))
		return
	}

	if err := saveCredentials(configPath, panelURL, creds); err != nil {
		cb.OnError(fmt.Errorf("save credentials: %w", err))
		return
	}

	cb.OnClaimed(creds.Name)
}

// NormalizePanelURL strips trailing slashes and adds an https:// prefix
// when the user types a bare hostname.
func NormalizePanelURL(u string) string {
	u = strings.TrimSpace(u)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	return strings.TrimSuffix(u, "/")
}

func buildSystemInfo(sysInfo *metrics.SystemInfo, displayName string) map[string]interface{} {
	m := map[string]interface{}{}
	if sysInfo != nil {
		m["hostname"] = sysInfo.Hostname
		m["os"] = sysInfo.OS
		m["platform"] = sysInfo.Platform
		m["platform_version"] = sysInfo.PlatformVersion
		m["architecture"] = sysInfo.Architecture
		m["cpu_cores"] = sysInfo.CPUCores
		m["total_memory"] = sysInfo.TotalMemory
		m["total_disk"] = sysInfo.TotalDisk
	} else {
		hostname, _ := os.Hostname()
		m["hostname"] = hostname
		m["os"] = runtime.GOOS
		m["architecture"] = runtime.GOARCH
	}
	if displayName = strings.TrimSpace(displayName); displayName != "" {
		m["display_name"] = displayName
	}
	return m
}

func saveCredentials(configPath, panelURL string, creds *pairing.Credentials) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.Default()
	}
	wsURL := strings.TrimSuffix(panelURL, "/")
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	cfg.Server.URL = wsURL + "/agent"
	cfg.Agent.ID = creds.AgentID
	cfg.Agent.Name = creds.Name
	cfg.Auth.APIKey = creds.APIKey
	cfg.Auth.APISecret = creds.APISecret

	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	return cfg.SaveCredentials()
}

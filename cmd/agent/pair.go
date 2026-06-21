package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/metrics"
	"github.com/jhd3197/serverkit-agent/internal/pairing"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// pairCmd implements `serverkit-agent pair` — RustDesk-style short-code pairing.
//
// Flags:
//
//	--server, -s   Panel base URL (e.g. https://panel.example.com)
//	--passphrase   Passphrase to set on this agent (will prompt if absent)
//	--headless     No interactive prompts; read passphrase from $SERVERKIT_AGENT_PASSPHRASE
//	--set-passphrase  Write/overwrite passphrase only; don't begin pairing
func pairCmd() *cobra.Command {
	var (
		serverURL      string
		passphrase     string
		headless       bool
		setPassphrase  bool
	)

	cmd := &cobra.Command{
		Use:   "pair",
		Short: "Pair this agent with a ServerKit panel using a short code",
		Long: `Pair this agent with a ServerKit panel.

Generates an Ed25519 keypair (cached at-rest), enrolls with the panel, and
displays a rotating 6-character pair code. An operator enters that code +
the passphrase set here in the panel UI to claim this server. Once claimed,
credentials are saved and the agent is ready to start.

This is the recommended way to add a server. Run 'serverkit-agent register'
only if you have a long pre-shared registration token.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPair(serverURL, passphrase, headless, setPassphrase)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "server", "s", "", "ServerKit panel URL (required, unless previously paired)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase (will prompt if empty)")
	cmd.Flags().BoolVar(&headless, "headless", false, "no interactive prompts; read $SERVERKIT_AGENT_PASSPHRASE")
	cmd.Flags().BoolVar(&setPassphrase, "set-passphrase", false, "store passphrase only; don't pair yet")

	return cmd
}

func runPair(serverURL, passphrase string, headless, setPassphraseOnly bool) error {
	log := logger.New(config.LoggingConfig{Level: "info"})

	// Resolve passphrase
	if passphrase == "" && headless {
		passphrase = os.Getenv("SERVERKIT_AGENT_PASSPHRASE")
		if passphrase == "" {
			return fmt.Errorf("--headless requires SERVERKIT_AGENT_PASSPHRASE env var")
		}
	}
	if passphrase == "" {
		var err error
		passphrase, err = promptPassphrase()
		if err != nil {
			return err
		}
	}
	if len(passphrase) < 4 {
		return fmt.Errorf("passphrase must be at least 4 characters")
	}

	// Persist passphrase reference (for later re-pair flows). We never write
	// the plaintext to disk; we only store a marker so the tray can show
	// "passphrase set". The bcrypt'd canonical form lives on the panel.
	if err := writePassphraseMarker(); err != nil {
		log.Warn("could not write passphrase marker", "error", err)
	}

	if setPassphraseOnly {
		fmt.Println("Passphrase stored. Run 'serverkit-agent pair --server <url>' when ready to pair.")
		return nil
	}

	if serverURL == "" {
		return fmt.Errorf("--server is required (e.g. --server https://panel.example.com)")
	}

	// Load or create Ed25519 pairing keypair
	kp, err := pairing.LoadOrCreate(pairing.DefaultKeyPath())
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}

	// Collect system info
	collector := metrics.NewCollector(config.MetricsConfig{}, log)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sysInfo, _ := collector.GetSystemInfo(ctx)
	sysMap := map[string]interface{}{}
	if sysInfo != nil {
		sysMap = map[string]interface{}{
			"hostname":         sysInfo.Hostname,
			"os":               sysInfo.OS,
			"platform":         sysInfo.Platform,
			"platform_version": sysInfo.PlatformVersion,
			"architecture":     sysInfo.Architecture,
			"cpu_cores":        sysInfo.CPUCores,
			"total_memory":     sysInfo.TotalMemory,
			"total_disk":       sysInfo.TotalDisk,
			"agent_version":    Version,
		}
	} else {
		hostname, _ := os.Hostname()
		sysMap["hostname"] = hostname
		sysMap["os"] = runtime.GOOS
		sysMap["architecture"] = runtime.GOARCH
		sysMap["agent_version"] = Version
	}

	// Enroll
	client := pairing.NewClient(serverURL, log)
	enrollCtx, enrollCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer enrollCancel()

	enrollResp, err := client.Enroll(enrollCtx, pairing.EnrollRequest{
		Pubkey:     kp.PublicKeyHex(),
		Passphrase: passphrase,
		MachineID:  config.MachineID(),
		SystemInfo: sysMap,
	})
	if err != nil {
		return fmt.Errorf("enroll failed: %w", err)
	}

	printPairBanner(enrollResp.PairCodeFormatted, enrollResp.PubkeyFingerprint)

	// Wait for claim (with periodic code rotation)
	claimCtx, claimCancel := context.WithCancel(context.Background())
	defer claimCancel()

	creds, err := client.WaitForClaim(claimCtx, func(code, formatted, expiresAt string) {
		printPairBanner(formatted, enrollResp.PubkeyFingerprint)
	})
	if err != nil {
		return fmt.Errorf("waiting for claim: %w", err)
	}

	// Save credentials and config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		cfg = config.Default()
	}

	wsURL := strings.TrimSuffix(serverURL, "/")
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	cfg.Server.URL = wsURL + "/agent"
	cfg.Agent.ID = creds.AgentID
	cfg.Agent.Name = creds.Name
	cfg.Auth.APIKey = creds.APIKey
	cfg.Auth.APISecret = creds.APISecret

	configPath := cfgFile
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	if cfgFile != "" {
		cfg.Auth.KeyFile = filepath.Join(filepath.Dir(configPath), "agent.key")
	}
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if err := cfg.SaveCredentials(); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Pairing successful!")
	fmt.Printf("  Server name: %s\n", creds.Name)
	fmt.Printf("  Agent ID:    %s\n", creds.AgentID)
	fmt.Printf("  Fingerprint: %s\n", enrollResp.PubkeyFingerprint)
	fmt.Println()
	fmt.Println("Start the agent with: serverkit-agent start")
	return nil
}

func printPairBanner(code, fingerprint string) {
	fmt.Println()
	fmt.Println("┌──────────────────────────────────────────────┐")
	fmt.Println("│   ServerKit Agent — Pairing                  │")
	fmt.Println("├──────────────────────────────────────────────┤")
	fmt.Printf("│   Pair code:   %-30s│\n", code)
	fmt.Printf("│   Fingerprint: %-30s│\n", fingerprint)
	fmt.Println("├──────────────────────────────────────────────┤")
	fmt.Println("│   1. Open ServerKit panel → Add Server       │")
	fmt.Println("│   2. Enter the pair code + your passphrase   │")
	fmt.Println("│   3. Verify the fingerprint matches          │")
	fmt.Println("└──────────────────────────────────────────────┘")
	fmt.Println("Waiting for claim...")
}

func promptPassphrase() (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		// Fallback: read line from stdin (e.g., piped postinst input)
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Passphrase: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Print("Set a passphrase for this agent (4+ chars, you'll need it to pair): ")
	pass, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(pass) != string(pass2) {
		return "", fmt.Errorf("passphrases do not match")
	}
	return string(pass), nil
}

// writePassphraseMarker writes a non-secret marker file used by the tray to
// indicate that a passphrase has been configured. It does NOT contain the
// passphrase itself.
func writePassphraseMarker() error {
	dir := filepath.Dir(pairing.DefaultKeyPath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	marker := filepath.Join(dir, "passphrase.set")
	// Random non-secret token so the file timestamps differ across resets.
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return os.WriteFile(marker, []byte(base64.RawURLEncoding.EncodeToString(buf)), 0600)
}

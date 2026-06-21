package main

import (
	"context"
	"fmt"
	stdlog "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jhd3197/serverkit-agent/internal/agent"
	"github.com/jhd3197/serverkit-agent/internal/agentui"
	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/connstring"
	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/setupui"
	pollclient "github.com/jhd3197/serverkit-agent/internal/transport/poll"
	"github.com/jhd3197/serverkit-agent/internal/tray"
	"github.com/jhd3197/serverkit-agent/internal/updater"
	wsclient "github.com/jhd3197/serverkit-agent/internal/ws"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Mirror Version into every package that surfaces it in user-visible
// strings. ldflags set main.Version, but the agent / ws / poll packages
// each have their own Version var — they were silently drifting, which
// is why the panel UI displayed "ServerKit-Agent-Poll/dev" even when
// `serverkit-agent version` correctly printed the build tag.
func init() {
	if Version != "dev" {
		agent.Version = Version
		wsclient.Version = Version
		pollclient.Version = Version
	}
}

var (
	cfgFile   string
	debugMode bool
	repair    bool
)

func main() {
	attachParentConsole()

	rootCmd := &cobra.Command{
		Use:   "serverkit-agent",
		Short: "ServerKit Agent - Remote server management agent",
		Long: `ServerKit Agent connects your server to a ServerKit control plane,
enabling remote Docker management, monitoring, and more.

When run without a subcommand on Windows, opens the desktop application
(pairing wizard if not configured, otherwise system tray).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDesktop()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&debugMode, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&repair, "repair", false, "force the pairing wizard even if a config already exists")

	// Add commands
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(registerCmd())
	rootCmd.AddCommand(pairCmd())
	rootCmd.AddCommand(setupCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(trayCmd())
	rootCmd.AddCommand(consoleCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the agent service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent()
		},
	}
}

func registerCmd() *cobra.Command {
	var token string
	var serverURL string
	var name string
	var connStr string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register this agent with a ServerKit instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Let the secret-bearing inputs come from the environment so the
			// installer never has to put the registration token in argv —
			// process arguments are world-readable (`ps`, /proc/<pid>/cmdline),
			// whereas a process's environment is readable only by its owner and
			// root. Explicit flags still win when provided.
			if connStr == "" {
				connStr = os.Getenv("SERVERKIT_CONNECTION_STRING")
			}
			if token == "" {
				token = os.Getenv("SERVERKIT_REGISTRATION_TOKEN")
			}
			if serverURL == "" {
				serverURL = os.Getenv("SERVERKIT_SERVER_URL")
			}

			// --connection-string is the modern entry path: a single
			// pasteable blob from the panel that already contains the
			// URL and token. When present, it overrides the legacy
			// flags so users don't have to copy three things.
			if connStr != "" {
				decoded, err := connstring.Decode(connStr)
				if err != nil {
					return fmt.Errorf("invalid connection string: %w", err)
				}
				return runRegister(decoded.Token, decoded.URL, name)
			}
			if token == "" || serverURL == "" {
				return fmt.Errorf("provide either --connection-string or both --token and --server")
			}
			return runRegister(token, serverURL, name)
		},
	}

	// no shorthand: "c" belongs to the global --config persistent flag, and
	// pflag panics on shorthand redefinition the moment any command runs
	cmd.Flags().StringVar(&connStr, "connection-string", "", "panel connection string (single value, replaces --token + --server)")
	cmd.Flags().StringVarP(&token, "token", "t", "", "registration token (use with --server; or set SERVERKIT_REGISTRATION_TOKEN to keep it out of the process arg list)")
	cmd.Flags().StringVarP(&serverURL, "server", "s", "", "ServerKit server URL (use with --token)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "display name for this server")

	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show agent status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showStatus()
		},
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ServerKit Agent\n")
			fmt.Printf("  Version:    %s\n", Version)
			fmt.Printf("  Build Time: %s\n", BuildTime)
			fmt.Printf("  Git Commit: %s\n", GitCommit)
		},
	}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			cfg.Print()
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Show configuration file path",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(config.DefaultConfigPath())
		},
	})

	return cmd
}

func updateCmd() *cobra.Command {
	var forceUpdate bool
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install updates",
		Long: `Check for available updates and optionally install them.

By default, this command checks for updates and prompts before installing.
Use --force to install without prompting.
Use --check to only check for updates without installing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(forceUpdate, checkOnly)
		},
	}

	cmd.Flags().BoolVarP(&forceUpdate, "force", "f", false, "install update without prompting")
	cmd.Flags().BoolVarP(&checkOnly, "check", "c", false, "only check for updates, don't install")

	return cmd
}

func runUpdate(force, checkOnly bool) error {
	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log := logger.New(config.LoggingConfig{Level: "info"})
	u := updater.New(cfg, log, Version)

	ctx := context.Background()

	fmt.Printf("Current version: %s\n", Version)
	fmt.Println("Checking for updates...")

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if !info.UpdateAvailable {
		fmt.Println("You are running the latest version.")
		return nil
	}

	fmt.Printf("\nUpdate available: v%s -> v%s\n", info.CurrentVersion, info.LatestVersion)
	fmt.Printf("Published: %s\n", info.PublishedAt)
	if info.ReleaseNotesURL != "" {
		fmt.Printf("Release notes: %s\n", info.ReleaseNotesURL)
	}

	if checkOnly {
		return nil
	}

	// Prompt for confirmation unless forced
	if !force {
		fmt.Print("\nDo you want to install this update? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Update cancelled.")
			return nil
		}
	}

	fmt.Println("\nDownloading update...")
	binaryPath, err := u.DownloadUpdate(ctx, info)
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}

	fmt.Println("Installing update...")
	if err := u.InstallUpdate(binaryPath); err != nil {
		u.Cleanup(binaryPath)
		return fmt.Errorf("failed to install update: %w", err)
	}

	fmt.Println("\nUpdate installed successfully!")
	fmt.Println("The agent will restart with the new version.")

	return nil
}

func runAgent() error {
	// SCM detection: when launched as a Windows Service, the binary must
	// implement the Service Control dispatcher protocol or SCM kills it
	// with error 1053 within 30s. Older versions of the agent skipped
	// this entirely — every "Start-Service ServerKitAgent" was silently
	// failing while manual `serverkit-agent start` worked, which had
	// users running the agent in foreground console windows as a
	// workaround. Now: if SCM started us, route through svc.Run; if
	// the user ran it from CLI, run directly with signal handling.
	if isWindowsService() {
		return runAsService(agentMainLoop)
	}
	return agentMainLoop(nil)
}

// agentMainLoop is the actual run logic, factored out so both the
// SCM-driven path (svc.Run dispatching to serviceHandler.Execute) and
// the CLI path can share it. Pass nil for ctx to use a fresh
// signal-handled context (CLI mode); pass the SCM-supplied ctx for
// service mode.
func agentMainLoop(parentCtx context.Context) error {
	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override debug mode if flag is set
	if debugMode {
		cfg.Logging.Level = "debug"
	}

	// Initialize logger
	log := logger.New(cfg.Logging)
	log.Info("Starting ServerKit Agent",
		"version", Version,
		"config", config.DefaultConfigPath(),
		"mode", map[bool]string{true: "service", false: "cli"}[isWindowsService()],
	)

	// Loud warning if credentials failed to decrypt. Without surfacing
	// this, the agent would proceed with empty APIKey/APISecret and
	// every panel /connect would 400 "Missing required fields" — which
	// is exactly the silent failure mode that hid this bug for years.
	if cfg.Auth.LoadError != "" && cfg.Agent.ID != "" {
		log.Error("Failed to load credentials — agent cannot authenticate. "+
			"Re-pair the agent (Actions → Open wizard) to regenerate the key file.",
			"error", cfg.Auth.LoadError,
			"key_file", cfg.Auth.KeyFile,
		)
	}

	// Single-instance enforcement for the service. Multiple "start"
	// invocations would fight for IPC port 19780 and the SCM-launched
	// service would lose to a manually-started one (or vice versa) with
	// a 30s timeout in either direction. Mutex is in the Global\
	// namespace because the service runs as SYSTEM and a per-user lock
	// wouldn't catch a user-context "serverkit-agent start" race.
	if alreadyRunning, release := acquireServiceInstance(); alreadyRunning {
		log.Error("Another ServerKit agent service is already running. " +
			"If this is unexpected, end leftover serverkit-agent.exe processes via " +
			"Task Manager (or run `taskkill /F /IM serverkit-agent.exe /T`) and try again.")
		return fmt.Errorf("another agent service is already running (mutex held)")
	} else {
		defer release()
	}

	// Probe the IPC port up-front. If it's held by something else (a
	// stale agent, another tool, anything), fail fast with a clear
	// message instead of letting the IPC server later time out and
	// trip SCM's 1053 "service did not respond" error.
	if cfg.IPC.Enabled {
		probe, perr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.IPC.Port))
		if perr != nil {
			log.Error("IPC port is already in use — likely a leftover serverkit-agent.exe process",
				"port", cfg.IPC.Port, "error", perr)
			return fmt.Errorf("IPC port %d is in use; "+
				"end leftover agent processes (Task Manager → 'serverkit-agent.exe') and try again",
				cfg.IPC.Port)
		}
		// Release the probe — the real IPC server will rebind in a moment.
		// There's a tiny race window where another process could grab the
		// port between probe-close and real-bind, but that's acceptable
		// for what's effectively a "is anyone else here?" check.
		probe.Close()
	}

	// Check if registered
	if cfg.Agent.ID == "" {
		return fmt.Errorf("agent not registered. Run 'serverkit-agent register' first")
	}

	// Build the run context. Service mode supplies its own (cancelled
	// when SCM sends Stop). CLI mode wires SIGINT/SIGTERM as the
	// cancellation signal.
	var ctx context.Context
	var cancel context.CancelFunc
	if parentCtx != nil {
		ctx, cancel = context.WithCancel(parentCtx)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			log.Info("Received shutdown signal", "signal", sig.String())
			cancel()
		}()
	}
	defer cancel()

	ag, err := agent.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	// Start update checker in background
	updateChecker := updater.NewChecker(cfg, log, Version)
	go updateChecker.Start(ctx)

	// Start agent
	if err := ag.Run(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("agent error: %w", err)
	}

	log.Info("Agent stopped gracefully")
	return nil
}

func runRegister(token, serverURL, name string) error {
	log := logger.New(config.LoggingConfig{Level: "info"})

	log.Info("Registering agent with ServerKit",
		"server", serverURL,
	)

	// Load or create config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		// Create new config if doesn't exist
		cfg = config.Default()
	}

	// Register with server
	reg := agent.NewRegistration(log)
	result, err := reg.Register(serverURL, token, name)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Update config
	cfg.Server.URL = result.WebSocketURL
	cfg.Agent.ID = result.AgentID
	cfg.Agent.Name = result.Name
	cfg.Auth.APIKey = result.APIKey
	cfg.Auth.APISecret = result.APISecret

	// Determine config path (use --config flag if set, otherwise default)
	configPath := cfgFile
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}

	// Update key file path to be relative to config directory if using custom path
	if cfgFile != "" {
		cfg.Auth.KeyFile = filepath.Join(filepath.Dir(configPath), "agent.key")
	}

	// Save config (key_file path must be set before saving)
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Save credentials securely
	if err := cfg.SaveCredentials(); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	log.Info("Registration successful!",
		"agent_id", result.AgentID,
		"name", result.Name,
	)

	fmt.Println("\nAgent registered successfully!")
	fmt.Printf("  Agent ID: %s\n", result.AgentID)
	fmt.Printf("  Name:     %s\n", result.Name)
	fmt.Println("\nStart the agent with: serverkit-agent start")

	return nil
}

func showStatus() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		fmt.Println("Status: Not configured")
		fmt.Printf("  Config file not found at %s\n", config.DefaultConfigPath())
		fmt.Println("\nRun 'serverkit-agent register' to configure.")
		return nil
	}

	if cfg.Agent.ID == "" {
		fmt.Println("Status: Not registered")
		fmt.Println("\nRun 'serverkit-agent register' to register with a ServerKit instance.")
		return nil
	}

	fmt.Println("Status: Configured")
	fmt.Printf("  Agent ID:   %s\n", cfg.Agent.ID)
	fmt.Printf("  Agent Name: %s\n", cfg.Agent.Name)
	fmt.Printf("  Server:     %s\n", cfg.Server.URL)

	// TODO: Check if actually connected
	// This would require checking a PID file or socket

	return nil
}

func setupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Open the pairing wizard",
		Long: `Opens the desktop console at the pairing wizard. Enter the panel
URL and a server name; the agent generates a code and passphrase to type
into the panel UI to claim this server.

For headless servers, use 'serverkit-agent pair' instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The wizard now lives inside the React console; setup is a
			// thin alias that opens it. The PairGate component routes the
			// user straight to /pair when no config is present.
			if legacyWizard {
				return runSetup()
			}
			return runConsole()
		},
	}
}

// consoleCmd opens the WebView2-based agent console window. Sibling to the
// `setup` (pairing wizard) command — they coexist while the wizard is being
// migrated to the same React app. Once the wizard lives inside the console,
// `setup` becomes a thin alias that opens the console at the /pair route.
func consoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "console",
		Short: "Open the agent console window (status, logs, actions)",
		Long: `Opens the desktop console for this agent. Shows pairing status,
connection state, recent activity, raw logs, and service controls.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsole()
		},
	}
}

func runConsole() error {
	dbg := openDesktopLog()
	defer dbg.Close()
	dbg.Logf("--- runConsole start, version=%s pid=%d ---", Version, os.Getpid())

	// go-webview2 uses the stdlib log package internally for fatal errors
	// during chromium init. Without this redirect, "Error calling
	// Webview2Loader: ..." goes to a hidden stdout and we'd never see it
	// on a blank-window report. Path is the same desktop.log so all the
	// diagnostic breadcrumbs end up in one file.
	if f := dbg.File(); f != nil {
		stdlog.SetOutput(f)
		stdlog.SetFlags(stdlog.LstdFlags | stdlog.Lmicroseconds)
		stdlog.SetPrefix("[stdlib] ")
	}

	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("ServerKit Agent console crashed:\n\n%v\n\nLog: %s", r, dbg.Path())
			dbg.Logf("PANIC: %v", r)
			showMessageBox("ServerKit Agent", msg, mbIconError)
		}
	}()

	// Point the slog logger at the same desktop.log so internal log.Info
	// calls in agentui land alongside the dbg.Logf trail. Without this, any
	// diagnostic logging from the package goes to a hidden stdout (the
	// console binary uses the windowsgui subsystem) and we end up debugging
	// blank windows blind.
	log := logger.New(config.LoggingConfig{
		Level:      "info",
		File:       dbg.Path(),
		MaxSize:    10,
		MaxBackups: 2,
		MaxAge:     7,
	})

	configPath := cfgFile
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	dbg.Logf("configPath=%s", configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	dbg.Logf("calling agentui.Run …")
	err := agentui.Run(ctx, log, configPath)
	dbg.Logf("agentui.Run returned: %v", err)
	if err != nil {
		showMessageBox("ServerKit Agent",
			fmt.Sprintf("Couldn't open the agent console.\n\n%v\n\nLog: %s", err, dbg.Path()),
			mbIconError)
	}
	return err
}

// runSetup is retained as a fallback into the legacy walk wizard. The
// current setup command points at runConsole, but if WebView2 is somehow
// unavailable on a target machine the user can still pair via this path
// by setting SERVERKIT_AGENT_LEGACY_WIZARD=1.
func runSetup() error {
	dbg := openDesktopLog()
	defer dbg.Close()
	dbg.Logf("--- runSetup (legacy) start, version=%s pid=%d ---", Version, os.Getpid())

	log := logger.New(config.LoggingConfig{Level: "info"})

	configPath := cfgFile
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	return setupui.Run(ctx, log, configPath)
}

// init wires the legacy fallback when explicitly requested, replacing the
// console-based setup runner with the walk wizard. This is purely an escape
// hatch — primary path is the React console.
func init() {
	if os.Getenv("SERVERKIT_AGENT_LEGACY_WIZARD") == "1" {
		legacyWizard = true
	}
}

var legacyWizard bool

// runDesktop is what `serverkit-agent` (no args) does on a desktop install.
// First-run: shows the pairing wizard. Subsequent runs (config exists): goes
// straight to tray. Either way the tray runs after pairing completes.
// runDesktop is what `serverkit-agent` (no args) does on a desktop install.
// Architecture: the tray always runs in this process and is the primary
// entry point — the user-visible app. If the agent is unconfigured (or the
// caller passed --repair) we spawn the pairing wizard as a *separate*
// detached process so the tray is visible immediately and remains the
// recovery surface even if the wizard fails to render.
func runDesktop() error {
	dbg := openDesktopLog()
	defer dbg.Close()
	dbg.Logf("--- runDesktop start, version=%s pid=%d ---", Version, os.Getpid())

	// Single-instance: if a tray is already running for this user, just
	// kick the wizard if needed and exit. Avoids the two-trays-in-one-bar
	// problem when the autostart and a Start-menu click race.
	if alreadyRunning, release := acquireSingleInstance(); alreadyRunning {
		dbg.Logf("another instance is already running; not starting a second tray")
		if repair {
			spawnSetupWizard(dbg)
		}
		return nil
	} else {
		defer release()
	}

	cfg, cfgErr := config.Load(cfgFile)
	dbg.Logf("config.Load err=%v", cfgErr)
	if cfg != nil {
		dbg.Logf("agent.id=%q server.url=%q", cfg.Agent.ID, cfg.Server.URL)
	}

	needsSetup := cfg == nil || cfg.Agent.ID == "" || repair
	dbg.Logf("needsSetup=%v (repair=%v)", needsSetup, repair)

	if needsSetup {
		spawnSetupWizard(dbg)
	}

	dbg.Logf("→ launching tray (needsSetup=%v)", needsSetup)
	return runTrayWithOpts(cfg, needsSetup)
}

func cfgName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.Agent.Name
}

// spawnSetupWizard launches `serverkit-agent setup` as a detached child so
// the wizard runs in its own process and the parent (the tray) is unaffected
// by what happens to the wizard's window. Used both at desktop boot when
// pairing is needed and from the tray's "Open setup wizard…" menu.
func spawnSetupWizard(dbg *desktopLog) {
	exe, err := os.Executable()
	if err != nil {
		if dbg != nil {
			dbg.Logf("spawn: os.Executable err=%v", err)
		}
		return
	}
	cmd := exec.Command(exe, "setup")
	cmd.SysProcAttr = detachedProcessAttrs()
	if err := cmd.Start(); err != nil {
		if dbg != nil {
			dbg.Logf("spawn: cmd.Start err=%v", err)
		}
		return
	}
	if dbg != nil {
		dbg.Logf("spawn: wizard pid=%d started", cmd.Process.Pid)
	}
}

// reopenSetupWizard is the OnOpenSetup callback the tray hands to its menu.
// Same as spawnSetupWizard but without a debug log (the tray runs in the
// long-lived parent process where re-opening logs would be noisy).
func reopenSetupWizard() {
	spawnSetupWizard(nil)
}

func trayCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tray",
		Short: "Run the system tray application",
		Long: `Start the ServerKit Agent system tray application.

The tray app shows the agent status in the system tray and provides
quick access to start/stop the service, view logs, and open the dashboard.

This is typically auto-started on Windows login when installed via MSI.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTray()
		},
	}
}

func runTray() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		cfg = config.Default()
	}
	return runTrayWithOpts(cfg, cfg.Agent.ID == "")
}

func runTrayWithOpts(cfg *config.Config, needsSetup bool) error {
	if cfg == nil {
		cfg = config.Default()
	}

	app := tray.NewApp(tray.AppConfig{
		Version:      Version,
		IPCAddress:   cfg.IPC.Address,
		IPCPort:      cfg.IPC.Port,
		ServerURL:    cfg.Server.URL,
		DashboardURL: getDashboardURL(cfg.Server.URL),
		LogFile:      cfg.Logging.File,
		NeedsSetup:   needsSetup,
		OnOpenSetup:  reopenSetupWizard,
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		app.Quit()
	}()

	app.Run()
	return nil
}

func getDashboardURL(serverURL string) string {
	// Convert WebSocket URL to HTTP dashboard URL
	// wss://server.example.com/ws/agent -> https://server.example.com
	if serverURL == "" {
		return ""
	}
	// Simple conversion - strip /ws/agent suffix and convert wss to https
	url := serverURL
	if len(url) > 4 && url[:4] == "wss:" {
		url = "https:" + url[4:]
	} else if len(url) > 3 && url[:3] == "ws:" {
		url = "http:" + url[3:]
	}
	// Strip path suffix
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' && i > 8 { // After https://
			return url[:i]
		}
	}
	return url
}

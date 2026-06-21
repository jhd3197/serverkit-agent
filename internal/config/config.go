package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all agent configuration
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Agent    AgentConfig    `yaml:"agent"`
	Auth     AuthConfig     `yaml:"auth"`
	Features FeaturesConfig `yaml:"features"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Docker   DockerConfig   `yaml:"docker"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
	Update   UpdateConfig   `yaml:"update"`
	IPC      IPCConfig      `yaml:"ipc"`
}

// ServerConfig holds connection settings
type ServerConfig struct {
	URL                  string        `yaml:"url"`
	ReconnectInterval    time.Duration `yaml:"reconnect_interval"`
	MaxReconnectInterval time.Duration `yaml:"max_reconnect_interval"`
	PingInterval         time.Duration `yaml:"ping_interval"`
	InsecureSkipVerify   bool          `yaml:"insecure_skip_verify"` // For dev only
}

// AgentConfig holds agent identity
type AgentConfig struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// AuthConfig holds authentication credentials
type AuthConfig struct {
	KeyFile   string `yaml:"key_file"`
	APIKey    string `yaml:"api_key,omitempty"`    // Not saved to config file
	APISecret string `yaml:"api_secret,omitempty"` // Not saved to config file
	// LoadError is populated by Load() when LoadCredentials() failed.
	// Surfaced in agent startup logs so "service runs but every /connect
	// returns 400 missing fields" reports become trivial to diagnose
	// (means the key file couldn't be decrypted under any known key).
	LoadError string `yaml:"-"`
}

// FeaturesConfig controls enabled features
type FeaturesConfig struct {
	Docker     bool `yaml:"docker"`
	Metrics    bool `yaml:"metrics"`
	Logs       bool `yaml:"logs"`
	FileAccess bool `yaml:"file_access"`
	Exec       bool `yaml:"exec"`
}

// MetricsConfig controls metrics collection
type MetricsConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Interval          time.Duration `yaml:"interval"`
	IncludePerCPU     bool          `yaml:"include_per_cpu"`
	IncludeDockerStats bool         `yaml:"include_docker_stats"`
}

// DockerConfig holds Docker connection settings
type DockerConfig struct {
	Socket  string        `yaml:"socket"`
	Timeout time.Duration `yaml:"timeout"`
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	AllowedPaths    []string      `yaml:"allowed_paths"`
	BlockedCommands []string      `yaml:"blocked_commands"`
	MaxExecTimeout  time.Duration `yaml:"max_exec_timeout"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
}

// UpdateConfig holds auto-update settings
type UpdateConfig struct {
	Enabled       bool          `yaml:"enabled"`
	CheckInterval time.Duration `yaml:"check_interval"`
	AutoInstall   bool          `yaml:"auto_install"`
}

// IPCConfig holds local IPC server settings for tray app communication
type IPCConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Address string `yaml:"address"`
}

// Default returns default configuration
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			ReconnectInterval:    5 * time.Second,
			MaxReconnectInterval: 5 * time.Minute,
			PingInterval:         30 * time.Second,
		},
		Agent: AgentConfig{},
		Auth: AuthConfig{
			KeyFile: defaultKeyPath(),
		},
		Features: FeaturesConfig{
			Docker:     true,
			Metrics:    true,
			Logs:       true,
			FileAccess: true,
			Exec:       false,
		},
		Metrics: MetricsConfig{
			Enabled:           true,
			Interval:          10 * time.Second,
			IncludePerCPU:     true,
			IncludeDockerStats: true,
		},
		Docker: DockerConfig{
			Socket:  defaultDockerSocket(),
			Timeout: 30 * time.Second,
		},
		Security: SecurityConfig{
			AllowedPaths:    defaultAllowedPaths(),
			BlockedCommands: []string{},
			MaxExecTimeout:  5 * time.Minute,
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       defaultLogPath(),
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   true,
		},
		Update: UpdateConfig{
			Enabled:       true,
			CheckInterval: 1 * time.Hour,
			AutoInstall:   false, // Require manual confirmation by default
		},
		IPC: IPCConfig{
			Enabled: true,
			Port:    19780,
			Address: "127.0.0.1",
		},
	}
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Load credentials from secure storage. We don't fail loading the
	// config if creds are missing — that's normal pre-pairing — but we
	// stash the error on the config so callers running with cfg.Agent.ID
	// set (i.e. should-be-paired) can detect "creds went missing"
	// scenarios that would otherwise silently produce empty auth fields
	// and 400s on every connect attempt.
	if err := cfg.LoadCredentials(); err != nil {
		cfg.Auth.LoadError = err.Error()
	}

	return cfg, nil
}

// Save saves configuration to file
func (c *Config) Save(path string) error {
	if path == "" {
		path = DefaultConfigPath()
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create a copy without sensitive data
	safeCfg := *c
	safeCfg.Auth.APIKey = ""
	safeCfg.Auth.APISecret = ""

	data, err := yaml.Marshal(&safeCfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write with restricted permissions
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Print prints configuration (excluding secrets)
func (c *Config) Print() {
	safeCfg := *c
	safeCfg.Auth.APIKey = "[REDACTED]"
	safeCfg.Auth.APISecret = "[REDACTED]"

	data, _ := yaml.Marshal(&safeCfg)
	fmt.Println(string(data))
}

// SaveCredentials saves API credentials securely
func (c *Config) SaveCredentials() error {
	if c.Auth.APIKey == "" || c.Auth.APISecret == "" {
		return nil
	}

	keyPath := c.Auth.KeyFile
	if keyPath == "" {
		keyPath = defaultKeyPath()
	}

	// Ensure directory exists
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Create credential data
	creds := fmt.Sprintf("%s:%s", c.Auth.APIKey, c.Auth.APISecret)

	// Encrypt credentials using machine-specific key
	encrypted, err := encryptCredentials([]byte(creds))
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Write with restricted permissions
	if err := os.WriteFile(keyPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// LoadCredentials loads API credentials from secure storage. Tries the
// current key derivation first, then falls back to the legacy (pre-1.6.14)
// key that included USERNAME. If the legacy key is what worked, we
// transparently re-encrypt under the current scheme so the next load
// uses the host-stable key — required for the SCM-launched service
// (running as SYSTEM) to read credentials paired by a user-context wizard.
func (c *Config) LoadCredentials() error {
	keyPath := c.Auth.KeyFile
	if keyPath == "" {
		keyPath = defaultKeyPath()
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	decrypted, usedLegacy, err := decryptCredentialsWithMigration(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	// Parse credentials
	var apiKey, apiSecret string
	if _, err := fmt.Sscanf(string(decrypted), "%s:%s", &apiKey, &apiSecret); err != nil {
		// Try splitting by colon
		parts := splitFirst(string(decrypted), ':')
		if len(parts) != 2 {
			return fmt.Errorf("invalid credentials format")
		}
		apiKey = parts[0]
		apiSecret = parts[1]
	}

	c.Auth.APIKey = apiKey
	c.Auth.APISecret = apiSecret

	// Migrate creds onto the host-only key so the next service start
	// (which may run as a different user / SYSTEM) can decrypt them.
	// Best-effort: failure here doesn't block this run.
	if usedLegacy {
		_ = c.SaveCredentials()
	}

	return nil
}

// DefaultConfigPath returns the default config file path
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ServerKit", "Agent", "config.yaml")
	}
	return "/etc/serverkit-agent/config.yaml"
}

func defaultKeyPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ServerKit", "Agent", "agent.key")
	}
	return "/etc/serverkit-agent/agent.key"
}

func defaultDockerSocket() string {
	if runtime.GOOS == "windows" {
		return "npipe:////./pipe/docker_engine"
	}
	return "unix:///var/run/docker.sock"
}

func defaultLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ServerKit", "Agent", "logs", "agent.log")
	}
	return "/var/log/serverkit-agent/agent.log"
}

// IPCTokenPath returns the absolute path to the agent's IPC bearer-token
// file. The token gates the local HTTP API the desktop console and tray
// app use; clients must pass it as `Authorization: Bearer <token>`.
// Living next to the existing key file means it inherits the same 0600
// directory ACLs and ships with the same backup/restore policies.
func IPCTokenPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ServerKit", "Agent", "ipc.token")
	}
	return "/etc/serverkit-agent/ipc.token"
}

func defaultAllowedPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{filepath.Join(os.Getenv("ProgramData"), "ServerKit")}
	}
	return []string{"/var/lib/serverkit", "/var/serverkit"}
}

// getMachineKey generates a machine-specific encryption key.
//
// Stable across user contexts on the same host. The previous derivation
// included USERNAME, which meant credentials encrypted by a user-context
// pairing wizard (juanh) were undecryptable by the SYSTEM-context service
// — agent service started up with empty credentials, every /connect
// returned 400 "Missing required fields". This was masked for years
// because the agent was never actually running as a real Windows service
// (the SCM dispatcher only landed in 1.6.13). Now that it is, the key
// must be host-stable, not user-stable.
func getMachineKey() []byte {
	hostname, _ := os.Hostname()

	var machineID string
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/etc/machine-id")
		if err == nil {
			machineID = string(data)
		}
	} else if runtime.GOOS == "windows" {
		machineID = os.Getenv("COMPUTERNAME")
	}

	combined := fmt.Sprintf("serverkit-agent:%s:%s", hostname, machineID)
	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}

// getMachineKeyLegacyV1 is the pre-1.6.14 derivation (Windows: included
// USERNAME). Kept solely so already-paired agents can decrypt their old
// key file once, re-encrypt under the stable v2 key, and never need it
// again. Drop after a few releases.
func getMachineKeyLegacyV1() []byte {
	hostname, _ := os.Hostname()

	var machineID string
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/etc/machine-id")
		if err == nil {
			machineID = string(data)
		}
	} else if runtime.GOOS == "windows" {
		machineID = os.Getenv("COMPUTERNAME") + os.Getenv("USERNAME")
	}

	combined := fmt.Sprintf("serverkit-agent:%s:%s", hostname, machineID)
	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}

func encryptCredentials(plaintext []byte) ([]byte, error) {
	key := getMachineKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// decryptCredentials tries the current (host-only) machine key first,
// then falls back to the legacy v1 key (host + username) so credentials
// paired before 1.6.14 still load. The bool return indicates whether the
// legacy fallback was used — callers re-encrypt under the stable v2 key
// so the migration only happens once.
func decryptCredentials(data []byte) ([]byte, error) {
	plaintext, _, err := decryptCredentialsWithMigration(data)
	return plaintext, err
}

func decryptCredentialsWithMigration(data []byte) (plaintext []byte, usedLegacy bool, err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, false, err
	}

	if pt, err2 := tryDecrypt(ciphertext, getMachineKey()); err2 == nil {
		return pt, false, nil
	}
	if pt, err2 := tryDecrypt(ciphertext, getMachineKeyLegacyV1()); err2 == nil {
		return pt, true, nil
	}
	return nil, false, fmt.Errorf("decryption failed with both current and legacy machine keys")
}

func tryDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, body, nil)
}

func splitFirst(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// EncryptBytes encrypts bytes using the machine-derived AES-GCM key.
// Exported for use by other internal packages (e.g. pairing keypair storage).
func EncryptBytes(plaintext []byte) ([]byte, error) {
	return encryptCredentials(plaintext)
}

// DecryptBytes decrypts bytes previously encrypted with EncryptBytes.
func DecryptBytes(data []byte) ([]byte, error) {
	return decryptCredentials(data)
}

// MachineID returns a stable per-host identifier suitable for re-pair detection.
func MachineID() string {
	hostname, _ := os.Hostname()
	var id string
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			id = string(data)
		}
	} else if runtime.GOOS == "windows" {
		id = os.Getenv("COMPUTERNAME")
	}
	if id == "" {
		id = hostname
	}
	hash := sha256.Sum256([]byte("serverkit-machine-id:" + hostname + ":" + id))
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

// Package pairing implements the RustDesk-style short-code agent pairing flow.
package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jhd3197/serverkit-agent/internal/config"
)

// KeyPair holds an Ed25519 keypair plus a short fingerprint string.
type KeyPair struct {
	Public      ed25519.PublicKey
	Private     ed25519.PrivateKey
	Fingerprint string // matches panel format: uppercase hex, first 16 chars of SHA-256(pubkey_hex).
}

// PublicKeyHex returns the public key as lowercase hex (64 chars).
func (k *KeyPair) PublicKeyHex() string {
	return hex.EncodeToString(k.Public)
}

// Sign produces an Ed25519 signature over message using the private key.
// Used for pairing proof-of-possession: the panel verifies the signature
// against the enrolled public key before releasing credentials.
func (k *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(k.Private, message)
}

// DefaultKeyPath returns the OS-specific default path for the pairing keyfile.
func DefaultKeyPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ServerKit", "Agent", "pairing.key")
	}
	return "/etc/serverkit-agent/pairing.key"
}

// LoadOrCreate returns the keypair at path, generating + persisting one if
// no file exists. The file is encrypted with the machine-derived key.
func LoadOrCreate(path string) (*KeyPair, error) {
	if path == "" {
		path = DefaultKeyPath()
	}
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	kp, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := Save(kp, path); err != nil {
		return nil, err
	}
	return kp, nil
}

// Generate creates a new random Ed25519 keypair.
func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv, Fingerprint: fingerprint(pub)}, nil
}

// Load reads + decrypts a keypair file.
func Load(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	plain, err := config.DecryptBytes(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt key file: %w", err)
	}
	if len(plain) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key file size: %d", len(plain))
	}
	priv := ed25519.PrivateKey(plain)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{Public: pub, Private: priv, Fingerprint: fingerprint(pub)}, nil
}

// Save encrypts and writes the keypair to disk with restricted permissions.
func Save(kp *KeyPair, path string) error {
	if path == "" {
		path = DefaultKeyPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	encrypted, err := config.EncryptBytes(kp.Private)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

func fingerprint(pub ed25519.PublicKey) string {
	pubHex := hex.EncodeToString(pub)
	digest := sha256.Sum256([]byte(pubHex))
	return strings.ToUpper(hex.EncodeToString(digest[:8]))
}

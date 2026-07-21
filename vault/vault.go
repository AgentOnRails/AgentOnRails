// Package vault manages AES-256-GCM encrypted key files for AgentOnRails.
// Keys are derived from a passphrase using scrypt, stored per-agent in the vault
// directory, and held in memory only during daemon runtime. The vault itself is
// key-type-agnostic — it stores and returns raw bytes; callers are responsible
// for marshalling their own key material (an ECDSA wallet key, an ed25519
// identity key, etc.) to and from bytes.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

const (
	// scrypt parameters — N=2^15 gives ~100ms on modern hardware.
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
	keyLen  = 32 // AES-256

	saltLen  = 32
	nonceLen = 12
)

// Vault handles key storage for a directory of agent wallets.
type Vault struct {
	dir string
}

// New creates a Vault backed by dir. The directory is created if it does not exist.
func New(dir string) (*Vault, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("vault: create dir %s: %w", dir, err)
	}
	return &Vault{dir: dir}, nil
}

// walletKeyName is the key name StoreKey/LoadKey/HasKey/AgentVaultPath use —
// kept as the literal "wallet" so their on-disk filename (wallet.enc) and
// behavior are unchanged for existing callers (the x402 rail).
const walletKeyName = "wallet"

// AgentVaultPath returns the path of the encrypted wallet key file for agentID.
func (v *Vault) AgentVaultPath(agentID string) string {
	return v.namedKeyPath(agentID, walletKeyName)
}

func (v *Vault) namedKeyPath(agentID, keyName string) string {
	return filepath.Join(v.dir, agentID, keyName+".enc")
}

// StoreKey encrypts keyBytes with passphrase and writes it to the vault as
// agentID's wallet key. Equivalent to StoreNamedKey(agentID, "wallet", ...).
func (v *Vault) StoreKey(agentID, passphrase string, keyBytes []byte) error {
	return v.StoreNamedKey(agentID, walletKeyName, passphrase, keyBytes)
}

// LoadKey decrypts and returns agentID's wallet key bytes. Equivalent to
// LoadNamedKey(agentID, "wallet", ...).
func (v *Vault) LoadKey(agentID, passphrase string) ([]byte, error) {
	return v.LoadNamedKey(agentID, walletKeyName, passphrase)
}

// HasKey returns true if agentID has an encrypted wallet key stored.
func (v *Vault) HasKey(agentID string) bool {
	return v.HasNamedKey(agentID, walletKeyName)
}

// StoreNamedKey encrypts keyBytes with passphrase and writes it under
// <agentID>/<keyName>.enc — a second secret (e.g. a card rail's Stripe API
// key) can live alongside the wallet key for the same agent without
// colliding, since each key name gets its own file. The file is created with
// mode 0600 (owner read/write only). keyBytes is caller-defined.
func (v *Vault) StoreNamedKey(agentID, keyName, passphrase string, keyBytes []byte) error {
	agentDir := filepath.Join(v.dir, agentID)
	if err := os.MkdirAll(agentDir, 0700); err != nil {
		return fmt.Errorf("vault: mkdir %s: %w", agentDir, err)
	}

	ciphertext, err := encrypt(keyBytes, passphrase)
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}

	path := v.namedKeyPath(agentID, keyName)
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		return fmt.Errorf("vault: write %s: %w", path, err)
	}
	return nil
}

// LoadNamedKey decrypts and returns the raw bytes stored under keyName for agentID.
func (v *Vault) LoadNamedKey(agentID, keyName, passphrase string) ([]byte, error) {
	path := v.namedKeyPath(agentID, keyName)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}

	keyBytes, err := decrypt(ciphertext, passphrase)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt %s for agent %s: %w (wrong passphrase?)", keyName, agentID, err)
	}
	return keyBytes, nil
}

// HasNamedKey returns true if an encrypted file named keyName exists for agentID.
func (v *Vault) HasNamedKey(agentID, keyName string) bool {
	_, err := os.Stat(v.namedKeyPath(agentID, keyName))
	return err == nil
}

// ─── Encryption helpers ────────────────────────────────────────────────────────

// encrypt uses AES-256-GCM with an scrypt-derived key.
// Output layout: [32-byte salt][12-byte nonce][ciphertext+tag]
func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	aesKey, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, saltLen+nonceLen+len(sealed))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// decrypt reverses encrypt.
func decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltLen+nonceLen {
		return nil, fmt.Errorf("ciphertext too short")
	}

	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ciphertext := data[saltLen+nonceLen:]

	aesKey, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	return plaintext, nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keyLen)
}

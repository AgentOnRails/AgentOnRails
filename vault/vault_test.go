package vault

import (
	"bytes"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func TestStoreAndLoadKey(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := ethcrypto.FromECDSA(key)

	const passphrase = "test-passphrase-123"
	if err := v.StoreKey("test-agent", passphrase, keyBytes); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	loaded, err := v.LoadKey("test-agent", passphrase)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if !bytes.Equal(loaded, keyBytes) {
		t.Error("loaded key does not match stored key")
	}
}

func TestStoreAndLoadKey_ArbitraryBytes(t *testing.T) {
	// The vault is key-type-agnostic — any byte slice round-trips, not just
	// ECDSA keys (e.g. an ed25519 seed).
	dir := t.TempDir()
	v, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	seed := []byte("32-byte-ed25519-seed-material!!")
	if err := v.StoreKey("identity-agent", "pass", seed); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	loaded, err := v.LoadKey("identity-agent", "pass")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !bytes.Equal(loaded, seed) {
		t.Error("loaded bytes do not match stored bytes")
	}
}

func TestLoadKey_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ethcrypto.GenerateKey()
	_ = v.StoreKey("agent", "correct", ethcrypto.FromECDSA(key))

	_, err = v.LoadKey("agent", "wrong")
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestHasKey(t *testing.T) {
	dir := t.TempDir()
	v, _ := New(dir)

	if v.HasKey("missing") {
		t.Error("HasKey should return false for missing agent")
	}

	key, _ := ethcrypto.GenerateKey()
	_ = v.StoreKey("present", "pass", ethcrypto.FromECDSA(key))

	if !v.HasKey("present") {
		t.Error("HasKey should return true after StoreKey")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	plaintext := []byte("secret private key material")
	passphrase := "passphrase"

	ct, err := encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := decrypt(ct, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	if string(pt) != string(plaintext) {
		t.Errorf("decrypt(%q) = %q, want %q", ct, pt, plaintext)
	}
}

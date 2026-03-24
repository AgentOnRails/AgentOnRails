package vault

import (
	"crypto/ecdsa"
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

	const passphrase = "test-passphrase-123"
	if err := v.StoreKey("test-agent", passphrase, key); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	loaded, err := v.LoadKey("test-agent", passphrase)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if loaded.D.Cmp(key.D) != 0 {
		t.Error("loaded key does not match stored key")
	}
}

func TestLoadKey_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ethcrypto.GenerateKey()
	_ = v.StoreKey("agent", "correct", key)

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
	_ = v.StoreKey("present", "pass", key)

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

// Compile-time check: vault uses ecdsa.PrivateKey from go-ethereum.
var _ *ecdsa.PrivateKey = (*ecdsa.PrivateKey)(nil)

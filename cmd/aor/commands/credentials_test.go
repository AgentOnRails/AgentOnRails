package commands

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/gagliardetto/solana-go/base58"
)

func TestParseEd25519Seed_Hex(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	got, err := parseEd25519Seed(hex.EncodeToString(seed))
	if err != nil {
		t.Fatalf("parseEd25519Seed: %v", err)
	}
	if string(got) != string(seed) {
		t.Errorf("got %x, want %x", got, seed)
	}
}

func TestParseEd25519Seed_HexWith0xPrefix(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	got, err := parseEd25519Seed("0x" + hex.EncodeToString(seed))
	if err != nil {
		t.Fatalf("parseEd25519Seed: %v", err)
	}
	if string(got) != string(seed) {
		t.Errorf("got %x, want %x", got, seed)
	}
}

func TestParseEd25519Seed_Base58(t *testing.T) {
	var seedArr [32]byte
	for i := range seedArr {
		seedArr[i] = byte(i * 2)
	}
	encoded := base58.Encode32(&seedArr)

	got, err := parseEd25519Seed(encoded)
	if err != nil {
		t.Fatalf("parseEd25519Seed: %v", err)
	}
	if string(got) != string(seedArr[:]) {
		t.Errorf("got %x, want %x", got, seedArr)
	}
}

func TestParseEd25519Seed_InvalidInput_Errors(t *testing.T) {
	cases := []string{
		"",
		"not a key at all",
		hex.EncodeToString([]byte("too short")),
		"0x" + hex.EncodeToString(make([]byte, 16)), // wrong length hex
	}
	for _, c := range cases {
		if _, err := parseEd25519Seed(c); err == nil {
			t.Errorf("parseEd25519Seed(%q): expected an error, got none", c)
		}
	}
}

func TestParseEd25519Seed_UsableAsKey(t *testing.T) {
	var seedArr [32]byte
	for i := range seedArr {
		seedArr[i] = byte(255 - i)
	}
	encoded := base58.Encode32(&seedArr)

	seed, err := parseEd25519Seed(encoded)
	if err != nil {
		t.Fatalf("parseEd25519Seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
		t.Error("signature produced from parsed seed does not verify")
	}
}

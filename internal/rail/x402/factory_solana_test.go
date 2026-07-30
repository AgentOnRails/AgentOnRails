package x402

import (
	"crypto/ed25519"
	"testing"

	solanago "github.com/gagliardetto/solana-go"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/rail"
	"github.com/agentOnRails/agent-on-rails/vault"
)

// TestFactory_Ed25519KeyType_LoadsRealVaultKey proves Factory's key_type
// branch (not just chainsign/solana's own signing logic, and not just a
// hand-built X402Policy bypassing Factory entirely) actually round-trips a
// real ed25519 seed through the vault the same way the ecdsa path already
// does in factory_approval_test.go's buildTestX402Rail.
func TestFactory_Ed25519KeyType_LoadsRealVaultKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()
	addr := solanago.PrivateKey(priv).PublicKey().String()

	v, err := vault.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StoreKey("solana-agent", "pass", seed); err != nil {
		t.Fatal(err)
	}

	rawYAML := `
enabled: true
key_type: "ed25519"
wallet_address: "` + addr + `"
preferred_chain: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
`
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML), &node); err != nil {
		t.Fatal(err)
	}

	r, enabled, err := Factory(rail.FactoryParams{
		AgentID:    "solana-agent",
		RawConfig:  *node.Content[0],
		Vault:      v,
		Passphrase: "pass",
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if !enabled {
		t.Fatal("expected Factory to report enabled")
	}

	xr := r.(*X402Rail)
	if xr.policy.PrivateKey != nil {
		t.Error("expected PrivateKey (ECDSA) to be nil for an ed25519 agent")
	}
	if len(xr.policy.Ed25519Key) == 0 {
		t.Fatal("expected Ed25519Key to be set")
	}
	if got := solanago.PrivateKey(xr.policy.Ed25519Key).PublicKey().String(); got != addr {
		t.Errorf("loaded key derives to address %s, want %s", got, addr)
	}
}

func TestFactory_Ed25519KeyType_WalletAddressMismatch_Errors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	v, err := vault.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StoreKey("solana-agent", "pass", priv.Seed()); err != nil {
		t.Fatal(err)
	}

	rawYAML := `
enabled: true
key_type: "ed25519"
wallet_address: "` + solanago.SystemProgramID.String() + `"
`
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML), &node); err != nil {
		t.Fatal(err)
	}

	_, _, err = Factory(rail.FactoryParams{
		AgentID:    "solana-agent",
		RawConfig:  *node.Content[0],
		Vault:      v,
		Passphrase: "pass",
	})
	if err == nil {
		t.Fatal("expected a wallet-address-mismatch error")
	}
}

func TestFactory_Ed25519KeyType_WrongSeedLength_Errors(t *testing.T) {
	v, err := vault.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A raw ECDSA-shaped key (32 bytes happens to be the same length as an
	// ed25519 seed) stored under an agent configured as ed25519 should
	// still be rejected if it's not actually a valid stored form — this
	// specific case (right length, but see ParseRailConfig's own key_type
	// enum check for the wrong-VALUE case) covers a too-short/too-long
	// stored key instead.
	if err := v.StoreKey("solana-agent", "pass", []byte("too-short")); err != nil {
		t.Fatal(err)
	}

	rawYAML := `
enabled: true
key_type: "ed25519"
wallet_address: "` + solanago.TokenProgramID.String() + `"
`
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML), &node); err != nil {
		t.Fatal(err)
	}

	_, _, err = Factory(rail.FactoryParams{
		AgentID:    "solana-agent",
		RawConfig:  *node.Content[0],
		Vault:      v,
		Passphrase: "pass",
	})
	if err == nil {
		t.Fatal("expected an error for a stored key that isn't a valid ed25519 seed")
	}
}

func TestParseRailConfig_InvalidKeyType_Errors(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(`
enabled: true
wallet_address: "x"
key_type: "rsa"
`), &node); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRailConfig(*node.Content[0]); err == nil {
		t.Fatal("expected an error for an unrecognized key_type")
	}
}

func TestParseRailConfig_EmptyKeyType_DefaultsToECDSA(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(`
enabled: true
wallet_address: "0xabc"
`), &node); err != nil {
		t.Fatal(err)
	}
	rc, err := ParseRailConfig(*node.Content[0])
	if err != nil {
		t.Fatal(err)
	}
	if rc.KeyType != KeyTypeECDSA {
		t.Errorf("KeyType = %q, want %q (default)", rc.KeyType, KeyTypeECDSA)
	}
}

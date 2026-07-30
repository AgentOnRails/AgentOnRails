package x402chain

import (
	"testing"

	_ "github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign/eip155"
	_ "github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign/solana"
)

func TestNamespace(t *testing.T) {
	cases := map[string]string{
		"eip155:8453":         "eip155",
		"eip155:84532":        "eip155",
		"solana:mainnet-beta": "solana",
		"no-colon-at-all":     "no-colon-at-all",
		"":                    "",
	}
	for network, want := range cases {
		if got := Namespace(network); got != want {
			t.Errorf("Namespace(%q) = %q, want %q", network, got, want)
		}
	}
}

func TestSupported_RegisteredNamespaces(t *testing.T) {
	for _, network := range []string{"eip155:8453", "eip155:84532", "solana:mainnet-beta", "solana:devnet"} {
		if !Supported(network) {
			t.Errorf("Supported(%q) = false, want true — eip155 and solana are both registered by this test's blank imports", network)
		}
	}
}

func TestSupported_UnregisteredNamespace(t *testing.T) {
	if Supported("bitcoin:000000000019d6689c085ae165831e93") {
		t.Error("Supported(bitcoin:...) = true, want false — no chainsign.Signer is registered for bitcoin")
	}
}

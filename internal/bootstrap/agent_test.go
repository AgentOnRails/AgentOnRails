package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// writeMinimalAorYAML writes just enough aor.yaml for config.LoadGlobal to
// succeed, with the vault directory pointed inside aorDir so the test never
// touches a real ~/.aor.
func writeMinimalAorYAML(t *testing.T, aorDir string) {
	t.Helper()
	content := fmt.Sprintf("daemon:\n  vault_dir: %q\n", filepath.Join(aorDir, "vaults"))
	if err := os.WriteFile(filepath.Join(aorDir, "aor.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("write aor.yaml: %v", err)
	}
}

func TestCreateFundable_GeneratesThenReusesWallet(t *testing.T) {
	aorDir := t.TempDir()
	writeMinimalAorYAML(t, aorDir)

	opts := AgentOptions{
		AgentID:       "test-agent",
		ProxyPort:     9999,
		Network:       BaseSepoliaNetwork,
		DailyLimitUSD: "1.00",
		PerCallMaxUSD: "0.05",
	}

	addr1, pass1, err := CreateFundable(aorDir, opts)
	if err != nil {
		t.Fatalf("CreateFundable (first run): %v", err)
	}
	if addr1 == (common.Address{}) {
		t.Fatal("expected a non-zero wallet address")
	}

	agentPath := filepath.Join(aorDir, "agents", "test-agent.yaml")
	yamlBytes, err := os.ReadFile(agentPath)
	if err != nil {
		t.Fatalf("expected agent config written at %s: %v", agentPath, err)
	}
	if !strings.Contains(string(yamlBytes), addr1.Hex()) {
		t.Errorf("agent config does not contain wallet address %s:\n%s", addr1.Hex(), yamlBytes)
	}

	// A second call for the same AgentOptions must reuse the same wallet and
	// passphrase, not silently mint a new (unfunded) one — this is the exact
	// property scripts/demo and scripts/hermes-quickstart depend on so
	// re-running them doesn't require re-claiming a testnet faucet.
	addr2, pass2, err := CreateFundable(aorDir, opts)
	if err != nil {
		t.Fatalf("CreateFundable (second run): %v", err)
	}
	if addr2 != addr1 {
		t.Errorf("second CreateFundable generated a different wallet: %s != %s (should reuse)", addr2.Hex(), addr1.Hex())
	}
	if pass2 != pass1 {
		t.Error("second CreateFundable generated a different passphrase (should reuse)")
	}
}

func TestCreateFundable_CustomPassphraseFileIsHonored(t *testing.T) {
	aorDir := t.TempDir()
	writeMinimalAorYAML(t, aorDir)

	opts := AgentOptions{
		AgentID:        "custom-agent",
		ProxyPort:      9998,
		Network:        BaseSepoliaNetwork,
		DailyLimitUSD:  "1.00",
		PerCallMaxUSD:  "0.05",
		PassphraseFile: "legacy-passphrase",
	}
	if _, _, err := CreateFundable(aorDir, opts); err != nil {
		t.Fatalf("CreateFundable: %v", err)
	}

	if _, err := os.Stat(filepath.Join(aorDir, "legacy-passphrase")); err != nil {
		t.Errorf("expected passphrase stored at the overridden filename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(aorDir, "custom-agent-passphrase")); !os.IsNotExist(err) {
		t.Error("did not expect a default-named passphrase file when PassphraseFile is set")
	}
}

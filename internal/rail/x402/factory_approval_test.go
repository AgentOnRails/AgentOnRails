package x402

import (
	"context"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/approval"
	"github.com/agentOnRails/agent-on-rails/rail"
	"github.com/agentOnRails/agent-on-rails/vault"
)

// buildTestX402Rail builds a real *X402Rail via Factory, with a real vault
// key backing it — the same setup test/e2e's daemon tests use — so this
// exercises Factory's actual wiring, not a hand-constructed policy.
func buildTestX402Rail(t *testing.T, rawYAML string, approvals *approval.Registry) *X402Rail {
	t.Helper()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()

	v, err := vault.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StoreKey("agent-a", "pass", ethcrypto.FromECDSA(key)); err != nil {
		t.Fatal(err)
	}

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML+"\nwallet_address: \""+addr+"\"\n"), &node); err != nil {
		t.Fatal(err)
	}

	r, enabled, err := Factory(rail.FactoryParams{
		AgentID:    "agent-a",
		RawConfig:  *node.Content[0],
		Vault:      v,
		Passphrase: "pass",
		Approvals:  approvals,
	})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if !enabled {
		t.Fatal("expected Factory to report enabled")
	}
	return r.(*X402Rail)
}

func TestFactory_NoApprovalsRegistry_ApprovalFuncNil(t *testing.T) {
	xr := buildTestX402Rail(t, `
enabled: true
require_approval_above_usd: "10.00"
`, nil)
	if xr.policy.ApprovalFunc != nil {
		t.Error("expected ApprovalFunc to stay nil when FactoryParams.Approvals is nil — unchanged, fail-closed behavior")
	}
}

func TestFactory_WithApprovalsRegistry_ApprovalFuncWired(t *testing.T) {
	registry := approval.NewRegistry()
	xr := buildTestX402Rail(t, `
enabled: true
require_approval_above_usd: "10.00"
`, registry)

	if xr.policy.ApprovalFunc == nil {
		t.Fatal("expected ApprovalFunc to be wired when FactoryParams.Approvals is set")
	}

	// Resolve concurrently, then confirm the wired ApprovalFunc actually
	// routes through the shared registry (not some no-op stand-in).
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			pending := registry.List()
			if len(pending) == 1 {
				registry.Resolve(pending[0].ID, true) //nolint:errcheck
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	approved, err := xr.policy.ApprovalFunc(context.Background(), ApprovalRequest{
		AgentID:     "agent-a",
		Endpoint:    "https://api.example.com/paid",
		AmountCents: 1500,
		TaskContext: "test",
	})
	if err != nil {
		t.Fatalf("ApprovalFunc: %v", err)
	}
	if !approved {
		t.Error("expected the wired ApprovalFunc to report approved=true")
	}
}

func TestFactory_ApprovalTimeoutConfig_Wired(t *testing.T) {
	xr := buildTestX402Rail(t, `
enabled: true
require_approval_above_usd: "10.00"
approval_timeout_sec: 7
`, approval.NewRegistry())

	if xr.policy.ApprovalTimeout != 7*time.Second {
		t.Errorf("ApprovalTimeout = %v, want 7s", xr.policy.ApprovalTimeout)
	}
}

func TestFactory_ApprovalTimeoutConfig_DefaultsToZero(t *testing.T) {
	// Zero means "let approval.Await fall back to approval.DefaultTimeout"
	// — Factory/BuildPolicy don't hardcode that value themselves.
	xr := buildTestX402Rail(t, `
enabled: true
require_approval_above_usd: "10.00"
`, approval.NewRegistry())

	if xr.policy.ApprovalTimeout != 0 {
		t.Errorf("ApprovalTimeout = %v, want 0 (defer to approval.DefaultTimeout)", xr.policy.ApprovalTimeout)
	}
}

func TestFactory_DeniedApproval_ReturnsFalse(t *testing.T) {
	registry := approval.NewRegistry()
	xr := buildTestX402Rail(t, `
enabled: true
require_approval_above_usd: "10.00"
`, registry)

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			pending := registry.List()
			if len(pending) == 1 {
				registry.Resolve(pending[0].ID, false) //nolint:errcheck
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	approved, err := xr.policy.ApprovalFunc(context.Background(), ApprovalRequest{AgentID: "agent-a", AmountCents: 1500})
	if err != nil {
		t.Fatalf("ApprovalFunc: %v", err)
	}
	if approved {
		t.Error("expected approved=false when the registry denies the request")
	}
}

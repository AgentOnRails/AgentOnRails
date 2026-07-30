package x402

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/agentOnRails/agent-on-rails/approval"
)

// TestProxyRequest_ApprovalGate_BlocksThenApproves is the end-to-end proof
// for the gap CHANGELOG.md's [0.1.0] entry describes: before this, a real
// request hitting RequireApprovalAboveCents with no ApprovalFunc failed
// closed permanently — this drives one real HTTP request all the way
// through ProxyRequest with a real approval.Registry wired in exactly the
// way Factory now does, resolves it from a separate goroutine (standing in
// for the control API's approve handler, which calls the exact same
// Registry.Resolve), and confirms the ORIGINAL held request goes on to
// complete successfully — not just that ApprovalFunc is reachable in
// isolation (see factory_approval_test.go for that narrower check).
func TestProxyRequest_ApprovalGate_BlocksThenApproves(t *testing.T) {
	payTo := "0x" + strings.Repeat("f", 40)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerV1Payment) == "" {
			challenge := map[string]any{
				"x402Version": 1,
				"accepts": []map[string]any{{
					"scheme":            "exact",
					"network":           "base-sepolia",
					"maxAmountRequired": "1500000", // $1.50 — above the $1.00 approval threshold below
					"asset":             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
					"payTo":             payTo,
					"maxTimeoutSeconds": 60,
					"extra":             map[string]any{"name": "USDC", "version": "2"},
				}},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(challenge)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"paid content"}`))
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	registry := approval.NewRegistry()
	policy := &X402Policy{
		PrivateKey:                key,
		WalletAddress:             addr.Hex(),
		PreferredChain:            "eip155:84532",
		DailyLimitCents:           1_000_00,
		RequireApprovalAboveCents: 100, // $1.00
		UpstreamTimeout:           5 * time.Second,
		FacilitatorTimeout:        5 * time.Second,
		PayloadTTL:                60 * time.Second,
		EndpointMode:              "open",
		SkipPreVerify:             true,
		ApprovalTimeout:           2 * time.Second,
		ApprovalFunc: func(ctx context.Context, req ApprovalRequest) (bool, error) {
			return registry.Await(ctx, approval.Request{
				AgentID:     "test-agent",
				RailType:    "x402",
				Endpoint:    req.Endpoint,
				AmountCents: req.AmountCents,
				TaskContext: req.TaskContext,
			}, 2*time.Second)
		},
	}

	rail, err := NewX402Rail(policy, &noopAuditLogger{}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/paid", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		rail.ProxyRequest(context.Background(), w, req, "test-agent", "")
		close(done)
	}()

	// The request must actually be held, not complete instantly — confirm
	// it's still in flight (registry sees it) before resolving it, so this
	// test can't pass by accident if the gate were a no-op.
	select {
	case <-done:
		t.Fatal("ProxyRequest returned before the approval was ever resolved — the gate did not hold the request")
	case <-time.After(50 * time.Millisecond):
	}

	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pending := registry.List()
		if len(pending) == 1 {
			id = pending[0].ID
			if pending[0].AmountCents != 150 {
				t.Errorf("pending AmountCents = %d, want 150 ($1.50)", pending[0].AmountCents)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == "" {
		t.Fatal("approval never appeared in the registry")
	}

	// This is exactly what the daemon's control API's
	// POST /control/approvals/{id}/approve handler does.
	if err := registry.Resolve(id, true); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ProxyRequest did not return after the approval was resolved")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body := w.Body.String()
		t.Fatalf("status = %d, want 200 (payment should have proceeded after approval): %s", resp.StatusCode, body)
	}
}

// TestProxyRequest_ApprovalGate_Denied_Blocks404s confirms the other half:
// a denied approval fails the request rather than letting it through.
func TestProxyRequest_ApprovalGate_Denied_BlocksRequest(t *testing.T) {
	payTo := "0x" + strings.Repeat("f", 40)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := map[string]any{
			"x402Version": 1,
			"accepts": []map[string]any{{
				"scheme":            "exact",
				"network":           "base-sepolia",
				"maxAmountRequired": "1500000",
				"asset":             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
				"payTo":             payTo,
				"maxTimeoutSeconds": 60,
				"extra":             map[string]any{"name": "USDC", "version": "2"},
			}},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(challenge)
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	registry := approval.NewRegistry()
	policy := &X402Policy{
		PrivateKey:                key,
		WalletAddress:             addr.Hex(),
		PreferredChain:            "eip155:84532",
		DailyLimitCents:           1_000_00,
		RequireApprovalAboveCents: 100,
		UpstreamTimeout:           5 * time.Second,
		FacilitatorTimeout:        5 * time.Second,
		PayloadTTL:                60 * time.Second,
		EndpointMode:              "open",
		SkipPreVerify:             true,
		ApprovalFunc: func(ctx context.Context, req ApprovalRequest) (bool, error) {
			return registry.Await(ctx, approval.Request{AgentID: "test-agent", AmountCents: req.AmountCents}, 2*time.Second)
		},
	}

	rail, err := NewX402Rail(policy, &noopAuditLogger{}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/paid", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		rail.ProxyRequest(context.Background(), w, req, "test-agent", "")
		close(done)
	}()

	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pending := registry.List()
		if len(pending) == 1 {
			id = pending[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == "" {
		t.Fatal("approval never appeared in the registry")
	}
	if err := registry.Resolve(id, false); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ProxyRequest did not return after the denial was resolved")
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (denied)", resp.StatusCode)
	}
}

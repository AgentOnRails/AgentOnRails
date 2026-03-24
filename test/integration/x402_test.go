// Package integration contains end-to-end tests for the x402 payment rail.
// These tests spin up mock upstream servers and run the full proxy pipeline —
// policy check → sign → retry → audit log — without touching any real blockchain.
//
// Run with: go test ./test/integration/ -v -count=1
// (No external services required for these tests.)
package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// ─── Test helpers ──────────────────────────────────────────────────────────────

// mockX402Server returns an httptest.Server that:
//   - Returns 402 with a PAYMENT-REQUIRED challenge on requests without PAYMENT-SIGNATURE
//   - Returns 200 with PAYMENT-RESPONSE when a PAYMENT-SIGNATURE is present
func mockX402Server(t *testing.T, network, amount, payTo string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") == "" {
			// Issue a 402 challenge
			challenge := x402.PaymentRequired{
				X402Version: 2,
				Accepts: []x402.PaymentRequirement{
					{
						Scheme:            "exact",
						Network:           network,
						Amount:            amount,
						Asset:             knownUSDCAddress(network),
						PayTo:             payTo,
						MaxTimeoutSeconds: 60,
						Extra:             map[string]any{"name": "USDC", "version": "2"},
					},
				},
			}
			data, _ := json.Marshal(challenge)
			w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}

		// Payment accepted — return 200 with a fake settlement response
		resp := x402.PaymentResponse{
			Success:     true,
			Transaction: "0xfakedeadbeef1234567890abcdef",
			Network:     network,
			Payer:       "0x" + strings.Repeat("a", 40),
		}
		data, _ := json.Marshal(resp)
		w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(data))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	}))
}

// mockFacilitatorServer returns a facilitator that always approves.
func mockFacilitatorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := x402.FacilitatorVerifyResponse{IsValid: true, Payer: "0x" + strings.Repeat("b", 40)}
		json.NewEncoder(w).Encode(resp)
	}))
}

// newTestRail creates an X402Rail wired to a temp SQLite DB for testing.
func newTestRail(t *testing.T, policy *x402.X402Policy, dbPath string) (*x402.X402Rail, *audit.SQLiteAuditLogger) {
	t.Helper()
	db, err := audit.NewSQLiteAuditLogger(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteAuditLogger: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	logger := zap.NewNop()
	rail, err := x402.NewX402Rail(policy, db, logger)
	if err != nil {
		t.Fatalf("NewX402Rail: %v", err)
	}
	return rail, db
}

func testPolicy(t *testing.T, facilitatorURL string) *x402.X402Policy {
	t.Helper()
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	return &x402.X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		FacilitatorURL:     facilitatorURL,
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true, // skip by default; opt-in per test
	}
}

func knownUSDCAddress(network string) string {
	switch network {
	case "eip155:84532":
		return "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	case "eip155:8453":
		return "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	default:
		return "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	}
}

// ─── Happy path ────────────────────────────────────────────────────────────────

// TestHappyPath verifies the full x402 flow:
// agent → proxy → 402 challenge → sign → retry → 200 → audit log entry
func TestHappyPath(t *testing.T) {
	facilitator := mockFacilitatorServer(t)
	defer facilitator.Close()

	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	policy := testPolicy(t, facilitator.URL)
	policy.SkipPreVerify = true

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, db := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "test-task")

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Verify audit log entry was written
	time.Sleep(10 * time.Millisecond) // allow deferred log write
	txns, err := db.QueryTransactions("test-agent", time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(txns))
	}
	tx := txns[0]
	if tx.Status != "allowed" {
		t.Errorf("status = %q, want %q", tx.Status, "allowed")
	}
	if tx.TxHash == "" {
		t.Error("tx_hash should be populated from PAYMENT-RESPONSE")
	}
	if tx.AmountUSD != 0.01 {
		t.Errorf("amount_usd = %.4f, want 0.01 (10000 atomic units / 10000)", tx.AmountUSD)
	}
	if tx.Network != "eip155:84532" {
		t.Errorf("network = %q, want %q", tx.Network, "eip155:84532")
	}
}

// TestFreeEndpoint verifies that non-402 responses are passed through unchanged.
func TestFreeEndpoint(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Free", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("free content"))
	}))
	defer upstream.Close()

	policy := testPolicy(t, "http://localhost:0")
	policy.SkipPreVerify = true

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, db := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/free", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("X-Free") != "yes" {
		t.Error("response headers not forwarded")
	}

	// Audit record should show $0 (passthrough)
	txns, _ := db.QueryTransactions("agent", time.Time{}, 10)
	if len(txns) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(txns))
	}
	if txns[0].AmountUSD != 0 {
		t.Errorf("free endpoint should have 0 amount, got %.4f", txns[0].AmountUSD)
	}
}

// ─── Policy enforcement ────────────────────────────────────────────────────────

// TestAllowlistBlock verifies that requests to hosts not on the allowlist are blocked.
func TestAllowlistBlock(t *testing.T) {
	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	policy := testPolicy(t, "http://localhost:0")
	policy.EndpointMode = "allowlist"
	policy.AllowedHosts = []string{"allowed-api.example.com"} // upstream is 127.0.0.1, not in list

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, db := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "endpoint_not_on_allowlist") {
		t.Errorf("expected allowlist error, got: %s", w.Body.String())
	}

	// Audit record should show blocked status
	txns, _ := db.QueryTransactions("agent", time.Time{}, 10)
	if len(txns) == 1 && txns[0].Status != "blocked" {
		t.Errorf("audit status = %q, want blocked", txns[0].Status)
	}
}

// TestBlocklistBlock verifies that requests to blocked hosts are rejected.
func TestBlocklistBlock(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Extract the host (127.0.0.1) from the upstream URL
	host := strings.TrimPrefix(upstream.URL, "http://")
	host = strings.Split(host, ":")[0] // just the IP

	policy := testPolicy(t, "http://localhost:0")
	policy.EndpointMode = "blocklist"
	policy.BlockedHosts = []string{host}

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// TestPerCallMaxBlock verifies that payments above per_call_max are rejected.
func TestPerCallMaxBlock(t *testing.T) {
	upstream := mockX402Server(t, "eip155:84532", "1000000", "0x"+strings.Repeat("c", 40)) // $1.00
	defer upstream.Close()

	policy := testPolicy(t, "http://localhost:0")
	policy.PerCallMaxCents = 50 // $0.50 max per call

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (per-call max exceeded)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "per-call max") {
		t.Errorf("expected per-call max error, got: %s", w.Body.String())
	}
}

// TestDailyBudgetExhaustion verifies that requests are blocked after daily budget is exhausted.
func TestDailyBudgetExhaustion(t *testing.T) {
	facilitator := mockFacilitatorServer(t)
	defer facilitator.Close()

	// Each request costs $0.01 (10000 atomic units). Daily limit is $0.02 (2 cents).
	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	policy := testPolicy(t, facilitator.URL)
	policy.SkipPreVerify = true
	policy.DailyLimitCents = 2 // $0.02

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	makeRequest := func() int {
		req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
		req.RequestURI = ""
		w := httptest.NewRecorder()
		rail.ProxyRequest(context.Background(), w, req, "agent", "")
		return w.Code
	}

	// First two requests should succeed (1 cent each = 2 cents total = limit)
	if code := makeRequest(); code != http.StatusOK {
		t.Fatalf("request 1: status = %d, want 200", code)
	}
	if code := makeRequest(); code != http.StatusOK {
		t.Fatalf("request 2: status = %d, want 200", code)
	}

	// Third request should be blocked by daily budget
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req3.RequestURI = ""
	rail.ProxyRequest(context.Background(), w3, req3, "agent", "")

	if w3.Code != http.StatusForbidden {
		t.Errorf("request 3: status = %d, want 403 (budget exhausted)", w3.Code)
	}
	if !strings.Contains(w3.Body.String(), "daily budget exceeded") {
		t.Errorf("expected daily budget error, got: %s", w3.Body.String())
	}
}

// TestVelocityExhaustion verifies that the velocity limiter blocks after max_per_minute.
func TestVelocityExhaustion(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Use a fresh rail — default velocity limit is 30/min.
	policyLow := testPolicy(t, "http://localhost:0")
	policyLow.SkipPreVerify = true
	railLow, _ := newTestRail(t, policyLow, filepath.Join(t.TempDir(), "vel.db"))

	// Send 30 requests quickly — they all pass (free endpoint, no velocity hit yet)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("GET", upstream.URL+"/", nil)
		req.RequestURI = ""
		w := httptest.NewRecorder()
		railLow.ProxyRequest(context.Background(), w, req, "agent", "")
	}

	// 31st should hit velocity limit
	req := httptest.NewRequest("GET", upstream.URL+"/", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()
	railLow.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d after velocity limit, want 429", w.Code)
	}
}

// TestBudgetRefundOnSigningFailure verifies that if the signing fails (e.g. bad
// network in requirement), the reserved budget is returned.
func TestBudgetRefundOnUnknownNetwork(t *testing.T) {
	// Upstream offers an unknown network that signing will reject
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") == "" {
			challenge := x402.PaymentRequired{
				X402Version: 2,
				Accepts: []x402.PaymentRequirement{
					{
						Network: "eip155:99999", // unknown — selectRequirement will fail
						Amount:  "10000",
					},
				},
			}
			data, _ := json.Marshal(challenge)
			w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
			w.WriteHeader(http.StatusPaymentRequired)
		}
	}))
	defer upstream.Close()

	policy := testPolicy(t, "http://localhost:0")
	policy.DailyLimitCents = 1000

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()
	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (no acceptable network)", w.Code)
	}

	// Budget should not have been decremented (no reserve happened before failure)
	spent := rail.Budget().SpentThisPeriod("daily")
	if spent != 0 {
		t.Errorf("daily spent = %d after unknown-network failure, want 0", spent)
	}
}

// TestPreVerifyEnabled verifies that the facilitator /verify endpoint is called
// when SkipPreVerify is false.
func TestPreVerifyEnabled(t *testing.T) {
	verifyCalled := false
	facilitator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/verify") {
			verifyCalled = true
			resp := x402.FacilitatorVerifyResponse{IsValid: true}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer facilitator.Close()

	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	policy := testPolicy(t, facilitator.URL)
	policy.SkipPreVerify = false // explicitly enable pre-verification

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()
	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if !verifyCalled {
		t.Error("facilitator /verify was not called despite SkipPreVerify=false")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestPreVerifyRejection verifies that if the facilitator rejects the payload,
// the proxy returns 402 and the budget is refunded.
func TestPreVerifyRejection(t *testing.T) {
	facilitator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := x402.FacilitatorVerifyResponse{IsValid: false, InvalidReason: "insufficient_funds"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer facilitator.Close()

	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	policy := testPolicy(t, facilitator.URL)
	policy.SkipPreVerify = false
	policy.DailyLimitCents = 1000

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, _ := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()
	rail.ProxyRequest(context.Background(), w, req, "agent", "")

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402 (facilitator rejected)", w.Code)
	}

	// Budget must be fully refunded after facilitator rejection
	spent := rail.Budget().SpentThisPeriod("daily")
	if spent != 0 {
		t.Errorf("daily spent = %d after facilitator rejection, want 0 (refunded)", spent)
	}
}

// TestAuditLogFullPipeline verifies that a complete payment leaves a correct
// and complete record in the SQLite audit database.
func TestAuditLogFullPipeline(t *testing.T) {
	facilitator := mockFacilitatorServer(t)
	defer facilitator.Close()

	payTo := "0x" + strings.Repeat("d", 40)
	upstream := mockX402Server(t, "eip155:84532", "500000", payTo) // $0.50
	defer upstream.Close()

	policy := testPolicy(t, facilitator.URL)
	policy.SkipPreVerify = true

	dbPath := filepath.Join(t.TempDir(), "audit.db")
	rail, db := newTestRail(t, policy, dbPath)

	req := httptest.NewRequest("POST", upstream.URL+"/api/inference", strings.NewReader(`{"prompt":"hello"}`))
	req.RequestURI = ""
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentinel-Agent", "inference-agent")
	req.Header.Set("X-Sentinel-Task", "task-abc-123")
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "inference-agent", "task-abc-123")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	txns, err := db.QueryTransactions("inference-agent", time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(txns))
	}

	tx := txns[0]
	t.Logf("audit record: %+v", tx)

	if tx.Status != "allowed" {
		t.Errorf("status = %q", tx.Status)
	}
	if tx.RailType != "x402" {
		t.Errorf("rail_type = %q", tx.RailType)
	}
	if tx.Method != "POST" {
		t.Errorf("method = %q", tx.Method)
	}
	if tx.AmountUSD != 0.50 {
		t.Errorf("amount_usd = %.2f, want 0.50", tx.AmountUSD)
	}
	if tx.AmountRaw != "500000" {
		t.Errorf("amount_raw = %q", tx.AmountRaw)
	}
	if tx.Network != "eip155:84532" {
		t.Errorf("network = %q", tx.Network)
	}
	if tx.TxHash != "0xfakedeadbeef1234567890abcdef" {
		t.Errorf("tx_hash = %q", tx.TxHash)
	}
	if tx.TaskContext != "task-abc-123" {
		t.Errorf("task_context = %q", tx.TaskContext)
	}
	if tx.LatencyMS < 0 {
		t.Errorf("latency_ms = %d, want >= 0", tx.LatencyMS)
	}
	if tx.ID == "" {
		t.Error("id should not be empty")
	}
}

// TestMultiAgentBudgetIsolation verifies that two agents have independent budgets.
func TestMultiAgentBudgetIsolation(t *testing.T) {
	facilitator := mockFacilitatorServer(t)
	defer facilitator.Close()

	upstream := mockX402Server(t, "eip155:84532", "10000", "0x"+strings.Repeat("c", 40))
	defer upstream.Close()

	// Agent 1: tight budget
	p1 := testPolicy(t, facilitator.URL)
	p1.SkipPreVerify = true
	p1.DailyLimitCents = 1 // only $0.01

	// Agent 2: generous budget
	p2 := testPolicy(t, facilitator.URL)
	p2.SkipPreVerify = true
	p2.DailyLimitCents = 1000

	db1, err := audit.NewSQLiteAuditLogger(filepath.Join(t.TempDir(), "a1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db1.Close() })

	db2, err := audit.NewSQLiteAuditLogger(filepath.Join(t.TempDir(), "a2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db2.Close() })

	logger := zap.NewNop()
	rail1, _ := x402.NewX402Rail(p1, db1, logger)
	rail2, _ := x402.NewX402Rail(p2, db2, logger)

	call := func(rail *x402.X402Rail, agentID string) int {
		req := httptest.NewRequest("GET", upstream.URL+"/data", nil)
		req.RequestURI = ""
		w := httptest.NewRecorder()
		rail.ProxyRequest(context.Background(), w, req, agentID, "")
		return w.Code
	}

	// Agent 1 succeeds on first call ($0.01 = limit)
	if code := call(rail1, "agent1"); code != http.StatusOK {
		t.Errorf("agent1 first call: %d, want 200", code)
	}

	// Agent 1 is now at budget limit — second call should fail
	if code := call(rail1, "agent1"); code != http.StatusForbidden {
		t.Errorf("agent1 second call: %d, want 403", code)
	}

	// Agent 2 is unaffected — should succeed
	if code := call(rail2, "agent2"); code != http.StatusOK {
		t.Errorf("agent2 first call: %d, want 200 (agent budgets are independent)", code)
	}
}

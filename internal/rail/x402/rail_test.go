package x402

import (
	"context"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

// ─── BudgetTracker tests ───────────────────────────────────────────────────────

func TestBudgetTracker_Reserve_WithinLimit(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 1000, WeeklyLimitCents: 5000, MonthlyLimitCents: 10000}
	bt := NewBudgetTracker(policy)

	if err := bt.Reserve(100); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if bt.SpentThisPeriod("daily") != 100 {
		t.Errorf("daily spent = %d, want 100", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_Reserve_ExceedsDaily(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 100}
	bt := NewBudgetTracker(policy)

	if err := bt.Reserve(50); err != nil {
		t.Fatal(err)
	}
	if err := bt.Reserve(60); err == nil {
		t.Error("expected error when daily budget exceeded")
	}
	// Verify no partial debit on failure
	if bt.SpentThisPeriod("daily") != 50 {
		t.Errorf("daily spent = %d after failed reserve, want 50", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_Reserve_ExceedsWeekly(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 10000, WeeklyLimitCents: 100}
	bt := NewBudgetTracker(policy)

	_ = bt.Reserve(80)
	if err := bt.Reserve(30); err == nil {
		t.Error("expected error when weekly budget exceeded")
	}
}

func TestBudgetTracker_Reserve_NoLimit(t *testing.T) {
	policy := &X402Policy{} // zero limits = unlimited
	bt := NewBudgetTracker(policy)

	for i := 0; i < 100; i++ {
		if err := bt.Reserve(1000000); err != nil {
			t.Fatalf("unexpected error with no limits: %v", err)
		}
	}
}

func TestBudgetTracker_Refund(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 1000}
	bt := NewBudgetTracker(policy)

	_ = bt.Reserve(500)
	bt.Refund(500)

	if bt.SpentThisPeriod("daily") != 0 {
		t.Errorf("daily spent after refund = %d, want 0", bt.SpentThisPeriod("daily"))
	}

	// After refund, we should be able to reserve again
	if err := bt.Reserve(900); err != nil {
		t.Errorf("reserve after refund failed: %v", err)
	}
}

func TestBudgetTracker_Refund_FloorAtZero(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 1000}
	bt := NewBudgetTracker(policy)

	bt.Refund(999) // Refund without prior reserve — should not go negative
	if bt.SpentThisPeriod("daily") != 0 {
		t.Errorf("daily spent should not go below 0, got %d", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_OnThreshold(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 100}
	bt := NewBudgetTracker(policy)

	var fired []float64
	bt.OnThreshold = func(period string, pctUsed float64) {
		if period == "daily" {
			fired = append(fired, pctUsed)
		}
	}

	_ = bt.Reserve(90) // 90%
	if len(fired) == 0 {
		t.Error("threshold callback not fired")
	}
	if fired[0] < 89 || fired[0] > 91 {
		t.Errorf("pctUsed = %.1f, want ~90.0", fired[0])
	}
}

func TestBudgetTracker_Seed(t *testing.T) {
	policy := &X402Policy{DailyLimitCents: 1000}
	bt := NewBudgetTracker(policy)

	bt.Seed("daily", 700)
	if bt.SpentThisPeriod("daily") != 700 {
		t.Errorf("daily spent after seed = %d, want 700", bt.SpentThisPeriod("daily"))
	}
	// Reserve should now be constrained
	if err := bt.Reserve(400); err == nil {
		t.Error("expected budget exceeded error after seed")
	}
}

// ─── VelocityLimiter tests ─────────────────────────────────────────────────────

func TestVelocityLimiter_Allow_UnderLimit(t *testing.T) {
	v := NewVelocityLimiter(10, 100, 60)
	for i := 0; i < 9; i++ {
		if err := v.Allow(); err != nil {
			t.Fatalf("unexpected error at request %d: %v", i, err)
		}
	}
}

func TestVelocityLimiter_Allow_ExceedsPerMinute(t *testing.T) {
	v := NewVelocityLimiter(3, 100, 60)
	for i := 0; i < 3; i++ {
		_ = v.Allow()
	}
	if err := v.Allow(); err == nil {
		t.Error("expected velocity exceeded error")
	}
}

func TestVelocityLimiter_Allow_Cooldown(t *testing.T) {
	v := NewVelocityLimiter(1, 100, 1)

	_ = v.Allow()
	if err := v.Allow(); err == nil {
		t.Error("expected cooldown error")
	}

	// Simulate cooldown expiry by manipulating blockedUntil
	v.mu.Lock()
	v.blockedUntil = time.Now().Add(-1 * time.Second)
	v.minuteWindow = nil
	v.mu.Unlock()

	if err := v.Allow(); err != nil {
		t.Errorf("expected allow after cooldown, got: %v", err)
	}
}

// ─── Endpoint policy tests ─────────────────────────────────────────────────────

func TestCheckEndpoint_Open(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{EndpointMode: "open"}}
	u := mustParseURL("https://api.example.com/data")
	if err := rail.checkEndpoint(u); err != nil {
		t.Errorf("open mode should allow all, got: %v", err)
	}
}

func TestCheckEndpoint_Allowlist_Allowed(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		EndpointMode: "allowlist",
		AllowedHosts: []string{"api.example.com"},
	}}
	u := mustParseURL("https://api.example.com/data")
	if err := rail.checkEndpoint(u); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestCheckEndpoint_Allowlist_Blocked(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		EndpointMode: "allowlist",
		AllowedHosts: []string{"allowed.com"},
	}}
	u := mustParseURL("https://evil.com/data")
	if err := rail.checkEndpoint(u); err == nil {
		t.Error("expected block for host not on allowlist")
	}
}

func TestCheckEndpoint_Blocklist_Blocked(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		EndpointMode: "blocklist",
		BlockedHosts: []string{"evil.com"},
	}}
	u := mustParseURL("https://evil.com/data")
	if err := rail.checkEndpoint(u); err == nil {
		t.Error("expected block for host on blocklist")
	}
}

func TestCheckEndpoint_Blocklist_Allowed(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		EndpointMode: "blocklist",
		BlockedHosts: []string{"evil.com"},
	}}
	u := mustParseURL("https://api.example.com/data")
	if err := rail.checkEndpoint(u); err != nil {
		t.Errorf("expected allow for host not on blocklist, got: %v", err)
	}
}

// ─── selectRequirement tests ───────────────────────────────────────────────────

func TestSelectRequirement_PreferredChain(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		PreferredChain: "eip155:8453",
	}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "exact", Network: "eip155:1", Amount: "100"},
			{Scheme: "exact", Network: "eip155:8453", Amount: "100"},
		},
	}
	req, err := rail.selectRequirement(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != "eip155:8453" {
		t.Errorf("expected eip155:8453, got %s", req.Network)
	}
}

func TestSelectRequirement_FallbackToAny(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		PreferredChain: "eip155:9999", // not offered
	}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "exact", Network: "eip155:8453", Amount: "100"},
		},
	}
	req, err := rail.selectRequirement(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != "eip155:8453" {
		t.Errorf("expected fallback to eip155:8453, got %s", req.Network)
	}
}

func TestSelectRequirement_UnknownNetworkRejected(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Network: "eip155:99999", Amount: "100"}, // not in KnownNetworks
		},
	}
	_, err := rail.selectRequirement(challenge)
	if err == nil {
		t.Error("expected error for unknown network")
	}
}

func TestSelectRequirement_AllowedNetworksFilter(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{
		AllowedNetworks: []string{"eip155:84532"}, // only testnet
	}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "exact", Network: "eip155:8453"},  // mainnet — should be rejected
			{Scheme: "exact", Network: "eip155:84532"}, // testnet — should be chosen
		},
	}
	req, err := rail.selectRequirement(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if req.Network != "eip155:84532" {
		t.Errorf("expected eip155:84532, got %s", req.Network)
	}
}

// ─── parsePriceToCents tests ───────────────────────────────────────────────────

func TestParsePriceToCents(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{}}
	tests := []struct {
		atomicAmount string
		wantCents    int64
	}{
		{"10000", 1},      // $0.01 = 1 cent
		{"100000", 10},    // $0.10 = 10 cents
		{"1000000", 100},  // $1.00 = 100 cents
		{"500000", 50},    // $0.50 = 50 cents
		{"0", 0},
	}
	const (
		testNetwork = "eip155:8453"
		testAsset   = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" // USDC on Base
	)
	for _, tt := range tests {
		cents, raw, err := rail.parsePriceToCents(tt.atomicAmount, testAsset, testNetwork)
		if err != nil {
			t.Errorf("parsePriceToCents(%q): unexpected error: %v", tt.atomicAmount, err)
			continue
		}
		if cents != tt.wantCents {
			t.Errorf("parsePriceToCents(%q) = %d cents, want %d", tt.atomicAmount, cents, tt.wantCents)
		}
		if raw != tt.atomicAmount {
			t.Errorf("raw = %q, want %q", raw, tt.atomicAmount)
		}
	}
}

func TestParsePriceToCents_InvalidInput(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{}}
	_, _, err := rail.parsePriceToCents("not-a-number", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:8453")
	if err == nil {
		t.Error("expected error for invalid amount")
	}
}

// ─── EIP-712 signing tests ────────────────────────────────────────────────────

func TestSignPayment_ProducesValidSignature(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)

	policy := &X402Policy{
		PrivateKey:     key,
		WalletAddress:  addr.Hex(),
		PayloadTTL:     60 * time.Second,
		SkipPreVerify:  true,
	}

	rail := &X402Rail{policy: policy}
	req := &PaymentRequirement{
		Network:           "eip155:84532",
		Amount:            "10000",
		Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayTo:             "0x1234567890123456789012345678901234567890",
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"name": "USDC", "version": "2"},
	}

	payload, err := rail.signPayment(context.Background(), req, nil, "https://api.example.com/resource")
	if err != nil {
		t.Fatalf("signPayment: %v", err)
	}

	if payload.X402Version != 2 {
		t.Errorf("x402Version = %d, want 2", payload.X402Version)
	}
	if payload.Payload.Signature == "" {
		t.Error("signature is empty")
	}
	if len(payload.Payload.Authorization.Nonce) != 66 { // "0x" + 64 hex chars
		t.Errorf("nonce length = %d, want 66", len(payload.Payload.Authorization.Nonce))
	}
	if payload.Payload.Authorization.From != addr.Hex() {
		t.Errorf("from = %s, want %s", payload.Payload.Authorization.From, addr.Hex())
	}
}

func TestComputeEIP712DomainSeparator_Deterministic(t *testing.T) {
	addr := common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e")
	chainID := big.NewInt(84532)

	h1, err := computeEIP712DomainSeparator("USDC", "2", chainID, addr)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := computeEIP712DomainSeparator("USDC", "2", chainID, addr)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("domain separator is not deterministic")
	}
}

func TestComputeEIP712DomainSeparator_DiffersByChain(t *testing.T) {
	addr := common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e")
	h1, _ := computeEIP712DomainSeparator("USDC", "2", big.NewInt(1), addr)
	h2, _ := computeEIP712DomainSeparator("USDC", "2", big.NewInt(8453), addr)
	if h1 == h2 {
		t.Error("domain separator should differ by chain ID")
	}
}

// ─── Free endpoint passthrough test ───────────────────────────────────────────

func TestProxyRequest_FreeEndpoint_PassThrough(t *testing.T) {
	// Upstream server returns 200 directly (no payment required)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("free data"))
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:      key,
		WalletAddress:   addr.Hex(),
		PreferredChain:  "eip155:84532",
		FacilitatorURL:  "http://localhost:9999", // won't be called
		UpstreamTimeout: 5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:      60 * time.Second,
		EndpointMode:    "open",
		SkipPreVerify:   true,
	}

	logger := noopLogger()
	rail, err := NewX402Rail(policy, &noopAuditLogger{}, logger)
	if err != nil {
		t.Fatal(err)
	}

	// Build a request pointing at the upstream test server
	req := httptest.NewRequest("GET", upstream.URL+"/free", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxyRequest_Plain402_PassThrough(t *testing.T) {
	// Upstream returns a plain HTTP 402 (e.g. Stripe card error) with no x402 markers.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`{"error":{"type":"card_error","code":"card_declined","message":"Your card was declined."}}`))
	}))
	defer upstream.Close()

	var logged []TransactionRecord
	auditLogger := &capturingAuditLogger{records: &logged}

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		FacilitatorURL:     "http://localhost:9999",
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true,
	}

	logger := noopLogger()
	rail, err := NewX402Rail(policy, auditLogger, logger)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/paid", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	resp := w.Result()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402", resp.StatusCode)
	}
	if len(logged) > 0 && logged[0].Status != "passthrough_402" {
		t.Errorf("audit status = %q, want %q", logged[0].Status, "passthrough_402")
	}
}

func TestLooksLikeX402Challenge(t *testing.T) {
	tests := []struct {
		name   string
		header string
		body   string
		want   bool
	}{
		{
			name:   "v2 header present",
			header: `{"x402Version":1,"accepts":[]}`,
			want:   true,
		},
		{
			name: "v1 body with x402Version",
			body: `{"x402Version":1,"accepts":[]}`,
			want: true,
		},
		{
			name: "plain stripe error",
			body: `{"error":{"type":"card_error","code":"card_declined"}}`,
			want: false,
		},
		{
			name: "empty body",
			body: "",
			want: false,
		},
		{
			name: "non-json body",
			body: "Payment required",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{},
				Body:   io.NopCloser(strings.NewReader(tc.body)),
			}
			if tc.header != "" {
				resp.Header.Set(headerPaymentRequired, tc.header)
			}
			got := looksLikeX402Challenge(resp)
			if got != tc.want {
				t.Errorf("looksLikeX402Challenge = %v, want %v", got, tc.want)
			}
		})
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// noopAuditLogger satisfies AuditLogger without doing anything.
type noopAuditLogger struct{}

// capturingAuditLogger records every LogTransaction call for test assertions.
type capturingAuditLogger struct {
	records *[]TransactionRecord
}

func (c *capturingAuditLogger) LogTransaction(tx TransactionRecord) error {
	*c.records = append(*c.records, tx)
	return nil
}

func (n *noopAuditLogger) LogTransaction(tx TransactionRecord) error { return nil }

func noopLogger() *zap.Logger { return zap.NewNop() }

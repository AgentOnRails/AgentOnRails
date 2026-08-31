package x402

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	arail "github.com/agentOnRails/agent-on-rails/rail"
)

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

func TestSelectRequirement_UptoRejectedByDefault(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{}} // AllowUpto defaults false
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "upto", Network: "eip155:84532"},
		},
	}
	if _, err := rail.selectRequirement(challenge); err == nil {
		t.Error("expected upto to be rejected when AllowUpto is false, even as the only option")
	}
}

func TestSelectRequirement_ExactPreferredOverUpto(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{AllowUpto: true}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "upto", Network: "eip155:84532"},
			{Scheme: "exact", Network: "eip155:84532"},
		},
	}
	req, err := rail.selectRequirement(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if req.Scheme != "exact" {
		t.Errorf("scheme = %q, want exact preferred over upto", req.Scheme)
	}
}

func TestSelectRequirement_UptoAllowedWhenOnlyOption(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{AllowUpto: true}}
	challenge := &PaymentRequired{
		Accepts: []PaymentRequirement{
			{Scheme: "upto", Network: "eip155:84532"},
		},
	}
	req, err := rail.selectRequirement(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if req.Scheme != "upto" {
		t.Errorf("scheme = %q, want upto", req.Scheme)
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
	var eip3009 EIP3009Payload
	if err := json.Unmarshal(payload.Payload, &eip3009); err != nil {
		t.Fatalf("unmarshal exact payload: %v", err)
	}
	if eip3009.Signature == "" {
		t.Error("signature is empty")
	}
	if len(eip3009.Authorization.Nonce) != 66 { // "0x" + 64 hex chars
		t.Errorf("nonce length = %d, want 66", len(eip3009.Authorization.Nonce))
	}
	if eip3009.Authorization.From != addr.Hex() {
		t.Errorf("from = %s, want %s", eip3009.Authorization.From, addr.Hex())
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

// eip3009StructHash reproduces chainsign/eip155's unexported
// computeTransferWithAuthStructHash so tests here can independently verify
// which EIP-712 domain a returned signature actually recovers under. The
// type string is EIP-3009's own spec text, not something specific to this
// codebase, so duplicating it in a test is not fragile.
func eip3009StructHash(t *testing.T, from, to common.Address, value, validAfter, validBefore *big.Int, nonce [32]byte) [32]byte {
	t.Helper()
	const eip3009TypeString = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
	typeHash := ethcrypto.Keccak256Hash([]byte(eip3009TypeString))

	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)
	args := abi.Arguments{
		{Type: bytes32Type}, {Type: addressType}, {Type: addressType},
		{Type: uint256Type}, {Type: uint256Type}, {Type: uint256Type}, {Type: bytes32Type},
	}
	encoded, err := args.Pack(typeHash, from, to, value, validAfter, validBefore, nonce)
	if err != nil {
		t.Fatalf("pack struct hash args: %v", err)
	}
	return ethcrypto.Keccak256Hash(encoded)
}

// eip712Digest reproduces chainsign/eip155's unexported computeEIP712Digest.
func eip712Digest(domainSep, structHash [32]byte) [32]byte {
	raw := make([]byte, 0, 2+32+32)
	raw = append(raw, 0x19, 0x01)
	raw = append(raw, domainSep[:]...)
	raw = append(raw, structHash[:]...)
	return ethcrypto.Keccak256Hash(raw)
}

// recoversUnderDomain reports whether sigHex (the "0x"-prefixed 65-byte
// EIP3009Payload signature) was produced over the digest built from
// domainSep and the authorization fields.
func recoversUnderDomain(t *testing.T, sigHex string, domainSep [32]byte, auth EIP3009AuthFields, wantSigner common.Address) bool {
	t.Helper()
	sig := common.FromHex(sigHex)
	if len(sig) != 65 {
		t.Fatalf("signature length = %d, want 65", len(sig))
	}
	// crypto.SigToPub expects V in {0,1}; SignExact stores it as {27,28}.
	sigForRecover := slices.Clone(sig)
	sigForRecover[64] -= 27

	value, _ := new(big.Int).SetString(auth.Value, 10)
	validAfter, _ := new(big.Int).SetString(auth.ValidAfter, 10)
	validBefore, _ := new(big.Int).SetString(auth.ValidBefore, 10)
	var nonce [32]byte
	copy(nonce[:], common.FromHex(auth.Nonce))

	structHash := eip3009StructHash(t,
		common.HexToAddress(auth.From), common.HexToAddress(auth.To),
		value, validAfter, validBefore, nonce)
	digest := eip712Digest(domainSep, structHash)

	pubKey, err := ethcrypto.SigToPub(digest[:], sigForRecover)
	if err != nil {
		return false
	}
	return ethcrypto.PubkeyToAddress(*pubKey) == wantSigner
}

func TestSignPayment_VerifyingContractOverride(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)

	const (
		arcUSDC         = "0x3600000000000000000000000000000000000000"
		gatewayContract = "0x0077777d7EBA4688BDeF3E311b846F25870A19B9"
	)

	rail := &X402Rail{policy: &X402Policy{
		PrivateKey:    key,
		WalletAddress: addr.Hex(),
		PayloadTTL:    60 * time.Second,
		SkipPreVerify: true,
	}}
	req := &PaymentRequirement{
		Network:           "eip155:5042002",
		Amount:            "10000",
		Asset:             arcUSDC,
		PayTo:             "0x1234567890123456789012345678901234567890",
		MaxTimeoutSeconds: 60,
		Extra: map[string]any{
			"name":              "GatewayWalletBatched",
			"version":           "1",
			"verifyingContract": gatewayContract,
		},
	}

	payload, err := rail.signPayment(context.Background(), req, nil, "https://api.example.com/resource")
	if err != nil {
		t.Fatalf("signPayment: %v", err)
	}
	var eip3009 EIP3009Payload
	if err := json.Unmarshal(payload.Payload, &eip3009); err != nil {
		t.Fatalf("unmarshal exact payload: %v", err)
	}

	chainID := big.NewInt(5042002)
	gatewayDomain, err := computeEIP712DomainSeparator("GatewayWalletBatched", "1", chainID, common.HexToAddress(gatewayContract))
	if err != nil {
		t.Fatalf("gateway domain separator: %v", err)
	}
	assetDomain, err := computeEIP712DomainSeparator("GatewayWalletBatched", "1", chainID, common.HexToAddress(arcUSDC))
	if err != nil {
		t.Fatalf("asset domain separator: %v", err)
	}

	if !recoversUnderDomain(t, eip3009.Signature, gatewayDomain, eip3009.Authorization, addr) {
		t.Error("signature does not recover under the GatewayWalletBatched/verifyingContract domain — override did not take effect")
	}
	if recoversUnderDomain(t, eip3009.Signature, assetDomain, eip3009.Authorization, addr) {
		t.Error("signature recovers under the asset-address domain — verifyingContract override was ignored")
	}
}

func TestSignPayment_NoVerifyingContractOverride_UsesAsset(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)

	const usdcBaseSepolia = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

	rail := &X402Rail{policy: &X402Policy{
		PrivateKey:    key,
		WalletAddress: addr.Hex(),
		PayloadTTL:    60 * time.Second,
		SkipPreVerify: true,
	}}
	req := &PaymentRequirement{
		Network:           "eip155:84532",
		Amount:            "10000",
		Asset:             usdcBaseSepolia,
		PayTo:             "0x1234567890123456789012345678901234567890",
		MaxTimeoutSeconds: 60,
		Extra:             map[string]any{"name": "USDC", "version": "2"},
	}

	payload, err := rail.signPayment(context.Background(), req, nil, "https://api.example.com/resource")
	if err != nil {
		t.Fatalf("signPayment: %v", err)
	}
	var eip3009 EIP3009Payload
	if err := json.Unmarshal(payload.Payload, &eip3009); err != nil {
		t.Fatalf("unmarshal exact payload: %v", err)
	}

	assetDomain, err := computeEIP712DomainSeparator("USDC", "2", big.NewInt(84532), common.HexToAddress(usdcBaseSepolia))
	if err != nil {
		t.Fatalf("asset domain separator: %v", err)
	}
	if !recoversUnderDomain(t, eip3009.Signature, assetDomain, eip3009.Authorization, addr) {
		t.Error("signature does not recover under the asset domain when no verifyingContract override is present — existing chains must be unaffected")
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

	var logged []arail.TransactionRecord
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
	records *[]arail.TransactionRecord
}

func (c *capturingAuditLogger) LogTransaction(tx arail.TransactionRecord) error {
	*c.records = append(*c.records, tx)
	return nil
}

func (n *noopAuditLogger) LogTransaction(tx arail.TransactionRecord) error { return nil }

func noopLogger() *zap.Logger { return zap.NewNop() }

package x402

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ─── Domain separator determinism ──────────────────────────────────────────────

func TestComputePermit2DomainSeparator_Deterministic(t *testing.T) {
	addr := common.HexToAddress(permit2ContractAddress)
	chainID := big.NewInt(84532)

	h1, err := computePermit2DomainSeparator(chainID, addr)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := computePermit2DomainSeparator(chainID, addr)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("permit2 domain separator is not deterministic")
	}
}

func TestComputePermit2DomainSeparator_DiffersByChain(t *testing.T) {
	addr := common.HexToAddress(permit2ContractAddress)
	h1, _ := computePermit2DomainSeparator(big.NewInt(1), addr)
	h2, _ := computePermit2DomainSeparator(big.NewInt(8453), addr)
	if h1 == h2 {
		t.Error("permit2 domain separator should differ by chain ID")
	}
}

func TestComputePermit2DomainSeparator_DiffersFromExactDomain(t *testing.T) {
	// Permit2's domain (no "version" field) must not collide with the
	// EIP-3009 token domain used for "exact" — they sign against different
	// verifying contracts entirely.
	permit2Addr := common.HexToAddress(permit2ContractAddress)
	tokenAddr := common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e")
	chainID := big.NewInt(84532)

	permit2Domain, err := computePermit2DomainSeparator(chainID, permit2Addr)
	if err != nil {
		t.Fatal(err)
	}
	exactDomain, err := computeEIP712DomainSeparator("USDC", "2", chainID, tokenAddr)
	if err != nil {
		t.Fatal(err)
	}
	if permit2Domain == exactDomain {
		t.Error("permit2 domain separator must differ from the exact-scheme token domain")
	}
}

// ─── signPermit2 ────────────────────────────────────────────────────────────────

func TestSignPermit2_ProducesValidShape(t *testing.T) {
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)

	policy := &X402Policy{
		PrivateKey:    key,
		WalletAddress: addr.Hex(),
		PayloadTTL:    60 * time.Second,
		SkipPreVerify: true,
		AllowUpto:     true,
	}
	rail := &X402Rail{policy: policy}

	req := &PaymentRequirement{
		Scheme:            x402SchemeUpto,
		Network:           "eip155:84532",
		Amount:            "5000000",
		Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayTo:             "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
		MaxTimeoutSeconds: 300,
		Extra: map[string]any{
			"name":               "USDC",
			"version":            "2",
			"facilitatorAddress": "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf",
		},
	}

	payload, err := rail.signPermit2(context.Background(), req, nil, "https://api.example.com/llm/generate")
	if err != nil {
		t.Fatalf("signPermit2: %v", err)
	}
	if payload.X402Version != 2 {
		t.Errorf("x402Version = %d, want 2", payload.X402Version)
	}

	var p2 Permit2Payload
	if err := json.Unmarshal(payload.Payload, &p2); err != nil {
		t.Fatalf("unmarshal permit2 payload: %v", err)
	}
	if p2.Signature == "" {
		t.Error("signature is empty")
	}
	if p2.Permit2Authorization.Permitted.Token != req.Asset {
		t.Errorf("permitted.token = %s, want %s", p2.Permit2Authorization.Permitted.Token, req.Asset)
	}
	if p2.Permit2Authorization.Permitted.Amount != req.Amount {
		t.Errorf("permitted.amount = %s, want %s (must be the MAX, not a settled amount)", p2.Permit2Authorization.Permitted.Amount, req.Amount)
	}
	if p2.Permit2Authorization.From != addr.Hex() {
		t.Errorf("from = %s, want %s", p2.Permit2Authorization.From, addr.Hex())
	}
	if p2.Permit2Authorization.Spender != x402UptoPermit2ProxyAddress {
		t.Errorf("spender = %s, want the fixed x402UptoPermit2Proxy address %s", p2.Permit2Authorization.Spender, x402UptoPermit2ProxyAddress)
	}
	if p2.Permit2Authorization.Witness.To != req.PayTo {
		t.Errorf("witness.to = %s, want %s", p2.Permit2Authorization.Witness.To, req.PayTo)
	}
	if p2.Permit2Authorization.Witness.Facilitator != "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf" {
		t.Errorf("witness.facilitator = %s, want the requirement's extra.facilitatorAddress", p2.Permit2Authorization.Witness.Facilitator)
	}
	if p2.Permit2Authorization.Nonce == "" || p2.Permit2Authorization.Deadline == "" {
		t.Error("nonce/deadline must be populated")
	}
}

func TestSignPermit2_MissingFacilitatorAddress(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{PrivateKey: key, WalletAddress: addr.Hex(), PayloadTTL: 60 * time.Second}
	rail := &X402Rail{policy: policy}

	req := &PaymentRequirement{
		Scheme:  x402SchemeUpto,
		Network: "eip155:84532",
		Amount:  "5000000",
		Asset:   "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		PayTo:   "0x209693Bc6afc0C5328bA36FaF03C514EF312287",
		Extra:   map[string]any{"name": "USDC", "version": "2"}, // no facilitatorAddress
	}

	if _, err := rail.signPermit2(context.Background(), req, nil, ""); err == nil {
		t.Error("expected error for missing extra.facilitatorAddress")
	}
}

// signPayment dispatch test: confirms the scheme-based dispatcher actually
// routes to signPermit2 for "upto" and signExact for "exact".
func TestSignPayment_DispatchesOnScheme(t *testing.T) {
	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{PrivateKey: key, WalletAddress: addr.Hex(), PayloadTTL: 60 * time.Second, SkipPreVerify: true}
	rail := &X402Rail{policy: policy}

	uptoReq := &PaymentRequirement{
		Scheme: x402SchemeUpto, Network: "eip155:84532", Amount: "5000000",
		Asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", PayTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287",
		Extra: map[string]any{"facilitatorAddress": "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf"},
	}
	payload, err := rail.signPayment(context.Background(), uptoReq, nil, "")
	if err != nil {
		t.Fatalf("signPayment(upto): %v", err)
	}
	var p2 Permit2Payload
	if err := json.Unmarshal(payload.Payload, &p2); err != nil {
		t.Fatalf("upto payload did not decode as Permit2Payload: %v", err)
	}

	exactReq := &PaymentRequirement{
		Scheme: x402SchemeExact, Network: "eip155:84532", Amount: "10000",
		Asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", PayTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287",
		Extra: map[string]any{"name": "USDC", "version": "2"},
	}
	payload, err = rail.signPayment(context.Background(), exactReq, nil, "")
	if err != nil {
		t.Fatalf("signPayment(exact): %v", err)
	}
	var e EIP3009Payload
	if err := json.Unmarshal(payload.Payload, &e); err != nil {
		t.Fatalf("exact payload did not decode as EIP3009Payload: %v", err)
	}
}

// ─── facilitatorSupported cache ────────────────────────────────────────────────

func TestFacilitatorSupported_CachesAndReflectsExtensions(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(supportedResponse{
			Extensions: []string{"erc20ApprovalGasSponsoring", "eip2612GasSponsoring"},
		})
	}))
	defer srv.Close()

	rail := &X402Rail{
		policy:     &X402Policy{FacilitatorURL: srv.URL},
		httpClient: http.DefaultClient,
	}

	sup, err := rail.facilitatorSupported(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sup.hasExtension("erc20ApprovalGasSponsoring") {
		t.Error("expected erc20ApprovalGasSponsoring to be reported")
	}
	if sup.hasExtension("not-a-real-extension") {
		t.Error("hasExtension should be false for unknown extensions")
	}

	// Second call within the TTL should be served from cache, not refetch.
	if _, err := rail.facilitatorSupported(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP call (cached on second), got %d", calls)
	}
}

// ─── ensurePermit2Allowance ─────────────────────────────────────────────────────

// fakeAllowanceRPC returns an eth_call response encoding a fixed allowance
// value as a 32-byte hex-encoded uint256, mirroring real JSON-RPC shape.
func fakeAllowanceRPC(t *testing.T, allowance *big.Int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hexVal := common.LeftPadBytes(allowance.Bytes(), 32)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"jsonrpc": "2.0",
			"result":  "0x" + common.Bytes2Hex(hexVal),
		})
	}))
}

func TestEnsurePermit2Allowance_Sufficient(t *testing.T) {
	rpc := fakeAllowanceRPC(t, big.NewInt(10_000_000))
	defer rpc.Close()

	rail := &X402Rail{policy: &X402Policy{}, httpClient: http.DefaultClient}
	network := NetworkInfo{Name: "Base Sepolia", RPCURL: rpc.URL}

	err := rail.ensurePermit2Allowance(context.Background(),
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
		network, big.NewInt(5_000_000))
	if err != nil {
		t.Fatalf("expected sufficient allowance to pass, got: %v", err)
	}
}

func TestEnsurePermit2Allowance_InsufficientNoExtensions(t *testing.T) {
	rpc := fakeAllowanceRPC(t, big.NewInt(100))
	defer rpc.Close()

	facilitator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(supportedResponse{Extensions: nil})
	}))
	defer facilitator.Close()

	rail := &X402Rail{
		policy:     &X402Policy{FacilitatorURL: facilitator.URL},
		httpClient: http.DefaultClient,
	}
	network := NetworkInfo{Name: "Base Sepolia", RPCURL: rpc.URL}

	err := rail.ensurePermit2Allowance(context.Background(),
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
		network, big.NewInt(5_000_000))
	if err == nil {
		t.Fatal("expected fail-closed error for insufficient allowance with no sponsoring extension")
	}
}

func TestEnsurePermit2Allowance_NoRPCURL(t *testing.T) {
	rail := &X402Rail{policy: &X402Policy{}, httpClient: http.DefaultClient}
	network := NetworkInfo{Name: "Nowhere"} // RPCURL intentionally empty

	err := rail.ensurePermit2Allowance(context.Background(),
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
		network, big.NewInt(5_000_000))
	if err == nil {
		t.Fatal("expected error when no RPC endpoint is configured")
	}
}

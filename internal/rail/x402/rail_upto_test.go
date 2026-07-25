package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	arail "github.com/agentOnRails/agent-on-rails/rail"
)

// withSufficientPermit2Allowance temporarily points eip155:84532's RPCURL at
// a fake JSON-RPC server that reports an effectively unlimited allowance, so
// ProxyRequest's upto preflight (ensurePermit2Allowance) passes without a
// real chain. Restores the original entry on cleanup.
func withSufficientPermit2Allowance(t *testing.T) {
	t.Helper()
	rpc := fakeAllowanceRPC(t, new(big.Int).Lsh(big.NewInt(1), 200)) // huge
	orig := KnownNetworks["eip155:84532"]
	patched := orig
	patched.RPCURL = rpc.URL
	KnownNetworks["eip155:84532"] = patched
	t.Cleanup(func() {
		rpc.Close()
		KnownNetworks["eip155:84532"] = orig
	})
}

func uptoTestChallenge(maxAtomic, payTo, facilitatorAddr string) []byte {
	pr := PaymentRequired{
		X402Version: 2,
		Accepts: []PaymentRequirement{{
			Scheme:            x402SchemeUpto,
			Network:           "eip155:84532",
			Amount:            maxAtomic,
			Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			PayTo:             payTo,
			MaxTimeoutSeconds: 300,
			Extra: map[string]any{
				"name":               "USDC",
				"version":            "2",
				"facilitatorAddress": facilitatorAddr,
			},
		}},
	}
	data, _ := json.Marshal(pr)
	return data
}

func encodeSettlement(t *testing.T, pr PaymentResponse) string {
	t.Helper()
	data, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// TestProxyRequest_Upto_PartialRefund confirms that when the upstream's
// settlement response reports an actual amount smaller than the authorized
// max, the rail refunds the difference and records the audit amount as the
// actual settled amount — not the max reserved upfront.
func TestProxyRequest_Upto_PartialRefund(t *testing.T) {
	withSufficientPermit2Allowance(t)

	payTo := "0x" + strings.Repeat("b", 40)
	facilitatorAddr := "0x" + strings.Repeat("f", 40)
	const maxAtomic = "1000000"   // $1.00 max authorized
	const actualAtomic = "300000" // $0.30 actually settled

	var gotPermit2Sig string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerPaymentSig) == "" {
			w.Header().Set(headerPaymentRequired, base64.StdEncoding.EncodeToString(uptoTestChallenge(maxAtomic, payTo, facilitatorAddr)))
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		gotPermit2Sig = r.Header.Get(headerPaymentSig)
		w.Header().Set(headerPaymentResponse, encodeSettlement(t, PaymentResponse{
			Success:     true,
			Transaction: "0xuptosettled",
			Network:     "eip155:84532",
			Payer:       "0x" + strings.Repeat("a", 40),
			Amount:      actualAtomic,
		}))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"generated tokens"}`))
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		AllowUpto:          true,
		DailyLimitCents:    1000, // $10 — well above the $1 max
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true,
	}

	var logged []arail.TransactionRecord
	rail, err := NewX402Rail(policy, &capturingAuditLogger{records: &logged}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/generate", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotPermit2Sig == "" {
		t.Fatal("upstream did not receive a PAYMENT-SIGNATURE header on retry")
	}
	raw, err := base64.StdEncoding.DecodeString(gotPermit2Sig)
	if err != nil {
		t.Fatalf("PAYMENT-SIGNATURE not base64: %v", err)
	}
	var pp PaymentPayload
	if err := json.Unmarshal(raw, &pp); err != nil {
		t.Fatalf("PAYMENT-SIGNATURE not valid JSON: %v", err)
	}
	var p2 Permit2Payload
	if err := json.Unmarshal(pp.Payload, &p2); err != nil {
		t.Fatalf("payload is not a Permit2Payload: %v", err)
	}
	if p2.Permit2Authorization.Permitted.Amount != maxAtomic {
		t.Errorf("signed amount = %s, want the MAX %s (not the eventual settlement)", p2.Permit2Authorization.Permitted.Amount, maxAtomic)
	}

	if len(logged) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(logged))
	}
	rec := logged[0]
	if rec.Status != "allowed" {
		t.Errorf("audit status = %q, want allowed", rec.Status)
	}
	if rec.AmountUSD != 0.30 {
		t.Errorf("audit AmountUSD = %v, want 0.30 (actual settled, not the $1.00 max)", rec.AmountUSD)
	}
	if rec.AmountRaw != actualAtomic {
		t.Errorf("audit AmountRaw = %q, want %q", rec.AmountRaw, actualAtomic)
	}

	// Budget should reflect only the actual 30 cents spent, not the $1 max —
	// Reserve(100) then Refund(70) should leave 30 cents spent.
	if spent := rail.budget.SpentThisPeriod("daily"); spent != 30 {
		t.Errorf("daily budget spent = %d cents, want 30 (max reserved then partially refunded)", spent)
	}
}

// TestProxyRequest_Upto_NoSettlementAmount_KeepsMaxReserved confirms the
// conservative fallback: if the upstream's retry response carries no
// parseable settlement amount at all, the rail keeps the full authorized max
// reserved/recorded rather than guessing or refunding blindly.
func TestProxyRequest_Upto_NoSettlementAmount_KeepsMaxReserved(t *testing.T) {
	withSufficientPermit2Allowance(t)

	payTo := "0x" + strings.Repeat("b", 40)
	facilitatorAddr := "0x" + strings.Repeat("f", 40)
	const maxAtomic = "1000000" // $1.00 max authorized

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerPaymentSig) == "" {
			w.Header().Set(headerPaymentRequired, base64.StdEncoding.EncodeToString(uptoTestChallenge(maxAtomic, payTo, facilitatorAddr)))
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		// No PAYMENT-RESPONSE header at all on the retry.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"generated tokens"}`))
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		AllowUpto:          true,
		DailyLimitCents:    1000,
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true,
	}

	var logged []arail.TransactionRecord
	rail, err := NewX402Rail(policy, &capturingAuditLogger{records: &logged}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/generate", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	if len(logged) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(logged))
	}
	rec := logged[0]
	if rec.AmountUSD != 1.00 {
		t.Errorf("audit AmountUSD = %v, want 1.00 (max kept as conservative fallback)", rec.AmountUSD)
	}
	if spent := rail.budget.SpentThisPeriod("daily"); spent != 100 {
		t.Errorf("daily budget spent = %d cents, want 100 (full max, no settlement amount to adjust by)", spent)
	}
}

// TestProxyRequest_Upto_AllowanceMissingBlocks confirms a request is blocked
// before any signing happens when the Permit2 allowance preflight fails.
func TestProxyRequest_Upto_AllowanceMissingBlocks(t *testing.T) {
	rpc := fakeAllowanceRPC(t, big.NewInt(0)) // zero allowance
	defer rpc.Close()
	orig := KnownNetworks["eip155:84532"]
	patched := orig
	patched.RPCURL = rpc.URL
	KnownNetworks["eip155:84532"] = patched
	defer func() { KnownNetworks["eip155:84532"] = orig }()

	payTo := "0x" + strings.Repeat("b", 40)
	facilitatorAddr := "0x" + strings.Repeat("f", 40)

	var retrySeen bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerPaymentSig) != "" {
			retrySeen = true
		}
		w.Header().Set(headerPaymentRequired, base64.StdEncoding.EncodeToString(uptoTestChallenge("1000000", payTo, facilitatorAddr)))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:      key,
		WalletAddress:   addr.Hex(),
		PreferredChain:  "eip155:84532",
		AllowUpto:       true,
		DailyLimitCents: 1000,
		UpstreamTimeout: 5 * time.Second,
		PayloadTTL:      60 * time.Second,
		EndpointMode:    "open",
		SkipPreVerify:   true,
	}
	var logged []arail.TransactionRecord
	rail, err := NewX402Rail(policy, &capturingAuditLogger{records: &logged}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/generate", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()
	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	if retrySeen {
		t.Error("upstream should never have seen a signed retry — allowance preflight should block first")
	}
	if resp := w.Result(); resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (blocked by allowance preflight)", resp.StatusCode)
	}
	if len(logged) != 1 || logged[0].Status != "blocked" {
		t.Fatalf("expected 1 blocked audit record, got %+v", logged)
	}
	if rail.budget.SpentThisPeriod("daily") != 0 {
		t.Error("budget should have been refunded after the preflight block")
	}
}

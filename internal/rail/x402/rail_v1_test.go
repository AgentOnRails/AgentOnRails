package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TestNormalizeNetwork checks V1 slug → CAIP-2 conversion and pass-through.
func TestNormalizeNetwork(t *testing.T) {
	cases := map[string]string{
		"base-sepolia": "eip155:84532",
		"base":         "eip155:8453",
		"eip155:8453":  "eip155:8453", // already CAIP-2
		"unknown-net":  "unknown-net", // left untouched
	}
	for in, want := range cases {
		if got := normalizeNetwork(in); got != want {
			t.Errorf("normalizeNetwork(%q) = %q, want %q", in, got, want)
		}
	}
	// Round trip CAIP-2 → slug.
	if got := v1NetworkName("eip155:84532"); got != "base-sepolia" {
		t.Errorf("v1NetworkName(eip155:84532) = %q, want base-sepolia", got)
	}
}

// TestProxyRequest_V1Challenge_RepliesWithXPayment verifies that when the
// upstream speaks x402 V1 (challenge in the JSON body, no PAYMENT-REQUIRED
// header), AgentOnRails replies with the V1 X-PAYMENT header — not the V2
// PAYMENT-SIGNATURE header — and settles via X-PAYMENT-RESPONSE.
func TestProxyRequest_V1Challenge_RepliesWithXPayment(t *testing.T) {
	payTo := "0x" + strings.Repeat("f", 40)

	var gotXPayment, gotV2Sig string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerV1Payment) == "" && r.Header.Get(headerPaymentSig) == "" {
			// First request: emit a V1 challenge in the body (slug network,
			// maxAmountRequired), with NO PAYMENT-REQUIRED header.
			challenge := map[string]any{
				"x402Version": 1,
				"accepts": []map[string]any{{
					"scheme":            "exact",
					"network":           "base-sepolia",
					"maxAmountRequired": "10000", // $0.01
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

		// Second request: capture which payment headers arrived, then settle.
		gotXPayment = r.Header.Get(headerV1Payment)
		gotV2Sig = r.Header.Get(headerPaymentSig)

		settlement := map[string]any{
			"success":     true,
			"transaction": "0xv1deadbeef",
			"network":     "base-sepolia",
			"payer":       "0x" + strings.Repeat("a", 40),
		}
		data, _ := json.Marshal(settlement)
		w.Header().Set(headerV1PaymentResponse, base64.StdEncoding.EncodeToString(data))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"v1 paid content"}`))
	}))
	defer upstream.Close()

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		PerCallMaxCents:    100,
		DailyLimitCents:    100,
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true, // exercise the reply path without a live facilitator
	}

	var logged []TransactionRecord
	rail, err := NewX402Rail(policy, &capturingAuditLogger{records: &logged}, noopLogger())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", upstream.URL+"/paid", nil)
	req.RequestURI = ""
	w := httptest.NewRecorder()

	rail.ProxyRequest(context.Background(), w, req, "test-agent", "")

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// The upstream must have received a V1 X-PAYMENT header and NOT a V2 one.
	if gotXPayment == "" {
		t.Fatal("upstream did not receive an X-PAYMENT header on retry")
	}
	if gotV2Sig != "" {
		t.Errorf("upstream unexpectedly received a V2 PAYMENT-SIGNATURE header: %q", gotV2Sig)
	}

	// Decode the X-PAYMENT header and check it is well-formed V1.
	raw, err := base64.StdEncoding.DecodeString(gotXPayment)
	if err != nil {
		t.Fatalf("X-PAYMENT not base64: %v", err)
	}
	var v1 v1PaymentPayload
	if err := json.Unmarshal(raw, &v1); err != nil {
		t.Fatalf("X-PAYMENT not valid JSON: %v", err)
	}
	if v1.X402Version != 1 {
		t.Errorf("x402Version = %d, want 1", v1.X402Version)
	}
	if v1.Scheme != "exact" {
		t.Errorf("scheme = %q, want exact", v1.Scheme)
	}
	if v1.Network != "base-sepolia" {
		t.Errorf("network = %q, want base-sepolia (slug, not CAIP-2)", v1.Network)
	}
	if !strings.EqualFold(v1.Payload.Authorization.From, addr.Hex()) {
		t.Errorf("authorization.from = %q, want %q", v1.Payload.Authorization.From, addr.Hex())
	}
	if !strings.EqualFold(v1.Payload.Authorization.To, payTo) {
		t.Errorf("authorization.to = %q, want %q", v1.Payload.Authorization.To, payTo)
	}
	if v1.Payload.Signature == "" {
		t.Error("authorization signature is empty")
	}

	// Audit record: amount normalized from maxAmountRequired, network to CAIP-2.
	if len(logged) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(logged))
	}
	rec := logged[0]
	if rec.Status != "allowed" {
		t.Errorf("audit status = %q, want allowed", rec.Status)
	}
	if rec.AmountUSD != 0.01 {
		t.Errorf("audit amount = %v, want 0.01", rec.AmountUSD)
	}
	if rec.Network != "eip155:84532" {
		t.Errorf("audit network = %q, want eip155:84532", rec.Network)
	}
	if rec.TxHash != "0xv1deadbeef" {
		t.Errorf("audit tx_hash = %q, want 0xv1deadbeef", rec.TxHash)
	}
}

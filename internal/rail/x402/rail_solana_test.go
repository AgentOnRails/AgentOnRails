package x402

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	solanago "github.com/gagliardetto/solana-go"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign/solana"
)

// fakeSolanaRPCForDispatch serves just enough of the Solana JSON-RPC surface
// for signPayment's namespace dispatch to reach chainsign/solana's SignExact
// and succeed — the destination token account always "exists" here since
// this test is about proving dispatch reaches the right Signer and wraps
// its result correctly, not about re-testing ATA-creation branching (already
// covered directly in chainsign/solana's own tests).
func fakeSolanaRPCForDispatch(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode fake rpc request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "getLatestBlockhash":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":1}}}`))
		case "getAccountInfo":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"data":["","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":0}}}`))
		default:
			t.Fatalf("unexpected rpc method %q", req.Method)
		}
	}))
}

// TestSignPayment_DispatchesToSolanaSigner proves signPayment's namespace
// dispatch (rail.go) is genuinely chain-agnostic, not just correctly
// refactored for eip155: a Solana network + an Ed25519Key-only policy (no
// ECDSA PrivateKey at all) reaches chainsign/solana's Signer and comes back
// wrapped in the same PaymentPayload envelope shape EVM chains get.
func TestSignPayment_DispatchesToSolanaSigner(t *testing.T) {
	srv := fakeSolanaRPCForDispatch(t)
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	walletAddr := solanago.PrivateKey(priv).PublicKey().String()

	// Override KnownNetworks just for this test's network entry so RPCURL
	// points at the fake server rather than a real public endpoint —
	// restored after, since KnownNetworks is shared package state other
	// tests also read.
	const testNetwork = "solana:test-dispatch"
	orig, hadOrig := KnownNetworks[testNetwork]
	KnownNetworks[testNetwork] = NetworkInfo{Name: "Solana Test", RPCURL: srv.URL}
	t.Cleanup(func() {
		if hadOrig {
			KnownNetworks[testNetwork] = orig
		} else {
			delete(KnownNetworks, testNetwork)
		}
	})

	policy := &X402Policy{
		WalletAddress: walletAddr,
		Ed25519Key:    priv,
		PayloadTTL:    60 * time.Second,
	}
	rail := &X402Rail{policy: policy}

	req := &PaymentRequirement{
		Network: testNetwork,
		Scheme:  x402SchemeExact,
		Amount:  "10000",
		Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
		PayTo:   solanago.TokenProgramID.String(),
	}

	payload, err := rail.signPayment(context.Background(), req, nil, "https://api.example.com/resource")
	if err != nil {
		t.Fatalf("signPayment: %v", err)
	}
	if payload.X402Version != x402Version {
		t.Errorf("X402Version = %d, want %d", payload.X402Version, x402Version)
	}
	if payload.Accepted.Network != testNetwork {
		t.Errorf("Accepted.Network = %q, want %q", payload.Accepted.Network, testNetwork)
	}

	var solPayload solana.Payload
	if err := json.Unmarshal(payload.Payload, &solPayload); err != nil {
		t.Fatalf("payload did not decode as a Solana Payload: %v", err)
	}
	if solPayload.SerializedTransaction == "" {
		t.Error("expected a non-empty serialized transaction")
	}

	tx := new(solanago.Transaction)
	if err := tx.UnmarshalBase64(solPayload.SerializedTransaction); err != nil {
		t.Fatalf("decode serialized transaction: %v", err)
	}
	if err := tx.VerifySignatures(); err != nil {
		t.Errorf("VerifySignatures: %v", err)
	}
}

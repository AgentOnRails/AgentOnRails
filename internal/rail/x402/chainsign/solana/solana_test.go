package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	solanago "github.com/gagliardetto/solana-go"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign"
)

// fakeRPCRequest is the minimal shape needed to route a JSON-RPC request by
// method name — the same hand-rolled-RPC test approach the eip155 package's
// sibling (permit2's readAllowance) already uses for EVM's own RPC calls.
type fakeRPCRequest struct {
	Method string `json:"method"`
}

// fakeSolanaRPC serves just the two RPC methods SignExact calls:
// getLatestBlockhash (always) and getAccountInfo (once, for the destination
// token account) — destATAExists controls which of getAccountInfo's two
// real shapes (a populated value, or value: null) it returns.
func fakeSolanaRPC(t *testing.T, destATAExists bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req fakeRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode fake rpc request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "getLatestBlockhash":
			// "11111111111111111111111111111111" is 32 zero bytes in
			// base58 (the real, well-known System Program address) — a
			// valid-shaped blockhash for test purposes, not a real one.
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":1}}}`))
		case "getAccountInfo":
			if destATAExists {
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"data":["","base64"],"executable":false,"lamports":2039280,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","rentEpoch":0}}}`))
			} else {
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}`))
			}
		default:
			t.Fatalf("unexpected rpc method %q", req.Method)
		}
	}))
}

func testWallet(t *testing.T) (chainsign.Wallet, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	solPriv := solanago.PrivateKey(priv)
	return chainsign.Wallet{
		Address: solPriv.PublicKey().String(),
		Ed25519: priv,
	}, priv
}

func validAuth(rpcURL string) chainsign.PaymentAuth {
	return chainsign.PaymentAuth{
		Network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
		Asset:   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", // devnet USDC mint
		// Any real (non-zero) pubkey works as a stand-in recipient — NOT
		// solanago.SystemProgramID, which is all-zero bytes and trips
		// CreateIdempotent's own "is this unset?" validation the same way
		// an actually-missing address would.
		PayTo:  solanago.TokenProgramID.String(),
		Amount: "10000",
		RPCURL: rpcURL,
	}
}

func TestSignExact_MissingWallet_Errors(t *testing.T) {
	srv := fakeSolanaRPC(t, true)
	defer srv.Close()

	_, err := SignExact(context.Background(), validAuth(srv.URL), chainsign.Wallet{})
	if err == nil {
		t.Fatal("expected an error when the wallet has no ed25519 key")
	}
}

func TestSignExact_MissingRPCURL_Errors(t *testing.T) {
	wallet, _ := testWallet(t)
	auth := validAuth("")

	_, err := SignExact(context.Background(), auth, wallet)
	if err == nil {
		t.Fatal("expected an error when no RPC endpoint is configured")
	}
}

func TestSignExact_InvalidAssetAddress_Errors(t *testing.T) {
	srv := fakeSolanaRPC(t, true)
	defer srv.Close()
	wallet, _ := testWallet(t)

	auth := validAuth(srv.URL)
	auth.Asset = "not-a-valid-base58-address!!"

	if _, err := SignExact(context.Background(), auth, wallet); err == nil {
		t.Fatal("expected an error for an invalid asset (mint) address")
	}
}

func TestSignExact_InvalidAmount_Errors(t *testing.T) {
	srv := fakeSolanaRPC(t, true)
	defer srv.Close()
	wallet, _ := testWallet(t)

	auth := validAuth(srv.URL)
	auth.Amount = "not-a-number"

	if _, err := SignExact(context.Background(), auth, wallet); err == nil {
		t.Fatal("expected an error for a non-numeric amount")
	}
}

func TestSignExact_DestinationATAMissing_IncludesCreateInstruction(t *testing.T) {
	srv := fakeSolanaRPC(t, false)
	defer srv.Close()
	wallet, _ := testWallet(t)

	raw, err := SignExact(context.Background(), validAuth(srv.URL), wallet)
	if err != nil {
		t.Fatalf("SignExact: %v", err)
	}
	tx := decodePayload(t, raw)

	if got := len(tx.Message.Instructions); got != 2 {
		t.Fatalf("expected 2 instructions (create ATA + transfer) when the destination account is missing, got %d", got)
	}
	if prog := tx.Message.AccountKeys[tx.Message.Instructions[0].ProgramIDIndex]; !prog.Equals(solanago.SPLAssociatedTokenAccountProgramID) {
		t.Errorf("first instruction program = %s, want the associated-token-account program %s", prog, solanago.SPLAssociatedTokenAccountProgramID)
	}
	if prog := tx.Message.AccountKeys[tx.Message.Instructions[1].ProgramIDIndex]; !prog.Equals(solanago.TokenProgramID) {
		t.Errorf("second instruction program = %s, want the token program %s", prog, solanago.TokenProgramID)
	}
}

func TestSignExact_DestinationATAExists_OnlyTransferInstruction(t *testing.T) {
	srv := fakeSolanaRPC(t, true)
	defer srv.Close()
	wallet, _ := testWallet(t)

	raw, err := SignExact(context.Background(), validAuth(srv.URL), wallet)
	if err != nil {
		t.Fatalf("SignExact: %v", err)
	}
	tx := decodePayload(t, raw)

	if got := len(tx.Message.Instructions); got != 1 {
		t.Fatalf("expected exactly 1 instruction (transfer only) when the destination account already exists, got %d", got)
	}
	if prog := tx.Message.AccountKeys[tx.Message.Instructions[0].ProgramIDIndex]; !prog.Equals(solanago.TokenProgramID) {
		t.Errorf("instruction program = %s, want the token program %s", prog, solanago.TokenProgramID)
	}
}

func TestSignExact_TransactionSignatureVerifies(t *testing.T) {
	srv := fakeSolanaRPC(t, true)
	defer srv.Close()
	wallet, _ := testWallet(t)

	raw, err := SignExact(context.Background(), validAuth(srv.URL), wallet)
	if err != nil {
		t.Fatalf("SignExact: %v", err)
	}
	tx := decodePayload(t, raw)

	if err := tx.VerifySignatures(); err != nil {
		t.Errorf("VerifySignatures: %v", err)
	}

	ownerPub := solanago.PrivateKey(wallet.Ed25519).PublicKey()
	if !tx.Message.AccountKeys[0].Equals(ownerPub) {
		t.Errorf("fee payer = %s, want the wallet's own address %s", tx.Message.AccountKeys[0], ownerPub)
	}
}

func TestSignUpto_ReturnsSchemeUnsupported(t *testing.T) {
	wallet, _ := testWallet(t)
	if _, err := SignUpto(context.Background(), validAuth("http://unused.invalid"), wallet); err != chainsign.ErrSchemeUnsupported {
		t.Errorf("SignUpto error = %v, want chainsign.ErrSchemeUnsupported", err)
	}
}

func TestSigner_RegisteredUnderSolanaNamespace(t *testing.T) {
	s, ok := chainsign.Get("solana")
	if !ok {
		t.Fatal("expected a Signer registered under the \"solana\" namespace")
	}
	if s.Namespace() != "solana" {
		t.Errorf("Namespace() = %q, want \"solana\"", s.Namespace())
	}
	if s.SupportsUpto() {
		t.Error("SupportsUpto() = true, want false for v1")
	}
}

func decodePayload(t *testing.T, raw json.RawMessage) *solanago.Transaction {
	t.Helper()
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.SerializedTransaction == "" {
		t.Fatal("payload has an empty serialized transaction")
	}
	tx := new(solanago.Transaction)
	if err := tx.UnmarshalBase64(p.SerializedTransaction); err != nil {
		t.Fatalf("decode serialized transaction: %v", err)
	}
	return tx
}

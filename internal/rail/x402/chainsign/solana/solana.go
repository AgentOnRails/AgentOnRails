// Package solana is the chainsign.Signer for Solana (CAIP-2 namespace
// "solana"): ed25519 signing of an SPL Token TransferChecked instruction for
// the "exact" scheme. This is the proof that chainsign's Signer interface
// (see internal/rail/x402/chainsign) is a real extensibility point, not one
// designed only around EVM's shape — Solana's signing model differs from
// EIP-3009 in a way that's structural, not cosmetic, and this package's doc
// comments below spell out exactly where and why.
//
// EIP-3009 (eip155's "exact" scheme) is gasless by design: the signed
// authorization is a bare signature over a struct, with no fee payer and no
// blockhash — the daemon never touches gas at all. Solana has no equivalent
// meta-transaction pattern for SPL transfers: every transaction embeds a
// recent blockhash and a fee payer who needs a small SOL balance, so signing
// here needs a live RPC read (the latest blockhash) before it can produce a
// payload at all, and the paying wallet has a real new operational
// requirement (SOL for fees, and for one-time Associated Token Account rent
// if the recipient's ATA doesn't exist yet) that EVM/USDC wallets under this
// rail never had. v1 uses the paying wallet itself as fee payer — documented
// plainly rather than papered over — with a facilitator-pays-fees v2 an
// explicitly out-of-scope future enhancement (see SignExact's doc comment).
//
// Like eip155, the daemon only signs here; it never broadcasts. The
// serialized transaction is handed back to the resource server/facilitator's
// existing /settle call, which submits it — the same non-broadcasting
// posture eip155's Permit2 allowance preflight already documents for EVM
// (this rail does not pay its own gas to submit an approval transaction
// either).
package solana

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	solanago "github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign"
)

// usdcDecimals is USDC's decimal precision on Solana — 6, the same as every
// EVM deployment this rail already assumes elsewhere (see x402's
// parsePriceToCents).
const usdcDecimals = 6

// Payload is the signed-transaction shape this Signer returns. Unlike
// eip155's EIP3009Payload/Permit2Payload (a bare signature over a struct),
// this is a fully-built, signed Solana transaction, base64-encoded — there
// is no smaller "just the signature" shape Solana's transaction model
// supports, since the blockhash and fee payer are part of what gets signed.
type Payload struct {
	SerializedTransaction string `json:"serializedTransaction"`
}

func marshalPayload(p Payload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// SignExact builds and signs an SPL Token TransferChecked instruction moving
// a.Amount of the a.Asset mint from w's Associated Token Account to a.PayTo's
// (creating the destination ATA first, if it doesn't exist yet), with w
// itself as fee payer. Requires a.RPCURL (see chainsign.PaymentAuth's doc
// comment on why this field exists) for the one read this scheme cannot
// avoid: a fresh blockhash, without which there is nothing valid to sign.
func SignExact(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	if len(w.Ed25519) == 0 {
		return nil, fmt.Errorf("solana: wallet has no ed25519 key configured (check rails.x402.key_type)")
	}
	if a.RPCURL == "" {
		return nil, fmt.Errorf("solana: no RPC endpoint configured for network %s", a.Network)
	}

	priv := solanago.PrivateKey(w.Ed25519)
	owner := priv.PublicKey()

	mint, err := solanago.PublicKeyFromBase58(a.Asset)
	if err != nil {
		return nil, fmt.Errorf("solana: invalid asset (mint) address %q: %w", a.Asset, err)
	}
	payTo, err := solanago.PublicKeyFromBase58(a.PayTo)
	if err != nil {
		return nil, fmt.Errorf("solana: invalid payTo address %q: %w", a.PayTo, err)
	}
	amount, err := strconv.ParseUint(a.Amount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("solana: cannot parse amount %q: %w", a.Amount, err)
	}

	sourceATA, _, err := solanago.FindAssociatedTokenAddress(owner, mint)
	if err != nil {
		return nil, fmt.Errorf("solana: derive source associated token account: %w", err)
	}
	destATA, _, err := solanago.FindAssociatedTokenAddress(payTo, mint)
	if err != nil {
		return nil, fmt.Errorf("solana: derive destination associated token account: %w", err)
	}

	rpcClient := rpc.New(a.RPCURL)

	recent, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana: get latest blockhash: %w", err)
	}

	var instructions []solanago.Instruction

	// The destination ATA may not exist yet — SPL transfers require it to,
	// so create it (idempotently: a no-op if it's already there, safe
	// against a concurrent creation racing this one) as the transaction's
	// first instruction whenever a fresh check says it's missing.
	if _, err := rpcClient.GetAccountInfo(ctx, destATA); err != nil {
		if !errors.Is(err, rpc.ErrNotFound) {
			return nil, fmt.Errorf("solana: check destination token account: %w", err)
		}
		createATA, err := associatedtokenaccount.NewCreateIdempotentInstructionBuilder().
			SetPayer(owner).
			SetWallet(payTo).
			SetMint(mint).
			ValidateAndBuild()
		if err != nil {
			return nil, fmt.Errorf("solana: build create-token-account instruction: %w", err)
		}
		instructions = append(instructions, createATA)
	}

	transfer, err := token.NewTransferCheckedInstruction(
		amount,
		usdcDecimals,
		sourceATA,
		mint,
		destATA,
		owner,
		nil,
	).ValidateAndBuild()
	if err != nil {
		return nil, fmt.Errorf("solana: build transfer instruction: %w", err)
	}
	instructions = append(instructions, transfer)

	tx, err := solanago.NewTransaction(instructions, recent.Value.Blockhash, solanago.TransactionPayer(owner))
	if err != nil {
		return nil, fmt.Errorf("solana: build transaction: %w", err)
	}

	if _, err := tx.Sign(func(key solanago.PublicKey) *solanago.PrivateKey {
		if key.Equals(owner) {
			return &priv
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("solana: sign transaction: %w", err)
	}

	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("solana: serialize transaction: %w", err)
	}

	return marshalPayload(Payload{SerializedTransaction: base64.StdEncoding.EncodeToString(raw)})
}

// SignUpto is unsupported for v1: "upto" needs a maximum-authorization
// pattern (Permit2's role for eip155) Solana's SPL Token program has no
// built-in equivalent of. SupportsUpto reports this so callers (signPayment)
// reject the pairing before ever calling this, per chainsign.Signer's
// contract.
func SignUpto(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	return nil, chainsign.ErrSchemeUnsupported
}

// signer adapts this package's free functions to chainsign.Signer.
type signer struct{}

func (signer) Namespace() string  { return "solana" }
func (signer) SupportsUpto() bool { return false }
func (signer) SignExact(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	return SignExact(ctx, a, w)
}
func (signer) SignUpto(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	return SignUpto(ctx, a, w)
}

func init() {
	chainsign.Register(signer{})
}

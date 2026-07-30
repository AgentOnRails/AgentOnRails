// Package chainsign is the plugin boundary between the x402 rail's protocol
// logic (challenge parsing, budget/policy enforcement, facilitator
// communication — all chain-agnostic) and the chain-family-specific
// cryptography needed to actually sign a payment authorization. It exists so
// x402's signing dispatch can be extended to a new chain family (Solana,
// eventually others) by registering a new Signer, rather than by adding
// another branch to a hardcoded EVM-only signing function.
//
// This mirrors the spirit of the OSS repo's rail.Register/rail.Get pattern
// (github.com/agentOnRails/agent-on-rails/rail) — a real plugin registry, not
// a type switch — but scoped one level down: rail.Register lets a new
// payment rail (x402, card, bank) plug into the daemon, while
// chainsign.Register lets a new chain family plug into the x402 rail
// specifically, keyed by CAIP-2 namespace ("eip155", "solana", ...) rather
// than by rail name.
package chainsign

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

// Wallet carries whichever key material a Signer needs. Exactly one of
// ECDSA/Ed25519 is populated, matching the agent's configured key_type (see
// factory.go) — a Signer only reads the field for its own chain family and
// ignores the other, which is nil/zero rather than an error to check for,
// since a given Signer implementation only ever expects one shape.
type Wallet struct {
	Address string
	ECDSA   *ecdsa.PrivateKey  // set for secp256k1 chains (eip155)
	Ed25519 ed25519.PrivateKey // set for ed25519 chains (solana)
}

// PaymentAuth carries everything a Signer needs to build one payment
// authorization, translated from the x402 PaymentRequirement the challenge
// actually offered plus this rail's own policy — deliberately not the
// PaymentRequirement type itself, so this package (and anything
// implementing Signer) never needs to import the x402 package, which would
// create an import cycle (x402 imports chainsign to dispatch to a Signer).
type PaymentAuth struct {
	Network           string // CAIP-2, e.g. "eip155:8453" or "solana:..."
	Asset             string
	PayTo             string
	Amount            string
	MaxTimeoutSeconds int
	Extra             map[string]any
	PayloadTTL        time.Duration

	// RPCURL is a JSON-RPC endpoint for Network, if the caller's own
	// per-network config has one — eip155's Signer ignores this entirely
	// (EIP-3009 needs no RPC read to sign), but it's load-bearing for
	// Solana: a Signer for a chain family with no gasless/meta-transaction
	// signing scheme needs a live blockhash before it can build a
	// transaction at all.
	RPCURL string
}

// ErrSchemeUnsupported is returned by SignUpto when a chain family's Signer
// doesn't implement the "upto" scheme — check SupportsUpto before calling
// SignUpto to avoid relying on this error for control flow.
var ErrSchemeUnsupported = errors.New("chainsign: scheme unsupported for this chain family")

// Signer builds a signed payment authorization for one chain family. It
// returns only the scheme-specific inner payload (e.g. an EIP3009Payload or
// a Permit2Payload, marshaled) — the caller (x402's signPayment) wraps that
// in the protocol-level PaymentPayload envelope, which is the same for every
// chain family and scheme.
type Signer interface {
	// Namespace is the CAIP-2 namespace this Signer handles, e.g. "eip155".
	Namespace() string

	// SignExact signs a's amount as a definite, final charge.
	SignExact(ctx context.Context, a PaymentAuth, w Wallet) (json.RawMessage, error)

	// SignUpto signs a's amount as a maximum, settled for actual usage
	// afterward. Returns ErrSchemeUnsupported if SupportsUpto is false.
	SignUpto(ctx context.Context, a PaymentAuth, w Wallet) (json.RawMessage, error)

	// SupportsUpto reports whether this chain family's Signer implements
	// the "upto" scheme at all — checked before ever selecting a
	// requirement that would need it, so an unsupported pairing is
	// rejected cheaply rather than deep inside signing.
	SupportsUpto() bool
}

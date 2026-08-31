// Package eip155 is the chainsign.Signer for EVM chains (CAIP-2 namespace
// "eip155"): EIP-3009 transferWithAuthorization for the "exact" scheme, and
// Uniswap Permit2's permitWitnessTransferFrom for "upto" — the same
// cryptography the x402 rail always used, moved out from behind
// *X402Rail's methods so it's reachable through the chain-agnostic
// chainsign.Signer interface instead of being hardcoded as the only chain
// x402 knows how to sign for.
//
// This package deliberately has zero dependency on the x402 package itself
// (only on chainsign, plus go-ethereum) — x402 depends on chainsign to
// dispatch to whichever Signer a payment's network resolves to, so the
// reverse dependency would be an import cycle.
package eip155

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign"
)

const (
	// eip3009TypeString is the EIP-3009 transferWithAuthorization type
	// string used in the EIP-712 domain for the "exact" scheme.
	eip3009TypeString = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"

	// eip712DomainTypeString is the EIP-712 domain type string for USDC on
	// EVM chains, used by the "exact" scheme.
	eip712DomainTypeString = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

	// permit2ContractAddress is Uniswap's canonical Permit2 singleton,
	// deployed at this same address via CREATE2 on essentially every EVM
	// chain (see https://docs.uniswap.org/contracts/v4/deployments).
	permit2ContractAddress = "0x000000000022D473030F116dDEE9F6B43aC78BA"

	// X402UptoPermit2ProxyAddress is the x402 "upto" scheme's own witness
	// proxy contract (x402UptoPermit2Proxy). Per the spec's Annex this is
	// also deployed at a fixed address on every supported chain via
	// CREATE2 — a constant, not something this package derives. Exported so
	// the x402 package can reference the same value in a test compatibility
	// const (see permit2.go).
	X402UptoPermit2ProxyAddress = "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"

	// permit2DomainTypeString is Permit2's own EIP-712 domain — unlike the
	// EIP-3009 token domain used for "exact", it carries no "version" field.
	permit2DomainTypeString = "EIP712Domain(string name,uint256 chainId,address verifyingContract)"

	tokenPermissionsTypeString = "TokenPermissions(address token,uint256 amount)"

	// permit2WitnessTypeString / permitWitnessTransferFromTypeString are a
	// BEST-EFFORT RECONSTRUCTION, not a byte-verified quote from x402's
	// source. Confirmed pattern: the sibling "exact" scheme's on-chain
	// x402ExactPermit2Proxy uses
	//   WITNESS_TYPEHASH = keccak256("Witness(address to,uint256 validAfter)")
	// The "upto" scheme's documented client payload additionally carries
	// witness.facilitator (specs/schemes/upto/scheme_upto_evm.md's JSON
	// example), so by the same witness-stub pattern Permit2 itself defines
	// (_PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB + witness type string +
	// referenced-struct definitions in alphabetical order), this rail
	// reconstructs the "upto" witness type as
	// "Witness(address to,address facilitator,uint256 validAfter)".
	//
	// A wrong string here fails CLOSED: Permit2's on-chain signature check
	// simply rejects the signature (or the facilitator's own /verify does),
	// it cannot misdirect funds — witness.to/witness.facilitator bind the
	// recipient and facilitator independently of the hash construction.
	// MUST be confirmed against one live testnet /verify call before this
	// is trusted for a real payment — the same "built, not yet
	// hand-verified" caveat applies to any commercial rail plugging into
	// this one's Rail interface until it's done the same live check.
	permit2WitnessTypeString            = "Witness(address to,address facilitator,uint256 validAfter)"
	permitWitnessTransferFromTypeString = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,address facilitator,uint256 validAfter)"
)

// ─── Wire types (x402 protocol payloads for EVM chains) ───────────────────────

// EIP3009Payload contains the "exact" scheme's cryptographic proof.
type EIP3009Payload struct {
	Signature     string            `json:"signature"`
	Authorization EIP3009AuthFields `json:"authorization"`
}

// EIP3009AuthFields are the parameters of transferWithAuthorization().
type EIP3009AuthFields struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// TokenPermissions is Permit2's "permitted" struct: the token and the
// maximum amount being authorized (the actual settled amount, decided later
// by the resource server, may be anywhere from 0 up to this).
type TokenPermissions struct {
	Token  string `json:"token"`
	Amount string `json:"amount"`
}

// Permit2Witness is the x402 "upto" scheme's witness data, cryptographically
// bound into the Permit2 signature so only the named facilitator can settle
// to the named recipient — see specs/schemes/upto's "Recipient Binding" and
// "facilitator address binding" security properties.
type Permit2Witness struct {
	To          string `json:"to"`
	Facilitator string `json:"facilitator"`
	ValidAfter  string `json:"validAfter"`
}

// Permit2AuthFields are the parameters of Permit2's permitWitnessTransferFrom().
type Permit2AuthFields struct {
	Permitted TokenPermissions `json:"permitted"`
	From      string           `json:"from"`
	Spender   string           `json:"spender"`
	Nonce     string           `json:"nonce"`
	Deadline  string           `json:"deadline"`
	Witness   Permit2Witness   `json:"witness"`
}

// Permit2Payload is the "upto" scheme's shape of the signed payload (mirrors
// EIP3009Payload's role for "exact").
type Permit2Payload struct {
	Signature            string            `json:"signature"`
	Permit2Authorization Permit2AuthFields `json:"permit2Authorization"`
}

func marshalExactPayload(p EIP3009Payload) (json.RawMessage, error) {
	return json.Marshal(p)
}

func marshalPermit2Payload(p Permit2Payload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// chainIDFromCAIP2 extracts the numeric chain ID from an eip155 CAIP-2
// network identifier (e.g. "eip155:8453" -> 8453) — CAIP-2's eip155
// namespace defines the reference as the chain ID itself, so no separate
// registry/lookup is needed the way x402.KnownNetworks is for other
// metadata (name, USDC address) that isn't encoded in the identifier.
func chainIDFromCAIP2(network string) (*big.Int, error) {
	const prefix = "eip155:"
	if !strings.HasPrefix(network, prefix) {
		return nil, fmt.Errorf("eip155: network %q is not an eip155 CAIP-2 identifier", network)
	}
	id, ok := new(big.Int).SetString(strings.TrimPrefix(network, prefix), 10)
	if !ok {
		return nil, fmt.Errorf("eip155: network %q has a non-numeric chain reference", network)
	}
	return id, nil
}

// ─── EIP-3009 ("exact") signing ────────────────────────────────────────────

// SignExact builds and signs an EIP-3009 transferWithAuthorization payload
// for a's amount, using w.ECDSA. Returns the marshaled EIP3009Payload.
func SignExact(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	chainID, err := chainIDFromCAIP2(a.Network)
	if err != nil {
		return nil, err
	}

	// Random 32-byte nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonceHex := "0x" + common.Bytes2Hex(nonce)

	// Time window
	now := time.Now().UTC()
	validAfter := now.Add(-5 * time.Second)
	validBefore := now.Add(a.PayloadTTL)
	if a.MaxTimeoutSeconds > 0 {
		serverTTL := time.Duration(a.MaxTimeoutSeconds) * time.Second
		if serverTTL < a.PayloadTTL {
			validBefore = now.Add(serverTTL)
		}
	}

	// EIP-712 domain separator
	tokenName := "USDC"
	tokenVersion := "2"
	if n, ok := a.Extra["name"].(string); ok && n != "" {
		tokenName = n
	}
	if v, ok := a.Extra["version"].(string); ok && v != "" {
		tokenVersion = v
	}

	// The domain's verifyingContract is normally the asset itself, but some
	// integrations sign "exact" payments against a different contract than
	// the asset being priced — e.g. Circle Gateway Nanopayments on Arc keeps
	// `asset` as the real native USDC address (for price/decimals purposes)
	// while requiring the EIP-3009 signature to verify against its own
	// GatewayWalletBatched ledger contract, carried in
	// extra.verifyingContract (see supportsBatching/getVerifyingContract in
	// @circle-fin/x402-batching). Defaulting to a.Asset keeps every existing
	// chain's behavior unchanged.
	assetAddr := common.HexToAddress(a.Asset)
	if vc, ok := a.Extra["verifyingContract"].(string); ok && vc != "" {
		assetAddr = common.HexToAddress(vc)
	}
	domainSep, err := ComputeEIP712DomainSeparator(tokenName, tokenVersion, chainID, assetAddr)
	if err != nil {
		return nil, fmt.Errorf("domain separator: %w", err)
	}

	// Struct hash
	fromAddr := common.HexToAddress(w.Address)
	toAddr := common.HexToAddress(a.PayTo)
	value := new(big.Int)
	value.SetString(a.Amount, 10)

	validAfterInt := big.NewInt(validAfter.Unix())
	validBeforeInt := big.NewInt(validBefore.Unix())
	var nonceBytes [32]byte
	copy(nonceBytes[:], nonce)

	structHash, err := computeTransferWithAuthStructHash(
		fromAddr, toAddr, value, validAfterInt, validBeforeInt, nonceBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("struct hash: %w", err)
	}

	// Final EIP-712 digest
	digest := computeEIP712Digest(domainSep, structHash)

	// ECDSA sign
	sig, err := crypto.Sign(digest[:], w.ECDSA)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	// go-ethereum returns [R || S || V] where V is 0 or 1; EVM expects 27 or 28.
	sig[64] += 27
	sigHex := "0x" + common.Bytes2Hex(sig)

	auth := EIP3009AuthFields{
		From:        fromAddr.Hex(),
		To:          toAddr.Hex(),
		Value:       a.Amount,
		ValidAfter:  strconv.FormatInt(validAfter.Unix(), 10),
		ValidBefore: strconv.FormatInt(validBefore.Unix(), 10),
		Nonce:       nonceHex,
	}

	return marshalExactPayload(EIP3009Payload{
		Signature:     sigHex,
		Authorization: auth,
	})
}

// ComputeEIP712DomainSeparator builds the domain separator hash for the token.
func ComputeEIP712DomainSeparator(
	name, version string,
	chainID *big.Int,
	contractAddr common.Address,
) ([32]byte, error) {
	domainTypeHash := crypto.Keccak256Hash([]byte(eip712DomainTypeString))
	nameHash := crypto.Keccak256Hash([]byte(name))
	versionHash := crypto.Keccak256Hash([]byte(version))

	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)
	addressType, _ := abi.NewType("address", "", nil)

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytes32Type},
		{Type: bytes32Type},
		{Type: uint256Type},
		{Type: addressType},
	}
	encoded, err := args.Pack(
		domainTypeHash,
		nameHash,
		versionHash,
		chainID,
		contractAddr,
	)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

// computeTransferWithAuthStructHash builds the struct hash of TransferWithAuthorization.
func computeTransferWithAuthStructHash(
	from, to common.Address,
	value, validAfter, validBefore *big.Int,
	nonce [32]byte,
) ([32]byte, error) {
	typeHash := crypto.Keccak256Hash([]byte(eip3009TypeString))

	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: addressType},
		{Type: addressType},
		{Type: uint256Type},
		{Type: uint256Type},
		{Type: uint256Type},
		{Type: bytes32Type},
	}
	encoded, err := args.Pack(typeHash, from, to, value, validAfter, validBefore, nonce)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

// computeEIP712Digest produces keccak256("\x19\x01" || domainSeparator || structHash).
func computeEIP712Digest(domainSep, structHash [32]byte) [32]byte {
	prefix := []byte{0x19, 0x01}
	raw := make([]byte, 0, 2+32+32)
	raw = append(raw, prefix...)
	raw = append(raw, domainSep[:]...)
	raw = append(raw, structHash[:]...)
	return crypto.Keccak256Hash(raw)
}

// ─── Permit2 ("upto") signing ──────────────────────────────────────────────

// SignUpto builds and signs a Permit2 permitWitnessTransferFrom
// authorization for the "upto" scheme's maximum amount, using w.ECDSA.
// Mirrors SignExact's shape/error handling but with Permit2's domain and
// struct instead of EIP-3009's. Returns the marshaled Permit2Payload.
func SignUpto(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	chainID, err := chainIDFromCAIP2(a.Network)
	if err != nil {
		return nil, err
	}

	facilitatorAddr, ok := a.Extra["facilitatorAddress"].(string)
	if !ok || facilitatorAddr == "" {
		return nil, fmt.Errorf("upto scheme: payment requirement is missing extra.facilitatorAddress")
	}

	amount, ok := new(big.Int).SetString(a.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("upto scheme: cannot parse max amount %q", a.Amount)
	}

	// Random 32-byte nonce. Permit2's SignatureTransfer checks nonces
	// against a per-owner bitmap (wordPos/bit derived from the nonce value
	// itself) rather than a monotonic counter, so any unused random uint256
	// is valid — the same randomness approach SignExact already uses for
	// EIP-3009's nonce.
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonce := new(big.Int).SetBytes(nonceBytes)

	now := time.Now().UTC()
	validAfter := now.Add(-5 * time.Second)
	deadline := now.Add(a.PayloadTTL)
	if a.MaxTimeoutSeconds > 0 {
		serverTTL := time.Duration(a.MaxTimeoutSeconds) * time.Second
		if serverTTL < a.PayloadTTL {
			deadline = now.Add(serverTTL)
		}
	}
	validAfterInt := big.NewInt(validAfter.Unix())
	deadlineInt := big.NewInt(deadline.Unix())

	tokenAddr := common.HexToAddress(a.Asset)
	spenderAddr := common.HexToAddress(X402UptoPermit2ProxyAddress)
	toAddr := common.HexToAddress(a.PayTo)
	facilitatorAddrParsed := common.HexToAddress(facilitatorAddr)
	fromAddr := common.HexToAddress(w.Address)
	permit2Addr := common.HexToAddress(permit2ContractAddress)

	domainSep, err := ComputePermit2DomainSeparator(chainID, permit2Addr)
	if err != nil {
		return nil, fmt.Errorf("permit2 domain separator: %w", err)
	}
	tokenPermHash, err := computeTokenPermissionsStructHash(tokenAddr, amount)
	if err != nil {
		return nil, fmt.Errorf("token permissions struct hash: %w", err)
	}
	witnessHash, err := computePermit2WitnessStructHash(toAddr, facilitatorAddrParsed, validAfterInt)
	if err != nil {
		return nil, fmt.Errorf("witness struct hash: %w", err)
	}
	structHash, err := computePermitWitnessTransferFromStructHash(tokenPermHash, spenderAddr, nonce, deadlineInt, witnessHash)
	if err != nil {
		return nil, fmt.Errorf("permit witness transfer from struct hash: %w", err)
	}
	digest := computeEIP712Digest(domainSep, structHash)

	sig, err := crypto.Sign(digest[:], w.ECDSA)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	// go-ethereum returns [R || S || V] where V is 0 or 1; EVM expects 27 or 28.
	sig[64] += 27
	sigHex := "0x" + common.Bytes2Hex(sig)

	auth := Permit2AuthFields{
		Permitted: TokenPermissions{Token: tokenAddr.Hex(), Amount: a.Amount},
		From:      fromAddr.Hex(),
		Spender:   spenderAddr.Hex(),
		Nonce:     "0x" + nonce.Text(16),
		Deadline:  strconv.FormatInt(deadlineInt.Int64(), 10),
		Witness: Permit2Witness{
			To:          toAddr.Hex(),
			Facilitator: facilitatorAddrParsed.Hex(),
			ValidAfter:  strconv.FormatInt(validAfterInt.Int64(), 10),
		},
	}

	return marshalPermit2Payload(Permit2Payload{Signature: sigHex, Permit2Authorization: auth})
}

// ComputePermit2DomainSeparator builds the EIP-712 domain separator for the
// canonical Permit2 contract itself — NOT the token contract, unlike
// ComputeEIP712DomainSeparator (used for "exact"'s EIP-3009 signing).
func ComputePermit2DomainSeparator(chainID *big.Int, permit2Addr common.Address) ([32]byte, error) {
	domainTypeHash := crypto.Keccak256Hash([]byte(permit2DomainTypeString))
	nameHash := crypto.Keccak256Hash([]byte("Permit2"))

	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)
	addressType, _ := abi.NewType("address", "", nil)

	args := abi.Arguments{
		{Type: bytes32Type},
		{Type: bytes32Type},
		{Type: uint256Type},
		{Type: addressType},
	}
	encoded, err := args.Pack(domainTypeHash, nameHash, chainID, permit2Addr)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func computeTokenPermissionsStructHash(token common.Address, amount *big.Int) ([32]byte, error) {
	typeHash := crypto.Keccak256Hash([]byte(tokenPermissionsTypeString))
	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)

	args := abi.Arguments{{Type: bytes32Type}, {Type: addressType}, {Type: uint256Type}}
	encoded, err := args.Pack(typeHash, token, amount)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func computePermit2WitnessStructHash(to, facilitator common.Address, validAfter *big.Int) ([32]byte, error) {
	typeHash := crypto.Keccak256Hash([]byte(permit2WitnessTypeString))
	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)

	args := abi.Arguments{{Type: bytes32Type}, {Type: addressType}, {Type: addressType}, {Type: uint256Type}}
	encoded, err := args.Pack(typeHash, to, facilitator, validAfter)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

// computePermitWitnessTransferFromStructHash builds the outer struct hash,
// nesting the already-hashed TokenPermissions and Witness sub-structs per
// standard EIP-712 nested-struct encoding.
func computePermitWitnessTransferFromStructHash(
	tokenPermissionsHash [32]byte,
	spender common.Address,
	nonce, deadline *big.Int,
	witnessHash [32]byte,
) ([32]byte, error) {
	typeHash := crypto.Keccak256Hash([]byte(permitWitnessTransferFromTypeString))
	bytes32Type, _ := abi.NewType("bytes32", "", nil)
	addressType, _ := abi.NewType("address", "", nil)
	uint256Type, _ := abi.NewType("uint256", "", nil)

	args := abi.Arguments{
		{Type: bytes32Type}, // typeHash
		{Type: bytes32Type}, // TokenPermissions struct hash
		{Type: addressType}, // spender
		{Type: uint256Type}, // nonce
		{Type: uint256Type}, // deadline
		{Type: bytes32Type}, // Witness struct hash
	}
	encoded, err := args.Pack(typeHash, tokenPermissionsHash, spender, nonce, deadline, witnessHash)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

// ─── chainsign.Signer registration ─────────────────────────────────────────

// signer adapts this package's free functions to chainsign.Signer.
type signer struct{}

func (signer) Namespace() string  { return "eip155" }
func (signer) SupportsUpto() bool { return true }
func (signer) SignExact(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	return SignExact(ctx, a, w)
}
func (signer) SignUpto(ctx context.Context, a chainsign.PaymentAuth, w chainsign.Wallet) (json.RawMessage, error) {
	return SignUpto(ctx, a, w)
}

func init() {
	chainsign.Register(signer{})
}

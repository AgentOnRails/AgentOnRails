// Permit2 signing support for the x402 "upto" payment scheme.
//
// "upto" is a distinct scheme from "exact": the client authorizes a maximum
// amount and the resource server settles for actual usage after the call
// completes, so the signed authorization cannot commit to a final value the
// way EIP-3009's transferWithAuthorization does. x402's spec explicitly
// forbids EIP-3009 for this scheme and requires Uniswap's Permit2
// (permitWitnessTransferFrom) instead — a different EIP-712 domain (the
// canonical Permit2 contract, not the token contract) and a different signed
// struct (TokenPermissions + a recipient/facilitator-binding witness).
//
// Protocol reference: github.com/coinbase/x402/blob/main/specs/schemes/upto/
package x402

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// x402SchemeUpto is the variable-cost x402 scheme: the client signs a
	// maximum, the resource server settles for actual usage.
	x402SchemeUpto = "upto"

	// permit2ContractAddress is Uniswap's canonical Permit2 singleton,
	// deployed at this same address via CREATE2 on essentially every EVM
	// chain (see https://docs.uniswap.org/contracts/v4/deployments).
	permit2ContractAddress = "0x000000000022D473030F116dDEE9F6B43aC78BA"

	// x402UptoPermit2ProxyAddress is the x402 "upto" scheme's own witness
	// proxy contract (x402UptoPermit2Proxy). Per the spec's Annex this is
	// also deployed at a fixed address on every supported chain via
	// CREATE2 — a constant, not something this rail derives.
	x402UptoPermit2ProxyAddress = "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"

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
	// is trusted for a real payment (see docs/ROADMAP.md's identical
	// "built, not yet hand-verified" caveat pattern for the card rail and
	// identity_gate).
	permit2WitnessTypeString            = "Witness(address to,address facilitator,uint256 validAfter)"
	permitWitnessTransferFromTypeString = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,address facilitator,uint256 validAfter)"

	// facilitatorSupportedCacheTTL bounds how often this rail re-fetches the
	// facilitator's /supported endpoint when checking for gas-sponsoring
	// extensions (erc20ApprovalGasSponsoring / eip2612GasSponsoring).
	facilitatorSupportedCacheTTL = 5 * time.Minute

	// permit2AllowanceSelector is the 4-byte selector for
	// ERC20.allowance(address,address).
	permit2AllowanceSelector = "0xdd62ed3e"
)

// ─── Wire types (x402 "upto" / Permit2 witness-transfer payload) ──────────────

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

// Permit2Payload is the "upto" scheme's shape of PaymentPayload.Payload
// (mirrors EIP3009Payload's role for "exact").
type Permit2Payload struct {
	Signature            string             `json:"signature"`
	Permit2Authorization Permit2AuthFields  `json:"permit2Authorization"`
}

func marshalExactPayload(p EIP3009Payload) (json.RawMessage, error) {
	return json.Marshal(p)
}

func marshalPermit2Payload(p Permit2Payload) (json.RawMessage, error) {
	return json.Marshal(p)
}

// ─── Permit2 EIP-712 signing ────────────────────────────────────────────────

// computePermit2DomainSeparator builds the EIP-712 domain separator for the
// canonical Permit2 contract itself — NOT the token contract, unlike
// computeEIP712DomainSeparator (used for "exact"'s EIP-3009 signing).
func computePermit2DomainSeparator(chainID *big.Int, permit2Addr common.Address) ([32]byte, error) {
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

// signPermit2 builds and signs a Permit2 permitWitnessTransferFrom
// authorization for the "upto" scheme's maximum amount. Mirrors signExact's
// shape/error handling but with Permit2's domain and struct instead of
// EIP-3009's.
func (r *X402Rail) signPermit2(
	_ context.Context,
	req *PaymentRequirement,
	resource *ResourceInfo,
	rawURL string,
) (*PaymentPayload, error) {
	network, ok := KnownNetworks[req.Network]
	if !ok {
		return nil, fmt.Errorf("unknown network %s", req.Network)
	}

	facilitatorAddr, ok := req.Extra["facilitatorAddress"].(string)
	if !ok || facilitatorAddr == "" {
		return nil, fmt.Errorf("upto scheme: payment requirement is missing extra.facilitatorAddress")
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("upto scheme: cannot parse max amount %q", req.Amount)
	}

	// Random 32-byte nonce. Permit2's SignatureTransfer checks nonces
	// against a per-owner bitmap (wordPos/bit derived from the nonce value
	// itself) rather than a monotonic counter, so any unused random uint256
	// is valid — the same randomness approach signExact already uses for
	// EIP-3009's nonce.
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonce := new(big.Int).SetBytes(nonceBytes)

	now := time.Now().UTC()
	validAfter := now.Add(-5 * time.Second)
	deadline := now.Add(r.policy.PayloadTTL)
	if req.MaxTimeoutSeconds > 0 {
		serverTTL := time.Duration(req.MaxTimeoutSeconds) * time.Second
		if serverTTL < r.policy.PayloadTTL {
			deadline = now.Add(serverTTL)
		}
	}
	validAfterInt := big.NewInt(validAfter.Unix())
	deadlineInt := big.NewInt(deadline.Unix())

	tokenAddr := common.HexToAddress(req.Asset)
	spenderAddr := common.HexToAddress(x402UptoPermit2ProxyAddress)
	toAddr := common.HexToAddress(req.PayTo)
	facilitatorAddrParsed := common.HexToAddress(facilitatorAddr)
	fromAddr := common.HexToAddress(r.policy.WalletAddress)
	permit2Addr := common.HexToAddress(permit2ContractAddress)

	domainSep, err := computePermit2DomainSeparator(big.NewInt(network.ChainID), permit2Addr)
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

	sig, err := crypto.Sign(digest[:], r.policy.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	// go-ethereum returns [R || S || V] where V is 0 or 1; EVM expects 27 or 28.
	sig[64] += 27
	sigHex := "0x" + common.Bytes2Hex(sig)

	auth := Permit2AuthFields{
		Permitted: TokenPermissions{Token: tokenAddr.Hex(), Amount: req.Amount},
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

	rawPayload, err := marshalPermit2Payload(Permit2Payload{Signature: sigHex, Permit2Authorization: auth})
	if err != nil {
		return nil, fmt.Errorf("marshal permit2 payload: %w", err)
	}

	var res *ResourceInfo
	if resource != nil {
		res = resource
	} else if rawURL != "" {
		res = &ResourceInfo{URL: rawURL}
	}

	return &PaymentPayload{
		X402Version: x402Version,
		Accepted:    *req,
		Resource:    res,
		Payload:     rawPayload,
	}, nil
}

// ─── Facilitator /supported discovery (gas-sponsoring extensions) ────────────

type supportedKind struct {
	Scheme  string         `json:"scheme"`
	Network string         `json:"network"`
	Extra   map[string]any `json:"extra,omitempty"`
}

// supportedResponse is the shape of a facilitator's GET /supported response.
type supportedResponse struct {
	Kinds      []supportedKind `json:"kinds"`
	Extensions []string        `json:"extensions"`
}

func (s *supportedResponse) hasExtension(name string) bool {
	if s == nil {
		return false
	}
	for _, e := range s.Extensions {
		if e == name {
			return true
		}
	}
	return false
}

// facilitatorSupported fetches and caches the facilitator's /supported
// response, used to discover gas-sponsoring extensions
// (erc20ApprovalGasSponsoring / eip2612GasSponsoring) before requiring a
// manual Permit2 approval from the operator.
func (r *X402Rail) facilitatorSupported(ctx context.Context) (*supportedResponse, error) {
	r.supportedMu.Lock()
	defer r.supportedMu.Unlock()

	if r.supportedCache != nil && time.Since(r.supportedFetchedAt) < facilitatorSupportedCacheTTL {
		return r.supportedCache, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, r.policy.FacilitatorURL+"/supported", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("facilitator /supported unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out supportedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("facilitator /supported response parse: %w", err)
	}
	r.supportedCache = &out
	r.supportedFetchedAt = time.Now()
	return r.supportedCache, nil
}

// ─── Permit2 allowance preflight ───────────────────────────────────────────

// ensurePermit2Allowance checks (and caches, per owner+token+network) that
// owner has already approved the canonical Permit2 contract to spend at
// least maxAmount of token. If not, it looks for a facilitator-advertised
// gas-sponsoring extension before failing closed — this rail does not
// broadcast its own gas-paying approval transaction (that would reintroduce
// the "agent needs native gas" requirement x402's EIP-3009 gasless design
// deliberately avoids for "exact").
func (r *X402Rail) ensurePermit2Allowance(ctx context.Context, owner, token common.Address, network NetworkInfo, maxAmount *big.Int) error {
	if network.RPCURL == "" {
		return fmt.Errorf("no RPC endpoint configured for network %s — cannot check Permit2 allowance for the upto scheme", network.Name)
	}

	cacheKey := owner.Hex() + "|" + token.Hex() + "|" + network.RPCURL
	r.allowanceMu.Lock()
	if r.allowanceOK == nil {
		r.allowanceOK = make(map[string]bool)
	}
	already := r.allowanceOK[cacheKey]
	r.allowanceMu.Unlock()
	if already {
		return nil
	}

	allowance, err := r.readAllowance(ctx, network.RPCURL, token, owner, common.HexToAddress(permit2ContractAddress))
	if err != nil {
		return fmt.Errorf("check Permit2 allowance: %w", err)
	}
	if allowance.Cmp(maxAmount) >= 0 {
		r.allowanceMu.Lock()
		r.allowanceOK[cacheKey] = true
		r.allowanceMu.Unlock()
		return nil
	}

	supported, suppErr := r.facilitatorSupported(ctx)
	if suppErr == nil && (supported.hasExtension("erc20ApprovalGasSponsoring") || supported.hasExtension("eip2612GasSponsoring")) {
		return fmt.Errorf(
			"wallet %s has not approved Permit2 to spend %s on %s; the facilitator advertises a gas-sponsoring extension for this, but automatic sponsored approval is not yet implemented in this rail (its invocation shape is undocumented) — run a one-time manual on-chain approve(%s, <allowance>) from this wallet, then retry",
			owner.Hex(), token.Hex(), network.Name, permit2ContractAddress,
		)
	}
	return fmt.Errorf(
		"wallet %s has not approved Permit2 to spend %s on %s and the facilitator offers no gas-sponsoring extension — run a one-time manual on-chain approve(%s, <allowance>) from this wallet, then retry",
		owner.Hex(), token.Hex(), network.Name, permit2ContractAddress,
	)
}

// readAllowance calls ERC20.allowance(owner, spender) via a raw eth_call
// JSON-RPC request — the same hand-rolled pattern scripts/demo's
// usdcBalance already uses, deliberately avoiding go-ethereum's
// ethclient/rpc packages (and their large transitive dependency tree) for a
// single read-only call.
func (r *X402Rail) readAllowance(ctx context.Context, rpcURL string, token, owner, spender common.Address) (*big.Int, error) {
	selectorBytes := common.FromHex(permit2AllowanceSelector)
	data := append(append([]byte{}, selectorBytes...),
		append(common.LeftPadBytes(owner.Bytes(), 32), common.LeftPadBytes(spender.Bytes(), 32)...)...)
	callData := "0x" + common.Bytes2Hex(data)

	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": token.Hex(), "data": callData},
			"latest",
		},
	})
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", out.Error.Message)
	}
	hexResult := strings.TrimPrefix(out.Result, "0x")
	if hexResult == "" {
		return big.NewInt(0), nil
	}
	val, ok := new(big.Int).SetString(hexResult, 16)
	if !ok {
		return nil, fmt.Errorf("unexpected eth_call result %q", out.Result)
	}
	return val, nil
}

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
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign/eip155"
)

const (
	// x402SchemeUpto is the variable-cost x402 scheme: the client signs a
	// maximum, the resource server settles for actual usage.
	x402SchemeUpto = "upto"

	// permit2ContractAddress is Uniswap's canonical Permit2 singleton,
	// deployed at this same address via CREATE2 on essentially every EVM
	// chain (see https://docs.uniswap.org/contracts/v4/deployments) — used
	// here only by the allowance preflight below; the signing side of this
	// address lives in chainsign/eip155 now.
	permit2ContractAddress = "0x000000000022D473030F116dDEE9F6B43aC78BA"

	// x402UptoPermit2ProxyAddress mirrors chainsign/eip155's exported
	// constant of the same value, kept here under its historical unexported
	// name only because permit2_test.go references it directly.
	x402UptoPermit2ProxyAddress = eip155.X402UptoPermit2ProxyAddress

	// facilitatorSupportedCacheTTL bounds how often this rail re-fetches the
	// facilitator's /supported endpoint when checking for gas-sponsoring
	// extensions (erc20ApprovalGasSponsoring / eip2612GasSponsoring).
	facilitatorSupportedCacheTTL = 5 * time.Minute

	// permit2AllowanceSelector is the 4-byte selector for
	// ERC20.allowance(address,address).
	permit2AllowanceSelector = "0xdd62ed3e"
)

// ─── Wire types (x402 "upto" / Permit2 witness-transfer payload) ──────────────
// Type aliases (not new types) for chainsign/eip155's definitions — the
// actual Permit2 signing logic lives there now (see signPermit2 below), but
// these names stay valid at the x402 package level since existing code and
// tests decode payloads as x402.Permit2Payload etc.

type TokenPermissions = eip155.TokenPermissions
type Permit2Witness = eip155.Permit2Witness
type Permit2AuthFields = eip155.Permit2AuthFields
type Permit2Payload = eip155.Permit2Payload

// computePermit2DomainSeparator is bound to chainsign/eip155's exported
// implementation so existing white-box tests in this package that call it
// directly by its historical unexported name keep working unmodified.
var computePermit2DomainSeparator = eip155.ComputePermit2DomainSeparator

// signPermit2 is kept only because existing tests call it directly to drive
// Permit2 signing in isolation — production code reaches the same eip155
// signer through signPayment's namespace dispatch (rail.go). Not
// chain-agnostic by design: the name (and the tests using it) predate
// chainsign existing.
func (r *X402Rail) signPermit2(
	ctx context.Context,
	req *PaymentRequirement,
	resource *ResourceInfo,
	rawURL string,
) (*PaymentPayload, error) {
	rawPayload, err := eip155.SignUpto(ctx, chainsign.PaymentAuth{
		Network:           req.Network,
		Asset:             req.Asset,
		PayTo:             req.PayTo,
		Amount:            req.Amount,
		MaxTimeoutSeconds: req.MaxTimeoutSeconds,
		Extra:             req.Extra,
		PayloadTTL:        r.policy.PayloadTTL,
	}, chainsign.Wallet{
		Address: r.policy.WalletAddress,
		ECDSA:   r.policy.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	return &PaymentPayload{
		X402Version: x402Version,
		Accepted:    *req,
		Resource:    resourceOrURL(resource, rawURL),
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

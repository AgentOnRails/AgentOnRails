// Package x402 implements AgentOnRails' x402 payment rail.
//
// x402 is an HTTP-native payment protocol that uses the HTTP 402 Payment Required
// status code. When an agent requests a paid resource the server returns 402 with a
// PAYMENT-REQUIRED header containing a base64-encoded JSON challenge. AgentOnRails
// intercepts this, evaluates it against policy, constructs a signed EIP-3009
// payload, and retries the request with a PAYMENT-SIGNATURE header. The upstream
// verifies the signature via a facilitator (Coinbase CDP or x402.org) and returns
// the resource if payment is valid.
//
// Protocol references:
//   - Spec:         github.com/coinbase/x402/blob/main/specs/x402-specification.md
//   - Go SDK types: pkg.go.dev/github.com/coinbase/x402/go/types
//   - EIP-3009:     eips.ethereum.org/EIPS/eip-3009
//   - CAIP-2:       github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
//
// AgentOnRails acts as the x402 client on behalf of the agent. The agent itself
// never holds wallet keys — AgentOnRails manages them in an encrypted vault and
// performs all signing. The agent simply points its HTTP client at the proxy port
// and AgentOnRails handles the rest transparently.
package x402

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/rail"
)

// ─── Protocol constants ────────────────────────────────────────────────────────

const (
	// x402 V2 header names.
	headerPaymentRequired = "PAYMENT-REQUIRED"
	headerPaymentSig      = "PAYMENT-SIGNATURE"
	headerPaymentResponse = "PAYMENT-RESPONSE"

	// x402 V1 header names. In V1 the challenge is carried in the 402 JSON body
	// (no PAYMENT-REQUIRED header); the client replies with the signed payload in
	// X-PAYMENT and reads the settlement result from X-PAYMENT-RESPONSE.
	headerV1Payment         = "X-PAYMENT"
	headerV1PaymentResponse = "X-PAYMENT-RESPONSE"

	// AgentOnRails identification headers set by the agent.
	headerSentinelAgent = "X-Sentinel-Agent"
	headerSentinelTask  = "X-Sentinel-Task"

	// x402 protocol versions.
	x402Version   = 2 // default targeted by this rail
	x402VersionV1 = 1

	// EIP-3009 transferWithAuthorization type string used in EIP-712 domain.
	eip3009TypeString = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"

	// EIP-712 domain type string for USDC on EVM chains.
	eip712DomainTypeString = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"

	// Facilitator endpoints.
	FacilitatorCDP     = "https://api.cdp.coinbase.com/platform/v2/x402" // enterprise CDP endpoint
	FacilitatorX402Org = "https://x402.org/facilitator"                  // Coinbase-operated public facilitator (default)

	facilitatorVerifyPath = "/verify"
	facilitatorSettlePath = "/settle"

	// Maximum time we will wait for upstream or facilitator responses.
	defaultUpstreamTimeout    = 10 * time.Second
	defaultFacilitatorTimeout = 5 * time.Second

	// x402 payment payloads include a validBefore unix timestamp. We add this
	// buffer to now() when constructing the authorization so the facilitator
	// has enough time to verify before the payload expires. 60 seconds matches
	// the maxTimeoutSeconds typically advertised by servers.
	defaultPayloadTTL = 60 * time.Second

	// x402SchemeExact is the only payment scheme this rail supports.
	// Other schemes (e.g. "usd-amount") use different signing mechanisms and
	// would produce invalid signatures if selected.
	x402SchemeExact = "exact"
)

// ─── CAIP-2 network identifiers ───────────────────────────────────────────────

// KnownNetworks maps CAIP-2 identifiers to their chain IDs and USDC addresses.
// Used for validation: AgentOnRails rejects payment challenges that reference an
// unknown or unconfigured network even if the amount passes policy checks.
var KnownNetworks = map[string]NetworkInfo{
	// EVM mainnet
	// RPCURL is only populated where a well-known, stable public endpoint is
	// available with confidence — it's only consulted by the "upto" scheme's
	// allowance preflight, and an empty value there just fails that preflight
	// closed with a clear error rather than guessing at a possibly-stale URL.
	"eip155:1":     {ChainID: 1, Name: "Ethereum Mainnet", USDCAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", RPCURL: "https://cloudflare-eth.com"},
	"eip155:8453":  {ChainID: 8453, Name: "Base", USDCAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", RPCURL: "https://mainnet.base.org"},
	"eip155:137":   {ChainID: 137, Name: "Polygon", USDCAddress: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"},
	"eip155:10":    {ChainID: 10, Name: "Optimism", USDCAddress: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"},
	"eip155:42161": {ChainID: 42161, Name: "Arbitrum One", USDCAddress: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"},
	"eip155:43114": {ChainID: 43114, Name: "Avalanche C-Chain", USDCAddress: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"},

	// EVM testnet
	"eip155:84532": {ChainID: 84532, Name: "Base Sepolia", USDCAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", RPCURL: "https://sepolia.base.org"},
	"eip155:80001": {ChainID: 80001, Name: "Polygon Mumbai", USDCAddress: "0x9999f7Fea5938fD3b1E26A12c3f2fb024e194f97"},

	// Solana (not EVM — handled by separate SVM signer, included for allowlist validation)
	"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": {ChainID: 0, Name: "Solana Mainnet"},
	"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": {ChainID: 0, Name: "Solana Devnet"},
}

// NetworkInfo holds chain metadata used during policy validation and signing.
type NetworkInfo struct {
	ChainID     int64  // EVM chain ID (0 for non-EVM)
	Name        string // Human-readable name for logs and alerts
	USDCAddress string // Canonical USDC contract address on this chain
	// RPCURL is a public JSON-RPC endpoint for this network, used only by
	// the "upto" scheme's Permit2 allowance preflight (ensurePermit2Allowance
	// in permit2.go). Empty means that preflight fails closed with a clear
	// error on this network — harmless for "exact", which never reads it.
	RPCURL string
}

// v1NetworkToCAIP2 maps x402 V1 network slugs (e.g. "base-sepolia") to their
// CAIP-2 identifiers. V1 challenges name networks by slug; internally the rail
// works exclusively in CAIP-2, so V1 slugs are normalized on the way in and
// converted back when emitting a V1 payment payload. Only slugs whose CAIP-2 is
// in KnownNetworks are listed — anything else is left untouched and rejected
// later by selectRequirement.
var v1NetworkToCAIP2 = map[string]string{
	"ethereum":     "eip155:1",
	"base":         "eip155:8453",
	"base-sepolia": "eip155:84532",
	"polygon":      "eip155:137",
	"optimism":     "eip155:10",
	"arbitrum":     "eip155:42161",
	"avalanche":    "eip155:43114",
}

// caip2ToV1Network is the reverse of v1NetworkToCAIP2, built at init.
var caip2ToV1Network = func() map[string]string {
	m := make(map[string]string, len(v1NetworkToCAIP2))
	for slug, caip := range v1NetworkToCAIP2 {
		m[caip] = slug
	}
	return m
}()

// normalizeNetwork converts an x402 V1 network slug to its CAIP-2 identifier.
// CAIP-2 inputs and unrecognized slugs are returned unchanged.
func normalizeNetwork(n string) string {
	if _, ok := KnownNetworks[n]; ok {
		return n
	}
	if caip, ok := v1NetworkToCAIP2[n]; ok {
		return caip
	}
	return n
}

// v1NetworkName converts a CAIP-2 identifier back to its x402 V1 slug. When no
// slug is known the CAIP-2 string is returned as a best-effort fallback.
func v1NetworkName(caip string) string {
	if slug, ok := caip2ToV1Network[caip]; ok {
		return slug
	}
	return caip
}

// ─── Wire types (x402 protocol messages) ──────────────────────────────────────

// PaymentRequired is the decoded body of a PAYMENT-REQUIRED header (base64 JSON).
type PaymentRequired struct {
	X402Version int                  `json:"x402Version"`
	Accepts     []PaymentRequirement `json:"accepts"`
	Error       string               `json:"error,omitempty"`
	Resource    *ResourceInfo        `json:"resource,omitempty"`
	Extensions  map[string]any       `json:"extensions,omitempty"`
}

// PaymentRequirement is one entry in the PaymentRequired.Accepts slice.
type PaymentRequirement struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Amount  string `json:"amount"`
	// MaxAmountRequired is the x402 V1 spelling of Amount. It is normalized into
	// Amount after parsing so downstream code only reads Amount.
	MaxAmountRequired string         `json:"maxAmountRequired,omitempty"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
	Description       string         `json:"description,omitempty"`
	MimeType          string         `json:"mimeType,omitempty"`
}

// ResourceInfo describes the resource being purchased.
type ResourceInfo struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// PaymentPayload is the signed payload attached to the PAYMENT-SIGNATURE header.
// Payload is raw JSON because its shape depends on the chosen scheme:
// EIP3009Payload for "exact", Permit2Payload for "upto" (see permit2.go).
type PaymentPayload struct {
	X402Version int                `json:"x402Version"`
	Accepted    PaymentRequirement `json:"accepted"`
	Resource    *ResourceInfo      `json:"resource,omitempty"`
	Payload     json.RawMessage    `json:"payload"`
	Extensions  map[string]any     `json:"extensions,omitempty"`
}

// EIP3009Payload contains the cryptographic proof.
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

// FacilitatorVerifyRequest is the body posted to /verify.
type FacilitatorVerifyRequest struct {
	PaymentPayload      PaymentPayload     `json:"paymentPayload"`
	PaymentRequirements PaymentRequirement `json:"paymentRequirements"`
}

// ─── x402 V1 wire types ────────────────────────────────────────────────────────
// V1 uses a flatter payload than V2: the X-PAYMENT header carries the scheme and
// network alongside the EIP-3009 proof, and the network is a slug rather than a
// CAIP-2 identifier.

// v1PaymentPayload is the base64-decoded body of the X-PAYMENT header.
type v1PaymentPayload struct {
	X402Version int             `json:"x402Version"`
	Scheme      string          `json:"scheme"`
	Network     string          `json:"network"` // V1 slug, e.g. "base-sepolia"
	Payload     json.RawMessage `json:"payload"`
}

// v1PaymentRequirements is the requirement shape a V1 facilitator's /verify
// endpoint expects (maxAmountRequired, slug network, string resource).
type v1PaymentRequirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	MaxAmountRequired string         `json:"maxAmountRequired"`
	Resource          string         `json:"resource"`
	Description       string         `json:"description"`
	MimeType          string         `json:"mimeType"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Asset             string         `json:"asset"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// v1VerifyRequest is the body posted to a V1 facilitator's /verify endpoint.
type v1VerifyRequest struct {
	X402Version         int                   `json:"x402Version"`
	PaymentPayload      v1PaymentPayload      `json:"paymentPayload"`
	PaymentRequirements v1PaymentRequirements `json:"paymentRequirements"`
}

// FacilitatorVerifyResponse is the body returned from /verify.
type FacilitatorVerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason,omitempty"`
	Payer         string `json:"payer,omitempty"`
}

// PaymentResponse is the decoded PAYMENT-RESPONSE header returned on 200 OK.
type PaymentResponse struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction,omitempty"`
	Network     string `json:"network,omitempty"`
	Payer       string `json:"payer,omitempty"`
	ErrorReason string `json:"errorReason,omitempty"`
	// Amount is the "upto" scheme's SettlementResponse extension: the actual
	// atomic-unit amount charged (may be "0"). Unused for "exact", where the
	// charged amount is already known from the requirement itself.
	Amount string `json:"amount,omitempty"`
}

// ─── Policy types ──────────────────────────────────────────────────────────────

// X402Policy defines the spend controls AgentOnRails enforces on behalf of an agent.
type X402Policy struct {
	// Wallet
	WalletAddress  string
	PrivateKey     *ecdsa.PrivateKey
	PreferredChain string

	// Facilitator
	FacilitatorURL string

	// Spend limits (all amounts are in USD cents for integer arithmetic)
	PerCallMaxCents   int64
	DailyLimitCents   int64
	WeeklyLimitCents  int64
	MonthlyLimitCents int64

	// Endpoint policy
	AllowedHosts []string
	BlockedHosts []string
	EndpointMode string // "allowlist" | "blocklist" | "open"

	// Network allowlist
	AllowedNetworks []string

	// Timeouts
	UpstreamTimeout    time.Duration
	FacilitatorTimeout time.Duration
	PayloadTTL         time.Duration

	// Human approval gate
	RequireApprovalAboveCents int64
	ApprovalFunc              func(ctx context.Context, req ApprovalRequest) (bool, error)
	// ApprovalTimeout bounds how long ApprovalFunc may block before this
	// rail treats the payment as denied (see Factory, which wires
	// ApprovalFunc to approval.Registry.Await using this value). Zero means
	// "use approval.DefaultTimeout" — Await's own fallback, not duplicated
	// here.
	ApprovalTimeout time.Duration

	// SkipPreVerify disables the pre-verification call to the facilitator.
	// When false (default), Sentinel calls /verify before retrying the request.
	SkipPreVerify bool

	// AllowUpto opts an agent into the x402 "upto" scheme (authorize a max,
	// resource server settles actual usage after the call). Default false:
	// "exact" is always preferred when a challenge offers both, and "upto" is
	// never selected at all unless this is set — see selectRequirement. Off
	// by default because "upto" shifts trust from "I know the exact price
	// before I pay" to "I trust the server to bill me fairly afterward" (the
	// scheme's own spec names this risk explicitly), which should be a
	// conscious per-agent choice, not a silent default.
	AllowUpto bool

	// Velocity limits (0 = use rail defaults: 30/min, 200/hr, 60s cooldown)
	VelocityMaxPerMinute    int
	VelocityMaxPerHour      int
	VelocityCooldownSeconds int

	// UpstreamTLSConfig overrides the TLS config used for outbound HTTPS calls to
	// upstreams and facilitators. Normally nil (system trust store). Used to trust
	// a custom CA or, in tests, a self-signed upstream. It does not affect the
	// certificate AgentOnRails presents to intercepted clients (that is the MITM CA).
	UpstreamTLSConfig *tls.Config
}

// skipPreVerify returns p.SkipPreVerify. Kept as a method for future extension.
func (p *X402Policy) skipPreVerify() bool {
	return p.SkipPreVerify
}

// ApprovalRequest is passed to ApprovalFunc when a payment exceeds the threshold.
type ApprovalRequest struct {
	AgentID     string
	Endpoint    string
	AmountCents int64
	TaskContext string
}

// ─── Velocity limiter ──────────────────────────────────────────────────────────

// VelocityLimiter tracks request counts in a sliding window. Safe for concurrent use.
type VelocityLimiter struct {
	mu              sync.Mutex
	maxPerMinute    int
	maxPerHour      int
	cooldownSeconds int
	minuteWindow    []time.Time
	hourWindow      []time.Time
	blockedUntil    time.Time
}

func velocityOrDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func NewVelocityLimiter(maxPerMinute, maxPerHour, cooldownSeconds int) *VelocityLimiter {
	return &VelocityLimiter{
		maxPerMinute:    maxPerMinute,
		maxPerHour:      maxPerHour,
		cooldownSeconds: cooldownSeconds,
	}
}

// Allow returns nil if the request is within velocity limits, or an error
// describing which limit was hit. If allowed, it records the timestamp.
func (v *VelocityLimiter) Allow() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	if now.Before(v.blockedUntil) {
		return fmt.Errorf("velocity_cooldown: retry after %s",
			v.blockedUntil.Format(time.RFC3339))
	}

	cutMinute := now.Add(-time.Minute)
	cutHour := now.Add(-time.Hour)
	v.minuteWindow = filterAfter(v.minuteWindow, cutMinute)
	v.hourWindow = filterAfter(v.hourWindow, cutHour)

	if v.maxPerMinute > 0 && len(v.minuteWindow) >= v.maxPerMinute {
		v.blockedUntil = now.Add(time.Duration(v.cooldownSeconds) * time.Second)
		return fmt.Errorf("velocity_exceeded: %d req/min limit hit", v.maxPerMinute)
	}
	if v.maxPerHour > 0 && len(v.hourWindow) >= v.maxPerHour {
		v.blockedUntil = now.Add(time.Duration(v.cooldownSeconds) * time.Second)
		return fmt.Errorf("velocity_exceeded: %d req/hour limit hit", v.maxPerHour)
	}

	v.minuteWindow = append(v.minuteWindow, now)
	v.hourWindow = append(v.hourWindow, now)
	return nil
}

func filterAfter(ts []time.Time, after time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(after) {
			out = append(out, t)
		}
	}
	return out
}

// ─── x402 Rail ────────────────────────────────────────────────────────────────

// X402Rail is the payment rail adapter for x402 crypto payments. It satisfies
// the rail.Rail interface.
type X402Rail struct {
	policy     *X402Policy
	budget     *rail.BudgetTracker
	velocity   *VelocityLimiter
	logger     *zap.Logger
	httpClient *http.Client
	auditLog   rail.AuditLogger

	// supportedCache/supportedFetchedAt cache the facilitator's /supported
	// response (used by the "upto" scheme's allowance preflight). Zero
	// values are safe — populated lazily on first use.
	supportedMu        sync.Mutex
	supportedCache     *supportedResponse
	supportedFetchedAt time.Time

	// allowanceOK caches "upto" Permit2-allowance preflight successes per
	// owner+token+network, so it's only checked on-chain once. Nil map is
	// safe — initialized lazily on first use.
	allowanceMu sync.Mutex
	allowanceOK map[string]bool
}

var _ rail.Rail = (*X402Rail)(nil)

// NewX402Rail creates a rail from a policy. The policy must already have a
// populated PrivateKey (decrypted from wallet.enc by the daemon's vault).
func NewX402Rail(policy *X402Policy, audit rail.AuditLogger, logger *zap.Logger) (*X402Rail, error) {
	if policy.PrivateKey == nil {
		return nil, errors.New("x402 rail: private key is nil — wallet not loaded")
	}
	if policy.FacilitatorURL == "" {
		policy.FacilitatorURL = FacilitatorX402Org
	}
	if policy.UpstreamTimeout == 0 {
		policy.UpstreamTimeout = defaultUpstreamTimeout
	}
	if policy.FacilitatorTimeout == 0 {
		policy.FacilitatorTimeout = defaultFacilitatorTimeout
	}
	if policy.PayloadTTL == 0 {
		policy.PayloadTTL = defaultPayloadTTL
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if policy.UpstreamTLSConfig != nil {
		transport.TLSClientConfig = policy.UpstreamTLSConfig
	}

	return &X402Rail{
		policy:   policy,
		budget:   rail.NewBudgetTracker(policy.DailyLimitCents, policy.WeeklyLimitCents, policy.MonthlyLimitCents),
		velocity: NewVelocityLimiter(
			velocityOrDefault(policy.VelocityMaxPerMinute, 30),
			velocityOrDefault(policy.VelocityMaxPerHour, 200),
			velocityOrDefault(policy.VelocityCooldownSeconds, 60),
		),
		logger: logger,
		httpClient: &http.Client{
			Timeout:   policy.UpstreamTimeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		auditLog: audit,
	}, nil
}

// Budget returns the rail's BudgetTracker (used by the daemon for rehydration).
func (r *X402Rail) Budget() *rail.BudgetTracker { return r.budget }

// ProxyRequest is the main entry point. The daemon calls this for every inbound
// request routed to the x402 rail.
func (r *X402Rail) ProxyRequest(
	ctx context.Context,
	w http.ResponseWriter,
	req *http.Request,
	agentID string,
	taskContext string,
) {
	start := time.Now()
	record := rail.TransactionRecord{
		ID:          newUUID(),
		AgentID:     agentID,
		Timestamp:   start,
		RailType:    "x402",
		Endpoint:    req.URL.String(),
		Method:      req.Method,
		TaskContext: taskContext,
		CallerDID:   rail.CallerDIDFromContext(ctx),
		Status:      "blocked",
	}
	defer func() {
		record.LatencyMS = time.Since(start).Milliseconds()
		if err := r.auditLog.LogTransaction(record); err != nil {
			r.logger.Error("audit log write failed", zap.Error(err))
		}
	}()

	// ── Step 1: Endpoint policy ──────────────────────────────────────────────
	if err := r.checkEndpoint(req.URL); err != nil {
		record.BlockReason = err.Error()
		r.logger.Info("x402 request blocked (endpoint)",
			zap.String("agent", agentID),
			zap.String("url", req.URL.String()),
			zap.Error(err),
		)
		http.Error(w, fmt.Sprintf("aor: %s", err.Error()), http.StatusForbidden)
		return
	}

	// ── Step 2: Velocity check ───────────────────────────────────────────────
	if err := r.velocity.Allow(); err != nil {
		record.BlockReason = err.Error()
		http.Error(w, fmt.Sprintf("aor: %s", err.Error()), http.StatusTooManyRequests)
		return
	}

	// ── Step 3: Forward original request ────────────────────────────────────
	upstreamReq, err := r.buildUpstreamRequest(ctx, req)
	if err != nil {
		record.BlockReason = "upstream_request_build_error"
		http.Error(w, "aor: internal error", http.StatusInternalServerError)
		r.logger.Error("failed to build upstream request", zap.Error(err))
		return
	}

	resp, err := r.httpClient.Do(upstreamReq)
	if err != nil {
		record.BlockReason = "upstream_unreachable"
		http.Error(w, "aor: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// ── Step 4: Non-402 → pass through ──────────────────────────────────────
	if resp.StatusCode != http.StatusPaymentRequired {
		record.Status = "allowed"
		record.AmountUSD = 0
		copyResponse(w, resp)
		return
	}

	// ── Step 5: Detect x402 vs plain 402 ────────────────────────────────────
	if !looksLikeX402Challenge(resp) {
		record.Status = "passthrough_402"
		record.BlockReason = "non_x402_payment_required"
		r.logger.Info("passing through non-x402 402 response",
			zap.String("agent", agentID),
			zap.String("url", req.URL.String()),
		)
		copyResponse(w, resp)
		return
	}

	// ── Step 6: Parse the x402 challenge ─────────────────────────────────────
	challenge, variant, err := r.parsePaymentRequired(resp)
	if err != nil {
		record.BlockReason = "invalid_payment_required_header"
		r.logger.Warn("malformed x402 challenge",
			zap.String("url", req.URL.String()),
			zap.Error(err),
		)
		http.Error(w, "aor: upstream sent malformed x402 challenge", http.StatusBadGateway)
		return
	}
	r.logger.Debug("x402 challenge parsed",
		zap.String("agent", agentID),
		zap.String("protocol", variant.String()),
	)

	// ── Step 7: Select best matching requirement ─────────────────────────────
	chosen, err := r.selectRequirement(challenge)
	if err != nil {
		record.BlockReason = "no_acceptable_payment_option"
		r.logger.Info("no acceptable payment option",
			zap.String("agent", agentID),
			zap.Any("accepts", challenge.Accepts),
		)
		http.Error(w, fmt.Sprintf("aor: %s", err.Error()), http.StatusForbidden)
		return
	}

	// ── Step 8: Budget checks ────────────────────────────────────────────────
	amountCents, amountRaw, err := r.parsePriceToCents(chosen.Amount, chosen.Asset, chosen.Network)
	if err != nil {
		record.BlockReason = "amount_parse_error"
		http.Error(w, "aor: cannot parse payment amount", http.StatusInternalServerError)
		return
	}

	if r.policy.PerCallMaxCents > 0 && amountCents > r.policy.PerCallMaxCents {
		record.BlockReason = fmt.Sprintf("per_call_max_exceeded: %d > %d cents", amountCents, r.policy.PerCallMaxCents)
		http.Error(w, fmt.Sprintf("aor: amount exceeds per-call max ($%.4f > $%.4f)",
			float64(amountCents)/100, float64(r.policy.PerCallMaxCents)/100),
			http.StatusForbidden,
		)
		return
	}

	if err := r.budget.Reserve(amountCents); err != nil {
		record.BlockReason = err.Error()
		http.Error(w, fmt.Sprintf("aor: %s", err.Error()), http.StatusForbidden)
		return
	}
	// Budget reserved. On any failure below, refund it.
	budgetReserved := true
	defer func() {
		if budgetReserved && record.Status != "allowed" {
			r.budget.Refund(amountCents)
		}
	}()

	// ── Step 9: Human approval gate ──────────────────────────────────────────
	if r.policy.RequireApprovalAboveCents > 0 && amountCents > r.policy.RequireApprovalAboveCents {
		if r.policy.ApprovalFunc == nil {
			record.BlockReason = "approval_required_but_no_approver_configured"
			http.Error(w, "aor: approval required but no approval channel configured", http.StatusForbidden)
			return
		}
		approved, err := r.policy.ApprovalFunc(ctx, ApprovalRequest{
			AgentID:     agentID,
			Endpoint:    req.URL.String(),
			AmountCents: amountCents,
			TaskContext: taskContext,
		})
		if err != nil {
			record.BlockReason = "approval_timeout_or_error"
			http.Error(w, "aor: approval request failed", http.StatusForbidden)
			return
		}
		if !approved {
			record.BlockReason = "approval_denied_by_human"
			http.Error(w, "aor: payment denied by approver", http.StatusForbidden)
			return
		}
	}

	// ── Step 10: Sign payment authorization ──────────────────────────────────
	// "upto" needs a one-time Permit2 approval in place before it can sign —
	// checked/preflighted here, ahead of signing, so a missing approval blocks
	// cleanly instead of producing a signature the facilitator will reject.
	if chosen.Scheme == x402SchemeUpto {
		network, ok := KnownNetworks[chosen.Network]
		if !ok {
			record.BlockReason = "unknown_network_for_upto_preflight"
			http.Error(w, "aor: unknown network", http.StatusInternalServerError)
			return
		}
		maxAmount, ok := new(big.Int).SetString(chosen.Amount, 10)
		if !ok {
			record.BlockReason = "amount_parse_error"
			http.Error(w, "aor: cannot parse payment amount", http.StatusInternalServerError)
			return
		}
		walletAddr := common.HexToAddress(r.policy.WalletAddress)
		tokenAddr := common.HexToAddress(chosen.Asset)
		if err := r.ensurePermit2Allowance(ctx, walletAddr, tokenAddr, network, maxAmount); err != nil {
			record.BlockReason = "permit2_allowance_preflight_failed: " + err.Error()
			r.logger.Info("upto payment blocked: Permit2 allowance preflight failed",
				zap.String("agent", agentID), zap.Error(err))
			http.Error(w, fmt.Sprintf("aor: upto scheme: %s", err.Error()), http.StatusForbidden)
			return
		}
	}

	payload, err := r.signPayment(ctx, chosen, challenge.Resource, req.URL.String())
	if err != nil {
		record.BlockReason = "signing_error: " + err.Error()
		r.logger.Error("payment signing failed", zap.Error(err))
		http.Error(w, "aor: payment signing failed", http.StatusInternalServerError)
		return
	}

	// ── Step 11: Optional facilitator pre-verification ───────────────────────
	if !r.policy.skipPreVerify() {
		if err := r.preVerify(ctx, payload, chosen, variant); err != nil {
			record.BlockReason = "facilitator_pre_verify_failed: " + err.Error()
			r.logger.Warn("facilitator pre-verify rejected payload", zap.Error(err))
			http.Error(w, "aor: payment pre-verification failed", http.StatusPaymentRequired)
			return
		}
	}

	// ── Step 12: Retry with payment signature ────────────────────────────────
	// The reply format depends on the challenge variant: V2 uses the
	// PAYMENT-SIGNATURE header with the full payload; V1 uses X-PAYMENT with the
	// flatter V1 payload shape.
	paymentHeaderName, paymentHeaderValue, err := encodePaymentForVariant(payload, chosen, variant)
	if err != nil {
		record.BlockReason = "payload_encode_error"
		http.Error(w, "aor: failed to encode payment payload", http.StatusInternalServerError)
		return
	}

	retryReq, err := r.buildUpstreamRequest(ctx, req)
	if err != nil {
		record.BlockReason = "retry_request_build_error"
		http.Error(w, "aor: internal error", http.StatusInternalServerError)
		return
	}
	retryReq.Header.Set(paymentHeaderName, paymentHeaderValue)

	retryResp, err := r.httpClient.Do(retryReq)
	if err != nil {
		record.BlockReason = "upstream_unreachable_on_retry"
		http.Error(w, "aor: upstream unreachable on retry", http.StatusBadGateway)
		return
	}
	defer retryResp.Body.Close()

	// ── Step 13: Parse settlement response ───────────────────────────────────
	// V2 returns PAYMENT-RESPONSE; V1 returns X-PAYMENT-RESPONSE. Accept either.
	settlementHeader := retryResp.Header.Get(headerPaymentResponse)
	if settlementHeader == "" {
		settlementHeader = retryResp.Header.Get(headerV1PaymentResponse)
	}
	var settlement *PaymentResponse
	if settlementHeader != "" {
		if pr, err := decodePaymentResponse(settlementHeader); err == nil {
			settlement = pr
			record.TxHash = pr.Transaction
			r.logger.Info("x402 payment settled",
				zap.String("tx_hash", pr.Transaction),
				zap.String("payer", pr.Payer),
				zap.String("network", pr.Network),
				zap.String("protocol", variant.String()),
			)
		}
	}

	// ── Step 14: Check upstream accepted the payment ─────────────────────────
	if retryResp.StatusCode == http.StatusPaymentRequired {
		record.BlockReason = "upstream_rejected_signed_payment"
		record.Status = "failed"
		r.logger.Warn("upstream rejected signed x402 payment",
			zap.String("url", req.URL.String()),
			zap.Int("status", retryResp.StatusCode),
		)
		http.Error(w, "aor: upstream rejected payment — check wallet balance and allowlists", http.StatusPaymentRequired)
		return
	}

	// ── Step 15: Record outcome — payment was submitted on-chain so debit stands ─
	budgetReserved = false
	record.AmountUSD = float64(amountCents) / 100
	record.AmountRaw = amountRaw
	record.Asset = chosen.Asset
	record.Network = chosen.Network

	// "upto" reserved the authorized MAX in Step 8; now that the retried
	// response is in, adjust down to what was actually settled so budget and
	// audit totals reflect real spend, not worst-case exposure. If no
	// settlement amount is parseable, conservatively keep the max reserved —
	// understating consumed budget is worse than overstating it for a spend
	// guardrail.
	if chosen.Scheme == x402SchemeUpto {
		if settlement != nil && settlement.Amount != "" {
			if actualCents, actualRaw, err := r.parsePriceToCents(settlement.Amount, chosen.Asset, chosen.Network); err == nil {
				if diff := amountCents - actualCents; diff > 0 {
					r.budget.Refund(diff)
				}
				record.AmountUSD = float64(actualCents) / 100
				record.AmountRaw = actualRaw
			} else {
				r.logger.Warn("x402 upto: could not parse settled amount, keeping authorized max reserved",
					zap.String("settled_amount", settlement.Amount), zap.Error(err))
			}
		} else {
			r.logger.Warn("x402 upto: upstream reported no settlement amount, keeping authorized max reserved")
		}
	}

	if retryResp.StatusCode >= 200 && retryResp.StatusCode < 300 {
		record.Status = "allowed"
	} else {
		record.Status = "failed"
		record.BlockReason = fmt.Sprintf("upstream_error_%d", retryResp.StatusCode)
	}

	copyResponse(w, retryResp)
}

// ─── Policy checks ─────────────────────────────────────────────────────────────

func (r *X402Rail) checkEndpoint(u *url.URL) error {
	host := strings.ToLower(u.Hostname())

	switch r.policy.EndpointMode {
	case "allowlist":
		for _, allowed := range r.policy.AllowedHosts {
			a := strings.ToLower(allowed)
			if host == a || strings.HasSuffix(host, "."+a) {
				return nil
			}
		}
		return fmt.Errorf("endpoint_not_on_allowlist: %s", host)

	case "blocklist":
		for _, blocked := range r.policy.BlockedHosts {
			b := strings.ToLower(blocked)
			if host == b || strings.HasSuffix(host, "."+b) {
				return fmt.Errorf("endpoint_blocked: %s", host)
			}
		}
		return nil

	default: // "open"
		return nil
	}
}

func (r *X402Rail) selectRequirement(challenge *PaymentRequired) (*PaymentRequirement, error) {
	allowedNets := make(map[string]bool)
	if len(r.policy.AllowedNetworks) == 0 {
		for net := range KnownNetworks {
			allowedNets[net] = true
		}
	} else {
		for _, net := range r.policy.AllowedNetworks {
			allowedNets[net] = true
		}
	}

	// isAcceptable returns true only for requirements this rail can sign for
	// the given scheme: the network must be known and allowed.
	isAcceptable := func(req *PaymentRequirement, scheme string) bool {
		if req.Scheme != scheme {
			return false
		}
		if !allowedNets[req.Network] {
			return false
		}
		_, known := KnownNetworks[req.Network]
		return known
	}

	// schemePriority always tries "exact" first — mature, and no after-the-
	// fact trust exposure — and only considers "upto" when the operator has
	// explicitly opted in via AllowUpto (see X402Policy.AllowUpto).
	schemePriority := []string{x402SchemeExact}
	if r.policy.AllowUpto {
		schemePriority = append(schemePriority, x402SchemeUpto)
	}

	for _, scheme := range schemePriority {
		// Prefer the configured preferred chain.
		for i := range challenge.Accepts {
			req := &challenge.Accepts[i]
			if req.Network == r.policy.PreferredChain && isAcceptable(req, scheme) {
				return req, nil
			}
		}
		// Fall back to any acceptable option for this scheme.
		for i := range challenge.Accepts {
			req := &challenge.Accepts[i]
			if isAcceptable(req, scheme) {
				return req, nil
			}
		}
	}

	return nil, fmt.Errorf("no_acceptable_payment_option: server requires %v (schemes %v), aor supports schemes=%v (allow_upto=%v) networks=%v",
		networksFromRequirements(challenge.Accepts),
		schemesFromRequirements(challenge.Accepts),
		schemePriority,
		r.policy.AllowUpto,
		r.policy.AllowedNetworks,
	)
}

func schemesFromRequirements(reqs []PaymentRequirement) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range reqs {
		if !seen[r.Scheme] {
			seen[r.Scheme] = true
			out = append(out, r.Scheme)
		}
	}
	return out
}

func networksFromRequirements(reqs []PaymentRequirement) []string {
	nets := make([]string, 0, len(reqs))
	for _, r := range reqs {
		nets = append(nets, r.Network)
	}
	return nets
}

// ─── Amount parsing ────────────────────────────────────────────────────────────

// parsePriceToCents converts the atomic-unit amount string from the challenge
// into USD cents. USDC has 6 decimals: 1 USDC = 1_000_000 units = 100 cents.
// It rejects any asset that is not the canonical USDC address for the network,
// because a different token may have different decimals and the conversion
// would be silently wrong.
func (r *X402Rail) parsePriceToCents(atomicAmount, asset, network string) (int64, string, error) {
	netInfo, ok := KnownNetworks[network]
	if !ok {
		return 0, "", fmt.Errorf("unknown network %q", network)
	}
	if netInfo.USDCAddress != "" && !strings.EqualFold(asset, netInfo.USDCAddress) {
		return 0, "", fmt.Errorf("unsupported asset %s on %s: only USDC (%s) is supported",
			asset, network, netInfo.USDCAddress)
	}

	amt, ok := new(big.Int).SetString(atomicAmount, 10)
	if !ok {
		return 0, "", fmt.Errorf("cannot parse amount %q as integer", atomicAmount)
	}

	// amountCents = atomicAmount / 10_000  (6 decimals - 2 for cents = 4)
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(4), nil)
	cents := new(big.Int).Div(amt, divisor)

	if !cents.IsInt64() {
		return 0, "", fmt.Errorf("amount %s exceeds int64 range", atomicAmount)
	}
	return cents.Int64(), atomicAmount, nil
}

// ─── EIP-3009 Signing ─────────────────────────────────────────────────────────

// signPayment dispatches to the signer for req's scheme: signExact (EIP-3009,
// "exact") or signPermit2 (Permit2 witness-transfer, "upto" — see permit2.go).
func (r *X402Rail) signPayment(
	ctx context.Context,
	req *PaymentRequirement,
	resource *ResourceInfo,
	rawURL string,
) (*PaymentPayload, error) {
	if req.Scheme == x402SchemeUpto {
		return r.signPermit2(ctx, req, resource, rawURL)
	}
	return r.signExact(ctx, req, resource, rawURL)
}

func (r *X402Rail) signExact(
	ctx context.Context,
	req *PaymentRequirement,
	resource *ResourceInfo,
	rawURL string,
) (*PaymentPayload, error) {
	network, ok := KnownNetworks[req.Network]
	if !ok {
		return nil, fmt.Errorf("unknown network %s", req.Network)
	}

	// Step 1: Random 32-byte nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	nonceHex := "0x" + common.Bytes2Hex(nonce)

	// Step 2: Time window
	now := time.Now().UTC()
	validAfter := now.Add(-5 * time.Second)
	validBefore := now.Add(r.policy.PayloadTTL)
	if req.MaxTimeoutSeconds > 0 {
		serverTTL := time.Duration(req.MaxTimeoutSeconds) * time.Second
		if serverTTL < r.policy.PayloadTTL {
			validBefore = now.Add(serverTTL)
		}
	}

	// Step 3: EIP-712 domain separator
	tokenName := "USDC"
	tokenVersion := "2"
	if n, ok := req.Extra["name"].(string); ok && n != "" {
		tokenName = n
	}
	if v, ok := req.Extra["version"].(string); ok && v != "" {
		tokenVersion = v
	}

	assetAddr := common.HexToAddress(req.Asset)
	chainID := big.NewInt(network.ChainID)
	domainSep, err := computeEIP712DomainSeparator(tokenName, tokenVersion, chainID, assetAddr)
	if err != nil {
		return nil, fmt.Errorf("domain separator: %w", err)
	}

	// Step 4: Struct hash
	fromAddr := common.HexToAddress(r.policy.WalletAddress)
	toAddr := common.HexToAddress(req.PayTo)
	value := new(big.Int)
	value.SetString(req.Amount, 10)

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

	// Step 5: Final EIP-712 digest
	digest := computeEIP712Digest(domainSep, structHash)

	// Step 6: ECDSA sign
	sig, err := crypto.Sign(digest[:], r.policy.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	// go-ethereum returns [R || S || V] where V is 0 or 1; EVM expects 27 or 28.
	sig[64] += 27
	sigHex := "0x" + common.Bytes2Hex(sig)

	auth := EIP3009AuthFields{
		From:        fromAddr.Hex(),
		To:          toAddr.Hex(),
		Value:       req.Amount,
		ValidAfter:  strconv.FormatInt(validAfter.Unix(), 10),
		ValidBefore: strconv.FormatInt(validBefore.Unix(), 10),
		Nonce:       nonceHex,
	}

	var res *ResourceInfo
	if resource != nil {
		res = resource
	} else if rawURL != "" {
		res = &ResourceInfo{URL: rawURL}
	}

	rawPayload, err := marshalExactPayload(EIP3009Payload{
		Signature:     sigHex,
		Authorization: auth,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal exact payload: %w", err)
	}

	return &PaymentPayload{
		X402Version: x402Version,
		Accepted:    *req,
		Resource:    res,
		Payload:     rawPayload,
	}, nil
}

// computeEIP712DomainSeparator builds the domain separator hash for the token.
func computeEIP712DomainSeparator(
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

// ─── Facilitator pre-verification ─────────────────────────────────────────────

// marshalVerifyRequest builds the /verify request body in the shape the
// facilitator expects for the given protocol variant.
func marshalVerifyRequest(payload *PaymentPayload, req *PaymentRequirement, variant protoVariant) ([]byte, error) {
	if variant == protoV1 {
		resourceURL := ""
		if payload.Resource != nil {
			resourceURL = payload.Resource.URL
		}
		v1Net := v1NetworkName(req.Network)
		return json.Marshal(v1VerifyRequest{
			X402Version: x402VersionV1,
			PaymentPayload: v1PaymentPayload{
				X402Version: x402VersionV1,
				Scheme:      req.Scheme,
				Network:     v1Net,
				Payload:     payload.Payload,
			},
			PaymentRequirements: v1PaymentRequirements{
				Scheme:            req.Scheme,
				Network:           v1Net,
				MaxAmountRequired: req.Amount,
				Resource:          resourceURL,
				Description:       req.Description,
				MimeType:          req.MimeType,
				PayTo:             req.PayTo,
				MaxTimeoutSeconds: req.MaxTimeoutSeconds,
				Asset:             req.Asset,
				Extra:             req.Extra,
			},
		})
	}
	return json.Marshal(FacilitatorVerifyRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *req,
	})
}

func (r *X402Rail) preVerify(
	ctx context.Context,
	payload *PaymentPayload,
	req *PaymentRequirement,
	variant protoVariant,
) error {
	body, err := marshalVerifyRequest(payload, req, variant)
	if err != nil {
		return fmt.Errorf("marshal verify request: %w", err)
	}

	verifyCtx, cancel := context.WithTimeout(ctx, r.policy.FacilitatorTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(
		verifyCtx,
		http.MethodPost,
		r.policy.FacilitatorURL+facilitatorVerifyPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("facilitator unreachable: %w", err)
	}
	defer resp.Body.Close()

	var vr FacilitatorVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		return fmt.Errorf("facilitator response parse: %w", err)
	}
	if !vr.IsValid {
		return fmt.Errorf("facilitator rejected: %s", vr.InvalidReason)
	}
	return nil
}

// ─── HTTP helpers ──────────────────────────────────────────────────────────────

// hopByHopHeaders lists HTTP/1.1 headers that must not be forwarded by a proxy (RFC 2616 §13.5.1).
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func (r *X402Rail) buildUpstreamRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	outReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}

	for k, vs := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-sentinel-") {
			continue
		}
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}

	outReq.Header.Set("User-Agent", "agentOnRails-proxy/0.1 (x402-client)")
	return outReq, nil
}

// looksLikeX402Challenge reports whether a 402 response carries x402 markers.
// V2: PAYMENT-REQUIRED header is present.
// V1: JSON body contains a non-zero x402Version field.
// The response body is buffered so it can be re-read by parsePaymentRequired.
func looksLikeX402Challenge(resp *http.Response) bool {
	if resp.Header.Get(headerPaymentRequired) != "" {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil || len(body) == 0 {
		return false
	}
	var probe struct {
		X402Version int `json:"x402Version"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.X402Version != 0
}

// protoVariant identifies which x402 wire format a challenge arrived in, which
// determines how AgentOnRails must reply.
type protoVariant int

const (
	// protoV2 — challenge in the PAYMENT-REQUIRED header; reply in PAYMENT-SIGNATURE.
	protoV2 protoVariant = iota
	// protoV1 — challenge in the 402 JSON body; reply in the X-PAYMENT header.
	protoV1
)

func (v protoVariant) String() string {
	if v == protoV1 {
		return "v1"
	}
	return "v2"
}

// parsePaymentRequired decodes the 402 challenge and reports which protocol
// variant it used. A PAYMENT-REQUIRED header means V2; a challenge carried in the
// JSON body means V1. The returned requirements are normalized to CAIP-2 networks
// and a populated Amount regardless of variant.
func (r *X402Rail) parsePaymentRequired(resp *http.Response) (*PaymentRequired, protoVariant, error) {
	if hdr := resp.Header.Get(headerPaymentRequired); hdr != "" {
		data, err := base64.StdEncoding.DecodeString(hdr)
		if err != nil {
			data = []byte(hdr)
		}
		var pr PaymentRequired
		if err := json.Unmarshal(data, &pr); err != nil {
			return nil, protoV2, fmt.Errorf("json unmarshal PAYMENT-REQUIRED: %w", err)
		}
		normalizeChallenge(&pr)
		return &pr, protoV2, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, protoV1, fmt.Errorf("read 402 body: %w", err)
	}
	var pr PaymentRequired
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, protoV1, fmt.Errorf("json unmarshal 402 body: %w", err)
	}
	normalizeChallenge(&pr)
	return &pr, protoV1, nil
}

// normalizeChallenge rewrites each requirement into the rail's internal form:
// CAIP-2 network identifiers and a populated Amount (folding in the V1
// maxAmountRequired spelling). This lets the selection, pricing, and signing
// paths stay variant-agnostic.
func normalizeChallenge(pr *PaymentRequired) {
	for i := range pr.Accepts {
		req := &pr.Accepts[i]
		req.Network = normalizeNetwork(req.Network)
		if req.Amount == "" && req.MaxAmountRequired != "" {
			req.Amount = req.MaxAmountRequired
		}
	}
}

func encodePaymentPayload(payload *PaymentPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// encodePaymentForVariant produces the payment header name and base64 value the
// upstream expects for the given protocol variant. V2 → PAYMENT-SIGNATURE with
// the full payload; V1 → X-PAYMENT with the flatter V1 payload (slug network).
func encodePaymentForVariant(payload *PaymentPayload, chosen *PaymentRequirement, variant protoVariant) (name, value string, err error) {
	if variant == protoV1 {
		v1 := v1PaymentPayload{
			X402Version: x402VersionV1,
			Scheme:      chosen.Scheme,
			Network:     v1NetworkName(chosen.Network),
			Payload:     payload.Payload,
		}
		data, mErr := json.Marshal(v1)
		if mErr != nil {
			return "", "", mErr
		}
		return headerV1Payment, base64.StdEncoding.EncodeToString(data), nil
	}

	hdr, eErr := encodePaymentPayload(payload)
	if eErr != nil {
		return "", "", eErr
	}
	return headerPaymentSig, hdr, nil
}

func decodePaymentResponse(hdr string) (*PaymentResponse, error) {
	data, err := base64.StdEncoding.DecodeString(hdr)
	if err != nil {
		data = []byte(hdr)
	}
	var pr PaymentResponse
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

const maxResponseBodyBytes = 32 * 1024 * 1024 // 32 MB — guard against unbounded upstream responses

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxResponseBodyBytes))
}

// ─── Reverse proxy adapter ────────────────────────────────────────────────────

// ReverseProxyHandler wraps any rail.Rail as an http.Handler. It is not
// x402-specific: HTTPS interception (CONNECT handling) decrypts traffic
// before handing each request to whatever rail is configured for the agent,
// so a card/ACH rail or an identity-gated wrapper (e.g. the commercial
// identity_gate rail) serves real traffic through the exact same path x402
// does — the daemon just needs any rail.Rail, not a *X402Rail.
type ReverseProxyHandler struct {
	inner   rail.Rail
	agentID string
	logger  *zap.Logger

	// ca is non-nil when HTTPS interception is enabled. When set, CONNECT
	// tunnels are terminated locally so https:// payments run through the rail.
	// When nil, CONNECT falls back to a transparent (blind) TCP tunnel.
	ca *CA
}

// NewReverseProxyHandler builds the proxy handler for any rail.Rail. Pass a
// non-nil ca to enable HTTPS interception; pass nil to keep HTTPS as an
// opaque passthrough tunnel.
func NewReverseProxyHandler(inner rail.Rail, agentID string, ca *CA, logger *zap.Logger) *ReverseProxyHandler {
	return &ReverseProxyHandler{inner: inner, agentID: agentID, ca: ca, logger: logger}
}

func (h *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// CONNECT requests are used by HTTP clients to establish HTTPS tunnels
	// (e.g. when HTTPS_PROXY is set). With interception enabled we terminate the
	// client's TLS session and inspect the plaintext for x402 challenges; without
	// it we fall back to an opaque byte tunnel (no payment handling on HTTPS).
	if req.Method == http.MethodConnect {
		h.handleConnect(w, req)
		return
	}

	// agentID is always taken from the handler (set at proxy startup), not from
	// the request header — allowing clients to override it would corrupt audit logs.
	taskCtx := req.Header.Get(headerSentinelTask)
	h.inner.ProxyRequest(req.Context(), w, req, h.agentID, taskCtx)
}

// serveInterceptedRequest handles a single plaintext request decrypted from an
// intercepted TLS tunnel. The request line inside a TLS session is origin-form
// (path only), so we rebuild the absolute https:// URL from the Host header
// before handing it to the rail.
func (h *ReverseProxyHandler) serveInterceptedRequest(w http.ResponseWriter, req *http.Request) {
	req.URL.Scheme = "https"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	// RequestURI must be empty when the request is used as an outbound client
	// request; ProxyRequest rebuilds it, but clear it here to be safe.
	req.RequestURI = ""
	taskCtx := req.Header.Get(headerSentinelTask)
	h.inner.ProxyRequest(req.Context(), w, req, h.agentID, taskCtx)
}

// handleConnect services an HTTPS CONNECT request. With interception enabled
// (h.ca != nil) it terminates the client's TLS session locally and routes the
// decrypted requests through the x402 rail; otherwise it falls back to an opaque
// bidirectional TCP tunnel with no payment handling.
func (h *ReverseProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request) {
	if h.ca != nil {
		h.interceptConnect(w, req)
		return
	}
	h.blindTunnel(w, req)
}

// interceptConnect terminates the client TLS session with a forged certificate,
// decrypts the tunnel, and serves each inner request through the rail. The agent
// must trust AgentOnRails' CA for the forged certificate to be accepted.
func (h *ReverseProxyHandler) interceptConnect(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "aor: CONNECT not supported (hijacking unavailable)", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Tell the client the tunnel is up; the TLS handshake happens next.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// The CONNECT authority is host:port; the cert only needs the host.
	host := req.Host
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}

	tlsConn := tls.Server(clientConn, h.ca.tlsConfig(host))
	if err := tlsConn.Handshake(); err != nil {
		h.logger.Debug("intercept TLS handshake failed",
			zap.String("agent", h.agentID),
			zap.String("host", host),
			zap.Error(err),
		)
		return
	}
	defer tlsConn.Close()

	h.logger.Debug("CONNECT intercepted",
		zap.String("agent", h.agentID),
		zap.String("host", req.Host),
	)

	// Serve the decrypted connection with a standard http.Server so we get
	// keep-alive and correct response framing. The server exits when the client
	// closes the connection (listener returns net.ErrClosed).
	ln := newOneShotListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, ir *http.Request) {
			h.serveInterceptedRequest(rw, ir)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		// Reclaim the tunnel goroutine if a kept-alive client goes idle instead
		// of closing the connection.
		IdleTimeout: 120 * time.Second,
	}
	_ = srv.Serve(ln)
}

// blindTunnel pipes raw bytes between the client and the destination without
// inspecting the TLS payload, so x402 payment handling does not apply.
func (h *ReverseProxyHandler) blindTunnel(w http.ResponseWriter, req *http.Request) {
	// Dial the destination before hijacking so we can still send an HTTP error
	// if the connection fails.
	destConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(req.Context(), "tcp", req.Host)
	if err != nil {
		http.Error(w, "aor: CONNECT dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "aor: CONNECT not supported (hijacking unavailable)", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}
	defer clientConn.Close()
	defer destConn.Close()

	h.logger.Debug("CONNECT tunnel opened",
		zap.String("agent", h.agentID),
		zap.String("host", req.Host),
	)

	// Signal the client that the tunnel is established.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Pipe bytes bidirectionally. errCh is buffered so neither goroutine leaks
	// when the deferred Close unblocks the other side.
	errCh := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src) //nolint:errcheck
		errCh <- struct{}{}
	}
	go pipe(destConn, clientConn)
	go pipe(clientConn, destConn)
	// Wait for one direction to close; deferred Close unblocks the other.
	<-errCh
}

var _ http.Handler = (*ReverseProxyHandler)(nil)

// ─── Helpers ───────────────────────────────────────────────────────────────────

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

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
)

// ─── Protocol constants ────────────────────────────────────────────────────────

const (
	// x402 V2 header names (V1 used X-PAYMENT / X-PAYMENT-RESPONSE).
	headerPaymentRequired = "PAYMENT-REQUIRED"
	headerPaymentSig      = "PAYMENT-SIGNATURE"
	headerPaymentResponse = "PAYMENT-RESPONSE"

	// AgentOnRails identification headers set by the agent.
	headerSentinelAgent = "X-Sentinel-Agent"
	headerSentinelTask  = "X-Sentinel-Task"

	// x402 protocol version this rail targets.
	x402Version = 2

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
	"eip155:1":     {ChainID: 1, Name: "Ethereum Mainnet", USDCAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
	"eip155:8453":  {ChainID: 8453, Name: "Base", USDCAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
	"eip155:137":   {ChainID: 137, Name: "Polygon", USDCAddress: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"},
	"eip155:10":    {ChainID: 10, Name: "Optimism", USDCAddress: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"},
	"eip155:42161": {ChainID: 42161, Name: "Arbitrum One", USDCAddress: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"},
	"eip155:43114": {ChainID: 43114, Name: "Avalanche C-Chain", USDCAddress: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E"},

	// EVM testnet
	"eip155:84532": {ChainID: 84532, Name: "Base Sepolia", USDCAddress: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"},
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
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
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
type PaymentPayload struct {
	X402Version int                `json:"x402Version"`
	Accepted    PaymentRequirement `json:"accepted"`
	Resource    *ResourceInfo      `json:"resource,omitempty"`
	Payload     EIP3009Payload     `json:"payload"`
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
}

// ─── Policy types ──────────────────────────────────────────────────────────────

// X402Policy defines the spend controls AgentOnRails enforces on behalf of an agent.
type X402Policy struct {
	// Wallet
	WalletAddress string
	PrivateKey    *ecdsa.PrivateKey
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

	// SkipPreVerify disables the pre-verification call to the facilitator.
	// When false (default), Sentinel calls /verify before retrying the request.
	SkipPreVerify bool

	// Velocity limits (0 = use rail defaults: 30/min, 200/hr, 60s cooldown)
	VelocityMaxPerMinute    int
	VelocityMaxPerHour      int
	VelocityCooldownSeconds int
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

// ─── Budget tracker ────────────────────────────────────────────────────────────

// BudgetTracker maintains rolling spend windows. All methods are safe for concurrent use.
// It does NOT persist to disk — it is rehydrated from the SQLite audit log at startup.
type BudgetTracker struct {
	mu      sync.Mutex
	windows []budgetWindow

	// OnThreshold is called after a successful Reserve when any window crosses
	// the alert threshold. agentID, period, and pctUsed are provided for alerting.
	OnThreshold func(period string, pctUsed float64)
}

type budgetWindow struct {
	period     string // "daily" | "weekly" | "monthly"
	limitCents int64
	spentCents int64
	resetAt    time.Time
}

// NewBudgetTracker creates a tracker initialised with the policy limits.
func NewBudgetTracker(policy *X402Policy) *BudgetTracker {
	now := time.Now().UTC()
	return &BudgetTracker{
		windows: []budgetWindow{
			{
				period:     "daily",
				limitCents: policy.DailyLimitCents,
				spentCents: 0,
				resetAt:    now.Truncate(24 * time.Hour).Add(24 * time.Hour),
			},
			{
				period:     "weekly",
				limitCents: policy.WeeklyLimitCents,
				spentCents: 0,
				resetAt:    nextWeekStart(now),
			},
			{
				period:     "monthly",
				limitCents: policy.MonthlyLimitCents,
				spentCents: 0,
				resetAt:    nextMonthStart(now),
			},
		},
	}
}

// Reserve atomically checks whether amountCents fits in all active windows and,
// if so, debits it. Returns an error naming the first exceeded period.
// If the check fails no debit is applied (all-or-nothing).
func (b *BudgetTracker) Reserve(amountCents int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	for i := range b.windows {
		w := &b.windows[i]
		if now.After(w.resetAt) {
			w.spentCents = 0
			switch w.period {
			case "daily":
				w.resetAt = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
			case "weekly":
				w.resetAt = nextWeekStart(now)
			case "monthly":
				w.resetAt = nextMonthStart(now)
			}
		}
		if w.limitCents > 0 && w.spentCents+amountCents > w.limitCents {
			return fmt.Errorf("%s budget exceeded: spent %d + %d > limit %d (cents)",
				w.period, w.spentCents, amountCents, w.limitCents)
		}
	}

	for i := range b.windows {
		b.windows[i].spentCents += amountCents
	}

	// Fire threshold callbacks after the debit.
	if b.OnThreshold != nil {
		for _, w := range b.windows {
			if w.limitCents > 0 {
				pct := float64(w.spentCents) / float64(w.limitCents) * 100
				b.OnThreshold(w.period, pct)
			}
		}
	}

	return nil
}

// Refund subtracts amountCents from all windows without performing a limit check.
// Used to undo a Reserve when a payment fails after signing.
func (b *BudgetTracker) Refund(amountCents int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.windows {
		b.windows[i].spentCents -= amountCents
		if b.windows[i].spentCents < 0 {
			b.windows[i].spentCents = 0
		}
	}
}

// SpentThisPeriod returns the current spend for the named period.
func (b *BudgetTracker) SpentThisPeriod(period string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, w := range b.windows {
		if w.period == period {
			return w.spentCents
		}
	}
	return 0
}

// Seed sets the initial spent value for a period (used during startup rehydration).
func (b *BudgetTracker) Seed(period string, spentCents int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.windows {
		if b.windows[i].period == period {
			b.windows[i].spentCents = spentCents
			return
		}
	}
}

// BudgetSnapshot is a point-in-time copy of one budget window, used for
// persistence across daemon restarts.
type BudgetSnapshot struct {
	Period     string
	SpentCents int64
	ResetAt    time.Time
}

// Snapshot returns the current state of all budget windows. Safe for concurrent use.
func (b *BudgetTracker) Snapshot() []BudgetSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BudgetSnapshot, len(b.windows))
	for i, w := range b.windows {
		out[i] = BudgetSnapshot{Period: w.period, SpentCents: w.spentCents, ResetAt: w.resetAt}
	}
	return out
}

func nextWeekStart(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	daysUntilMonday := 8 - weekday
	return t.Truncate(24 * time.Hour).Add(time.Duration(daysUntilMonday) * 24 * time.Hour)
}

func nextMonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
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

// X402Rail is the payment rail adapter for x402 crypto payments.
type X402Rail struct {
	policy     *X402Policy
	budget     *BudgetTracker
	velocity   *VelocityLimiter
	logger     *zap.Logger
	httpClient *http.Client
	auditLog   AuditLogger
}

// AuditLogger is the interface the rail uses to write transaction records.
// Implemented by the SQLite audit backend in the audit package.
type AuditLogger interface {
	LogTransaction(tx TransactionRecord) error
}

// TransactionRecord is written to the audit DB for every request.
type TransactionRecord struct {
	ID          string
	AgentID     string
	Timestamp   time.Time
	RailType    string
	Endpoint    string
	Method      string
	AmountUSD   float64
	AmountRaw   string
	Asset       string
	Network     string
	TxHash      string
	Status      string // "allowed" | "blocked" | "failed"
	BlockReason string
	TaskContext string
	LatencyMS   int64
}

// NewX402Rail creates a rail from a policy. The policy must already have a
// populated PrivateKey (decrypted from wallet.enc by the daemon's vault).
func NewX402Rail(policy *X402Policy, audit AuditLogger, logger *zap.Logger) (*X402Rail, error) {
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

	return &X402Rail{
		policy:   policy,
		budget:   NewBudgetTracker(policy),
		velocity: NewVelocityLimiter(
			velocityOrDefault(policy.VelocityMaxPerMinute, 30),
			velocityOrDefault(policy.VelocityMaxPerHour, 200),
			velocityOrDefault(policy.VelocityCooldownSeconds, 60),
		),
		logger:   logger,
		httpClient: &http.Client{
			Timeout: policy.UpstreamTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		auditLog: audit,
	}, nil
}

// Budget returns the rail's BudgetTracker (used by the daemon for rehydration).
func (r *X402Rail) Budget() *BudgetTracker { return r.budget }

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
	record := TransactionRecord{
		ID:          newUUID(),
		AgentID:     agentID,
		Timestamp:   start,
		RailType:    "x402",
		Endpoint:    req.URL.String(),
		Method:      req.Method,
		TaskContext: taskContext,
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

	// ── Step 5: Parse the payment challenge ──────────────────────────────────
	challenge, err := r.parsePaymentRequired(resp)
	if err != nil {
		record.BlockReason = "invalid_payment_required_header"
		r.logger.Warn("malformed PAYMENT-REQUIRED header",
			zap.String("url", req.URL.String()),
			zap.Error(err),
		)
		http.Error(w, "aor: upstream sent malformed x402 challenge", http.StatusBadGateway)
		return
	}

	// ── Step 6: Select best matching requirement ─────────────────────────────
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

	// ── Step 7: Budget checks ────────────────────────────────────────────────
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

	// ── Step 8: Human approval gate ──────────────────────────────────────────
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

	// ── Step 9: Sign EIP-3009 authorization ──────────────────────────────────
	payload, err := r.signPayment(ctx, chosen, challenge.Resource, req.URL.String())
	if err != nil {
		record.BlockReason = "signing_error: " + err.Error()
		r.logger.Error("payment signing failed", zap.Error(err))
		http.Error(w, "aor: payment signing failed", http.StatusInternalServerError)
		return
	}

	// ── Step 10: Optional facilitator pre-verification ────────────────────────
	if !r.policy.skipPreVerify() {
		if err := r.preVerify(ctx, payload, chosen); err != nil {
			record.BlockReason = "facilitator_pre_verify_failed: " + err.Error()
			r.logger.Warn("facilitator pre-verify rejected payload", zap.Error(err))
			http.Error(w, "aor: payment pre-verification failed", http.StatusPaymentRequired)
			return
		}
	}

	// ── Step 11: Retry with payment signature ────────────────────────────────
	payloadHeader, err := encodePaymentPayload(payload)
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
	retryReq.Header.Set(headerPaymentSig, payloadHeader)

	retryResp, err := r.httpClient.Do(retryReq)
	if err != nil {
		record.BlockReason = "upstream_unreachable_on_retry"
		http.Error(w, "aor: upstream unreachable on retry", http.StatusBadGateway)
		return
	}
	defer retryResp.Body.Close()

	// ── Step 12: Parse settlement response ───────────────────────────────────
	if paymentRespHeader := retryResp.Header.Get(headerPaymentResponse); paymentRespHeader != "" {
		if pr, err := decodePaymentResponse(paymentRespHeader); err == nil {
			record.TxHash = pr.Transaction
			r.logger.Info("x402 payment settled",
				zap.String("tx_hash", pr.Transaction),
				zap.String("payer", pr.Payer),
				zap.String("network", pr.Network),
			)
		}
	}

	// ── Step 13: Check upstream accepted the payment ──────────────────────────
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

	// ── Step 14: Record outcome — payment was submitted on-chain so debit stands ─
	budgetReserved = false
	record.AmountUSD = float64(amountCents) / 100
	record.AmountRaw = amountRaw
	record.Asset = chosen.Asset
	record.Network = chosen.Network
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

	// isAcceptable returns true only for requirements this rail can sign:
	// scheme must be "exact" and the network must be known and allowed.
	isAcceptable := func(req *PaymentRequirement) bool {
		if req.Scheme != x402SchemeExact {
			return false
		}
		if !allowedNets[req.Network] {
			return false
		}
		_, known := KnownNetworks[req.Network]
		return known
	}

	// Prefer the configured preferred chain.
	for i := range challenge.Accepts {
		req := &challenge.Accepts[i]
		if req.Network == r.policy.PreferredChain && isAcceptable(req) {
			return req, nil
		}
	}

	// Fall back to any acceptable option.
	for i := range challenge.Accepts {
		req := &challenge.Accepts[i]
		if isAcceptable(req) {
			return req, nil
		}
	}

	return nil, fmt.Errorf("no_acceptable_payment_option: server requires %v (schemes %v), aor supports scheme=%q networks=%v",
		networksFromRequirements(challenge.Accepts),
		schemesFromRequirements(challenge.Accepts),
		x402SchemeExact,
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

func (r *X402Rail) signPayment(
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

	return &PaymentPayload{
		X402Version: x402Version,
		Accepted:    *req,
		Resource:    res,
		Payload: EIP3009Payload{
			Signature:     sigHex,
			Authorization: auth,
		},
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

func (r *X402Rail) preVerify(
	ctx context.Context,
	payload *PaymentPayload,
	req *PaymentRequirement,
) error {
	body, err := json.Marshal(FacilitatorVerifyRequest{
		PaymentPayload:      *payload,
		PaymentRequirements: *req,
	})
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

func (r *X402Rail) parsePaymentRequired(resp *http.Response) (*PaymentRequired, error) {
	if hdr := resp.Header.Get(headerPaymentRequired); hdr != "" {
		data, err := base64.StdEncoding.DecodeString(hdr)
		if err != nil {
			data = []byte(hdr)
		}
		var pr PaymentRequired
		if err := json.Unmarshal(data, &pr); err != nil {
			return nil, fmt.Errorf("json unmarshal PAYMENT-REQUIRED: %w", err)
		}
		return &pr, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read 402 body: %w", err)
	}
	var pr PaymentRequired
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("json unmarshal 402 body: %w", err)
	}
	return &pr, nil
}

func encodePaymentPayload(payload *PaymentPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
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

// ReverseProxyHandler wraps the X402Rail as an http.Handler.
type ReverseProxyHandler struct {
	rail    *X402Rail
	agentID string
}

func NewReverseProxyHandler(rail *X402Rail, agentID string) *ReverseProxyHandler {
	return &ReverseProxyHandler{rail: rail, agentID: agentID}
}

func (h *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// CONNECT requests are used by HTTP clients to establish HTTPS tunnels
	// (e.g. when HTTPS_PROXY is set). We pass them through as a transparent
	// TCP tunnel. x402 payment interception is not possible inside a TLS
	// session, so HTTPS upstream payments are not handled.
	if req.Method == http.MethodConnect {
		h.handleConnect(w, req)
		return
	}

	// agentID is always taken from the handler (set at proxy startup), not from
	// the request header — allowing clients to override it would corrupt audit logs.
	taskCtx := req.Header.Get(headerSentinelTask)
	h.rail.ProxyRequest(req.Context(), w, req, h.agentID, taskCtx)
}

// handleConnect establishes a transparent TCP tunnel for HTTPS CONNECT requests.
// The proxy pipes raw bytes between the client and the destination without
// inspecting the TLS payload, so x402 payment handling does not apply to
// traffic routed through this tunnel.
func (h *ReverseProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request) {
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

	h.rail.logger.Debug("CONNECT tunnel opened",
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

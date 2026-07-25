package x402

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/approval"
	"github.com/agentOnRails/agent-on-rails/rail"
)

// X402RailConfig is the YAML shape for the x402 rail under an agent's rails.x402 block.
type X402RailConfig struct {
	Enabled        bool   `yaml:"enabled"`
	WalletAddress  string `yaml:"wallet_address"`
	PreferredChain string `yaml:"preferred_chain"` // CAIP-2 e.g. "eip155:8453"

	PerCallMaxUSD   string `yaml:"per_call_max_usd"` // decimal string e.g. "0.10"
	DailyLimitUSD   string `yaml:"daily_limit_usd"`
	WeeklyLimitUSD  string `yaml:"weekly_limit_usd"`
	MonthlyLimitUSD string `yaml:"monthly_limit_usd"`

	EndpointMode    string   `yaml:"endpoint_mode"` // open | allowlist | blocklist
	AllowedHosts    []string `yaml:"allowed_hosts"`
	BlockedHosts    []string `yaml:"blocked_hosts"`
	AllowedNetworks []string `yaml:"allowed_networks"`

	RequireApprovalAboveUSD string `yaml:"require_approval_above_usd"`
	// ApprovalTimeoutSec overrides how long a held payment waits for a
	// human decision (via the daemon's control API) before being treated
	// as denied. 0 = approval.DefaultTimeout (5 minutes).
	ApprovalTimeoutSec int `yaml:"approval_timeout_sec"`

	SkipPreVerify bool `yaml:"skip_pre_verify"`

	// AllowUpto opts this agent into the x402 "upto" scheme. See
	// X402Policy.AllowUpto's doc comment in rail.go for why this defaults
	// false rather than being auto-selected whenever a server offers it.
	AllowUpto bool `yaml:"allow_upto"`

	Velocity VelocityConfig `yaml:"velocity"`

	// Timeouts (optional overrides)
	UpstreamTimeoutSec    int `yaml:"upstream_timeout_sec"`
	FacilitatorTimeoutSec int `yaml:"facilitator_timeout_sec"`
	PayloadTTLSec         int `yaml:"payload_ttl_sec"`
}

// VelocityConfig limits request rate for an agent.
type VelocityConfig struct {
	MaxPerMinute    int `yaml:"max_per_minute"`
	MaxPerHour      int `yaml:"max_per_hour"`
	CooldownSeconds int `yaml:"cooldown_seconds"`
}

const DefaultEndpointMode = "open"

// ParseRailConfig decodes an agent's raw rails.x402 YAML node into a
// X402RailConfig, applying defaults and validating enum/required fields.
func ParseRailConfig(raw yaml.Node) (*X402RailConfig, error) {
	var rc X402RailConfig
	if err := raw.Decode(&rc); err != nil {
		return nil, fmt.Errorf("parse rails.x402: %w", err)
	}

	if rc.EndpointMode == "" {
		rc.EndpointMode = DefaultEndpointMode
	}
	if rc.EndpointMode != "open" && rc.EndpointMode != "allowlist" && rc.EndpointMode != "blocklist" {
		return nil, fmt.Errorf("rails.x402.endpoint_mode must be open|allowlist|blocklist, got %q", rc.EndpointMode)
	}
	if rc.Enabled && rc.WalletAddress == "" {
		return nil, fmt.Errorf("rails.x402.wallet_address is required")
	}

	return &rc, nil
}

// BuildPolicy converts a parsed X402RailConfig into an X402Policy. The
// private key is NOT populated here — callers load it from the vault.
func BuildPolicy(facilitatorURL string, rc *X402RailConfig) (*X402Policy, error) {
	policy := &X402Policy{
		WalletAddress:   rc.WalletAddress,
		PreferredChain:  rc.PreferredChain,
		FacilitatorURL:  facilitatorURL,
		EndpointMode:    rc.EndpointMode,
		AllowedHosts:    rc.AllowedHosts,
		BlockedHosts:    rc.BlockedHosts,
		AllowedNetworks: rc.AllowedNetworks,
		SkipPreVerify:   rc.SkipPreVerify,
		AllowUpto:       rc.AllowUpto,
	}

	if policy.FacilitatorURL == "" {
		policy.FacilitatorURL = FacilitatorX402Org
	}

	var err error
	if policy.PerCallMaxCents, err = parseDollarsToCents(rc.PerCallMaxUSD); err != nil {
		return nil, fmt.Errorf("per_call_max_usd: %w", err)
	}
	if policy.DailyLimitCents, err = parseDollarsToCents(rc.DailyLimitUSD); err != nil {
		return nil, fmt.Errorf("daily_limit_usd: %w", err)
	}
	if policy.WeeklyLimitCents, err = parseDollarsToCents(rc.WeeklyLimitUSD); err != nil {
		return nil, fmt.Errorf("weekly_limit_usd: %w", err)
	}
	if policy.MonthlyLimitCents, err = parseDollarsToCents(rc.MonthlyLimitUSD); err != nil {
		return nil, fmt.Errorf("monthly_limit_usd: %w", err)
	}
	if policy.RequireApprovalAboveCents, err = parseDollarsToCents(rc.RequireApprovalAboveUSD); err != nil {
		return nil, fmt.Errorf("require_approval_above_usd: %w", err)
	}

	policy.UpstreamTimeout = durSec(rc.UpstreamTimeoutSec, defaultUpstreamTimeout)
	policy.FacilitatorTimeout = durSec(rc.FacilitatorTimeoutSec, defaultFacilitatorTimeout)
	policy.PayloadTTL = durSec(rc.PayloadTTLSec, defaultPayloadTTL)
	if rc.ApprovalTimeoutSec > 0 {
		policy.ApprovalTimeout = time.Duration(rc.ApprovalTimeoutSec) * time.Second
	}

	policy.VelocityMaxPerMinute = rc.Velocity.MaxPerMinute
	policy.VelocityMaxPerHour = rc.Velocity.MaxPerHour
	policy.VelocityCooldownSeconds = rc.Velocity.CooldownSeconds

	return policy, nil
}

// parseDollarsToCents converts a decimal USD string like "0.10" to int64 cents.
// Returns 0 (no limit) if the string is empty.
func parseDollarsToCents(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid USD amount %q: %w", s, err)
	}
	if f < 0 {
		return 0, fmt.Errorf("USD amount %q must be non-negative", s)
	}
	return int64(math.Round(f * 100)), nil
}

func durSec(secs int, fallback time.Duration) time.Duration {
	if secs <= 0 {
		return fallback
	}
	return time.Duration(secs) * time.Second
}

// Factory implements rail.Factory: it builds an X402Rail for one agent from
// its raw rails.x402 config plus shared daemon dependencies. Returns
// enabled=false (nil rail, nil error) when the config marks the rail disabled.
func Factory(p rail.FactoryParams) (rail.Rail, bool, error) {
	rc, err := ParseRailConfig(p.RawConfig)
	if err != nil {
		return nil, false, err
	}
	if !rc.Enabled {
		return nil, false, nil
	}

	facilitatorURL := ""
	if p.Global != nil {
		facilitatorURL = p.Global.Facilitators.X402
	}
	policy, err := BuildPolicy(facilitatorURL, rc)
	if err != nil {
		return nil, false, err
	}

	keyBytes, err := p.Vault.LoadKey(p.AgentID, p.Passphrase)
	if err != nil {
		return nil, false, fmt.Errorf("load wallet for %s: %w (run `aor credentials set-wallet`)", p.AgentID, err)
	}
	key, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, false, fmt.Errorf("parse wallet key for %s: %w", p.AgentID, err)
	}

	derivedAddr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	if !strings.EqualFold(derivedAddr, policy.WalletAddress) {
		return nil, false, fmt.Errorf(
			"wallet key mismatch for agent %s: key derives to %s but config wallet_address is %s — update config or re-run `aor credentials set-wallet`",
			p.AgentID, derivedAddr, policy.WalletAddress,
		)
	}
	policy.PrivateKey = key

	// Wire the human-approval gate to the daemon's shared pending-approval
	// registry, if one was provided — without this, RequireApprovalAboveCents
	// has nowhere to route a held payment to and always fails closed (see
	// docs/ROADMAP.md Phase 7). p.Approvals is nil in contexts that don't
	// wire one up (some tests), in which case behavior is unchanged from
	// before this field existed: no approver configured.
	if p.Approvals != nil {
		agentID := p.AgentID
		timeout := policy.ApprovalTimeout
		policy.ApprovalFunc = func(ctx context.Context, req ApprovalRequest) (bool, error) {
			return p.Approvals.Await(ctx, approval.Request{
				AgentID:     agentID,
				RailType:    "x402",
				Endpoint:    req.Endpoint,
				AmountCents: req.AmountCents,
				TaskContext: req.TaskContext,
			}, timeout)
		}
	}

	r, err := NewX402Rail(policy, p.Audit, p.Logger)
	if err != nil {
		return nil, false, err
	}
	return r, true, nil
}

func init() {
	rail.Register("x402", Factory)
}

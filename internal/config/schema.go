// Package config loads and validates AgentOnRails YAML configuration files.
package config

import "time"

// GlobalConfig represents aor.yaml — the daemon-level configuration.
type GlobalConfig struct {
	Daemon      DaemonConfig      `yaml:"daemon"`
	Alerts      AlertsConfig      `yaml:"alerts"`
	Facilitators FacilitatorsConfig `yaml:"facilitators"`
}

// DaemonConfig controls the proxy daemon process.
type DaemonConfig struct {
	ListenAddr string `yaml:"listen_addr"` // host to bind per-agent servers on (default: 127.0.0.1)
	LogLevel   string `yaml:"log_level"`   // debug | info | warn | error
	AuditDB    string `yaml:"audit_db"`    // path to SQLite file (default: ~/.aor/audit.db)
	VaultDir   string `yaml:"vault_dir"`   // directory for encrypted wallet files (default: ~/.aor/vaults)
	PIDFile    string `yaml:"pid_file"`    // PID file path (default: ~/.aor/daemon.pid)
}

// AlertsConfig controls Slack notifications.
type AlertsConfig struct {
	SlackWebhookURL    string  `yaml:"slack_webhook_url"`
	BudgetThresholdPct float64 `yaml:"budget_threshold_pct"` // 0–100, default 80
}

// FacilitatorsConfig holds x402 facilitator endpoint URLs.
type FacilitatorsConfig struct {
	X402 string `yaml:"x402"` // default: https://api.cdp.coinbase.com/platform/v2/x402
}

// AgentConfig represents agents/<name>.yaml — per-agent policy.
type AgentConfig struct {
	AgentID   string      `yaml:"agent_id"`
	ProxyPort int         `yaml:"proxy_port"`
	Rails     RailsConfig `yaml:"rails"`
}

// RailsConfig holds per-rail configuration blocks.
type RailsConfig struct {
	X402 *X402RailConfig `yaml:"x402,omitempty"`
	// Card and Bank rails reserved for Phase 2.
}

// X402RailConfig is the YAML shape for the x402 rail under rails.x402.
type X402RailConfig struct {
	Enabled       bool   `yaml:"enabled"`
	WalletAddress string `yaml:"wallet_address"`
	PreferredChain string `yaml:"preferred_chain"` // CAIP-2 e.g. "eip155:8453"

	PerCallMaxUSD  string `yaml:"per_call_max_usd"`  // decimal string e.g. "0.10"
	DailyLimitUSD  string `yaml:"daily_limit_usd"`
	WeeklyLimitUSD string `yaml:"weekly_limit_usd"`
	MonthlyLimitUSD string `yaml:"monthly_limit_usd"`

	EndpointMode    string   `yaml:"endpoint_mode"` // open | allowlist | blocklist
	AllowedHosts    []string `yaml:"allowed_hosts"`
	BlockedHosts    []string `yaml:"blocked_hosts"`
	AllowedNetworks []string `yaml:"allowed_networks"`

	RequireApprovalAboveUSD string `yaml:"require_approval_above_usd"`

	SkipPreVerify bool `yaml:"skip_pre_verify"`

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

// defaults applied when fields are zero/empty.
const (
	DefaultListenAddr         = "127.0.0.1"
	DefaultLogLevel           = "info"
	DefaultBudgetThresholdPct = 80.0
	DefaultFacilitatorX402    = "https://x402.org/facilitator"
	DefaultEndpointMode       = "open"
	DefaultMaxPerMinute       = 30
	DefaultMaxPerHour         = 200
	DefaultCooldownSeconds    = 60
	DefaultUpstreamTimeout    = 10 * time.Second
	DefaultFacilitatorTimeout = 5 * time.Second
	DefaultPayloadTTL         = 60 * time.Second
)

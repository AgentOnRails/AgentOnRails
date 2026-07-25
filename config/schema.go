// Package config loads and validates AgentOnRails YAML configuration files.
package config

import (
	"time"

	"gopkg.in/yaml.v3"
)

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

	// HTTPSIntercept enables TLS interception of CONNECT tunnels so payments to
	// https:// endpoints run through the x402 rail. Requires the agent to trust
	// the AgentOnRails CA (written to CADir). Default false: HTTPS is tunneled
	// opaquely with no payment handling.
	HTTPSIntercept bool   `yaml:"https_intercept"`
	CADir          string `yaml:"ca_dir"` // directory for the interception CA (default: ~/.aor/ca)

	// ControlDisabled turns off the daemon's control API entirely — no
	// listener is started, so approval requests are never wired to
	// anything (RequireApprovalAboveCents falls back to failing closed,
	// the pre-Phase-7 behavior) and pause/resume/policy-reload aren't
	// available. Default false: the control API is on, since it's what
	// makes the free x402 rail's own approval gate actually work.
	ControlDisabled  bool   `yaml:"control_disabled"`
	ControlAddr      string `yaml:"control_addr"`       // default: 127.0.0.1:8420
	ControlTokenFile string `yaml:"control_token_file"` // default: ~/.aor/control-token
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

// RailsConfig holds per-rail configuration blocks, keyed by registered rail
// name (e.g. "x402"). Each rail decodes its own block from the raw YAML node
// via rail.Register — this repo does not need to know a rail's config shape
// ahead of time, so externally-registered (commercial) rails can plug in
// without changing this struct.
type RailsConfig map[string]yaml.Node

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
	DefaultControlAddr        = "127.0.0.1:8420"
	DefaultUpstreamTimeout    = 10 * time.Second
	DefaultFacilitatorTimeout = 5 * time.Second
	DefaultPayloadTTL         = 60 * time.Second
)

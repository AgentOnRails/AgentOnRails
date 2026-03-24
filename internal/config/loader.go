package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// LoadGlobal reads and validates the global aor.yaml config.
func LoadGlobal(path string) (*GlobalConfig, error) {
	path = expandHome(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg GlobalConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyGlobalDefaults(&cfg)
	return &cfg, nil
}

// LoadAgents reads all agent YAML files from the agents directory and returns a
// slice of validated AgentConfig structs.
func LoadAgents(agentsDir string) ([]*AgentConfig, error) {
	agentsDir = expandHome(agentsDir)
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		return nil, fmt.Errorf("read agents dir %s: %w", agentsDir, err)
	}

	var agents []*AgentConfig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(agentsDir, e.Name())
		a, err := LoadAgent(path)
		if err != nil {
			return nil, fmt.Errorf("load agent %s: %w", e.Name(), err)
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// LoadAgent reads a single agent YAML file.
func LoadAgent(path string) (*AgentConfig, error) {
	path = expandHome(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if err := validateAgent(&cfg); err != nil {
		return nil, fmt.Errorf("invalid agent config %s: %w", path, err)
	}
	return &cfg, nil
}

// BuildX402Policy converts an AgentConfig into an x402.X402Policy. The private
// key is NOT populated here — the daemon's vault loads it separately.
func BuildX402Policy(global *GlobalConfig, agent *AgentConfig) (*x402.X402Policy, error) {
	rc := agent.Rails.X402
	if rc == nil {
		return nil, fmt.Errorf("agent %s: no x402 rail config", agent.AgentID)
	}

	policy := &x402.X402Policy{
		WalletAddress:   rc.WalletAddress,
		PreferredChain:  rc.PreferredChain,
		FacilitatorURL:  global.Facilitators.X402,
		EndpointMode:    rc.EndpointMode,
		AllowedHosts:    rc.AllowedHosts,
		BlockedHosts:    rc.BlockedHosts,
		AllowedNetworks: rc.AllowedNetworks,
		SkipPreVerify:   rc.SkipPreVerify,
	}

	if policy.EndpointMode == "" {
		policy.EndpointMode = DefaultEndpointMode
	}
	if policy.FacilitatorURL == "" {
		policy.FacilitatorURL = DefaultFacilitatorX402
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

	policy.UpstreamTimeout = durSec(rc.UpstreamTimeoutSec, DefaultUpstreamTimeout)
	policy.FacilitatorTimeout = durSec(rc.FacilitatorTimeoutSec, DefaultFacilitatorTimeout)
	policy.PayloadTTL = durSec(rc.PayloadTTLSec, DefaultPayloadTTL)

	policy.VelocityMaxPerMinute = rc.Velocity.MaxPerMinute
	policy.VelocityMaxPerHour = rc.Velocity.MaxPerHour
	policy.VelocityCooldownSeconds = rc.Velocity.CooldownSeconds

	return policy, nil
}

// ─── Validation ────────────────────────────────────────────────────────────────

func validateAgent(a *AgentConfig) error {
	if a.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if a.ProxyPort <= 0 || a.ProxyPort > 65535 {
		return fmt.Errorf("proxy_port %d is invalid", a.ProxyPort)
	}
	if a.Rails.X402 != nil && a.Rails.X402.Enabled {
		rc := a.Rails.X402
		if rc.WalletAddress == "" {
			return fmt.Errorf("rails.x402.wallet_address is required")
		}
		mode := rc.EndpointMode
		if mode != "" && mode != "open" && mode != "allowlist" && mode != "blocklist" {
			return fmt.Errorf("rails.x402.endpoint_mode must be open|allowlist|blocklist, got %q", mode)
		}
	}
	return nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

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

func applyGlobalDefaults(cfg *GlobalConfig) {
	if cfg.Daemon.ListenAddr == "" {
		cfg.Daemon.ListenAddr = DefaultListenAddr
	}
	if cfg.Daemon.LogLevel == "" {
		cfg.Daemon.LogLevel = DefaultLogLevel
	}
	if cfg.Daemon.AuditDB == "" {
		cfg.Daemon.AuditDB = "~/.aor/audit.db"
	}
	if cfg.Daemon.VaultDir == "" {
		cfg.Daemon.VaultDir = "~/.aor/vaults"
	}
	if cfg.Daemon.PIDFile == "" {
		cfg.Daemon.PIDFile = "~/.aor/daemon.pid"
	}
	if cfg.Alerts.BudgetThresholdPct == 0 {
		cfg.Alerts.BudgetThresholdPct = DefaultBudgetThresholdPct
	}
	if cfg.Facilitators.X402 == "" {
		cfg.Facilitators.X402 = DefaultFacilitatorX402
	}
}

// ExpandHomePath expands a leading ~/ to the user's home directory.
func ExpandHomePath(path string) string { return expandHome(path) }

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

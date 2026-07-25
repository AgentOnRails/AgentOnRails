package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
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

// ─── Validation ────────────────────────────────────────────────────────────────

// validateAgent checks fields generic to every agent. Rail-specific
// validation (e.g. rails.x402.wallet_address) is owned by each rail's own
// config parser, invoked when the daemon builds that rail.
func validateAgent(a *AgentConfig) error {
	if a.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if a.ProxyPort <= 0 || a.ProxyPort > 65535 {
		return fmt.Errorf("proxy_port %d is invalid", a.ProxyPort)
	}
	return nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

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
	if cfg.Daemon.CADir == "" {
		cfg.Daemon.CADir = "~/.aor/ca"
	}
	if cfg.Daemon.ControlAddr == "" {
		cfg.Daemon.ControlAddr = DefaultControlAddr
	}
	if cfg.Daemon.ControlTokenFile == "" {
		cfg.Daemon.ControlTokenFile = "~/.aor/control-token"
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

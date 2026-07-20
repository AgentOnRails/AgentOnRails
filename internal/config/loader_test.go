package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateAgent(t *testing.T) {
	valid := &AgentConfig{
		AgentID:   "test-agent",
		ProxyPort: 8402,
	}
	if err := validateAgent(valid); err != nil {
		t.Errorf("unexpected error for valid config: %v", err)
	}

	noID := *valid
	noID.AgentID = ""
	if err := validateAgent(&noID); err == nil {
		t.Error("expected error for missing agent_id")
	}

	badPort := *valid
	badPort.ProxyPort = 0
	if err := validateAgent(&badPort); err == nil {
		t.Error("expected error for port 0")
	}
}

func TestLoadAgent(t *testing.T) {
	dir := t.TempDir()
	content := `
agent_id: "test-agent"
proxy_port: 8402
rails:
  x402:
    enabled: true
    wallet_address: "0x1234567890abcdef1234567890abcdef12345678"
    preferred_chain: "eip155:84532"
    per_call_max_usd: "0.10"
    daily_limit_usd: "5.00"
    endpoint_mode: "open"
    velocity:
      max_per_minute: 30
      max_per_hour: 200
      cooldown_seconds: 60
`
	path := filepath.Join(dir, "test-agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAgent(path)
	if err != nil {
		t.Fatalf("LoadAgent: %v", err)
	}
	if cfg.AgentID != "test-agent" {
		t.Errorf("AgentID = %q, want %q", cfg.AgentID, "test-agent")
	}

	node, ok := cfg.Rails["x402"]
	if !ok {
		t.Fatal("rails.x402 is missing")
	}
	// Rail-specific decoding (defaults, validation) is tested in the x402
	// package itself; here we only confirm the raw node round-trips.
	var probe struct {
		DailyLimitUSD string `yaml:"daily_limit_usd"`
	}
	if err := node.Decode(&probe); err != nil {
		t.Fatalf("decode rails.x402: %v", err)
	}
	if probe.DailyLimitUSD != "5.00" {
		t.Errorf("DailyLimitUSD = %q, want %q", probe.DailyLimitUSD, "5.00")
	}
}

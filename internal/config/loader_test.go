package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDollarsToCents(t *testing.T) {
	tests := []struct {
		input    string
		want     int64
		wantErr  bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1.00", 100, false},
		{"0.10", 10, false},
		{"0.01", 1, false},
		{"10.50", 1050, false},
		{"-1.00", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDollarsToCents(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDollarsToCents(%q): expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDollarsToCents(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDollarsToCents(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestValidateAgent(t *testing.T) {
	valid := &AgentConfig{
		AgentID:   "test-agent",
		ProxyPort: 8402,
		Rails: RailsConfig{
			X402: &X402RailConfig{
				Enabled:       true,
				WalletAddress: "0x1234567890abcdef1234567890abcdef12345678",
				EndpointMode:  "open",
			},
		},
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

	badMode := *valid
	badMode.Rails.X402.EndpointMode = "invalid"
	if err := validateAgent(&badMode); err == nil {
		t.Error("expected error for invalid endpoint_mode")
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
	if cfg.Rails.X402 == nil {
		t.Fatal("X402 rail config is nil")
	}
	if cfg.Rails.X402.DailyLimitUSD != "5.00" {
		t.Errorf("DailyLimitUSD = %q, want %q", cfg.Rails.X402.DailyLimitUSD, "5.00")
	}
}

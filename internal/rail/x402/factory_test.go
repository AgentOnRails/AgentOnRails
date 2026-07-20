package x402

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseDollarsToCents(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
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

func mustNode(t *testing.T, yamlStr string) yaml.Node {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(yamlStr), &node); err != nil {
		t.Fatalf("unmarshal test yaml: %v", err)
	}
	// yaml.Unmarshal into a Node produces a DocumentNode; ParseRailConfig
	// expects the mapping node itself (mirrors how map[string]yaml.Node
	// values decode when RailsConfig is unmarshalled from an agent file).
	return *node.Content[0]
}

func TestParseRailConfig_Valid(t *testing.T) {
	node := mustNode(t, `
enabled: true
wallet_address: "0x1234567890abcdef1234567890abcdef12345678"
endpoint_mode: "open"
`)
	rc, err := ParseRailConfig(node)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rc.Enabled || rc.WalletAddress == "" {
		t.Errorf("unexpected parsed config: %+v", rc)
	}
}

func TestParseRailConfig_DefaultsEndpointMode(t *testing.T) {
	node := mustNode(t, `
enabled: false
`)
	rc, err := ParseRailConfig(node)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.EndpointMode != "open" {
		t.Errorf("EndpointMode = %q, want default %q", rc.EndpointMode, "open")
	}
}

func TestParseRailConfig_InvalidEndpointMode(t *testing.T) {
	node := mustNode(t, `
enabled: true
wallet_address: "0x1234567890abcdef1234567890abcdef12345678"
endpoint_mode: "invalid"
`)
	if _, err := ParseRailConfig(node); err == nil {
		t.Error("expected error for invalid endpoint_mode")
	}
}

func TestParseRailConfig_RequiresWalletWhenEnabled(t *testing.T) {
	node := mustNode(t, `
enabled: true
`)
	if _, err := ParseRailConfig(node); err == nil {
		t.Error("expected error for missing wallet_address when enabled")
	}
}

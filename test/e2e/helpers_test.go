// Package e2e contains end-to-end tests that start the full AgentOnRails daemon
// and drive it via a real HTTP proxy client — exactly as an AI agent would use it.
//
// Unlike integration tests (which call ProxyRequest directly), these tests exercise:
//   - Config loading from YAML files
//   - Vault key encryption/decryption
//   - daemon.New() + daemon.Start() TCP server binding
//   - Per-agent port routing
//   - Budget rehydration from SQLite on restart
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/daemon"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/internal/vault"
)

const testPassphrase = "e2e-test-passphrase"

// daemonFixture holds everything needed to drive an e2e test against a live daemon.
type daemonFixture struct {
	ProxyURL  string // e.g. "http://127.0.0.1:8402"
	AuditDB   *audit.SQLiteAuditLogger
	Upstream  *httptest.Server // mock x402 upstream
	DBPath    string
	cancel    context.CancelFunc
}

// daemonOptions configures the test daemon's x402 policy.
type daemonOptions struct {
	PerCallMaxUSD  string
	DailyLimitUSD  string
	WeeklyLimitUSD string
	EndpointMode   string
	AllowedHosts   []string
	SkipPreVerify  bool
}

func defaultOpts() daemonOptions {
	return daemonOptions{
		PerCallMaxUSD: "1.00",
		DailyLimitUSD: "100.00",
		EndpointMode:  "open",
		SkipPreVerify: true,
	}
}

// startDaemon starts a full AgentOnRails daemon with a mock x402 upstream server.
// The daemon is stopped automatically when the test ends.
//
// The mock upstream returns 402 challenges for GET /paid and 200 for GET /free.
// On receipt of PAYMENT-SIGNATURE the upstream returns 200 with a PAYMENT-RESPONSE.
func startDaemon(t *testing.T, opts daemonOptions) *daemonFixture {
	t.Helper()

	upstream := startMockUpstream(t)
	return startDaemonWithUpstream(t, opts, upstream)
}

// startDaemonWithUpstream starts a daemon wired to the given upstream.
func startDaemonWithUpstream(t *testing.T, opts daemonOptions, upstream *httptest.Server) *daemonFixture {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	vaultDir := filepath.Join(tmpDir, "vaults")
	agentsDir := filepath.Join(tmpDir, "agents")
	globalCfgPath := filepath.Join(tmpDir, "aor.yaml")

	// Generate a test wallet key
	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()

	// Find a free port for the proxy
	proxyPort := freePort(t)

	// Write global config
	globalCfg := fmt.Sprintf(`
daemon:
  listen_addr: "127.0.0.1"
  log_level: "error"
  audit_db: %q
  vault_dir: %q
  pid_file: %q
alerts:
  slack_webhook_url: ""
  budget_threshold_pct: 80
facilitators:
  x402: "http://127.0.0.1:0"
`, dbPath, vaultDir, filepath.Join(tmpDir, "daemon.pid"))

	if err := os.WriteFile(globalCfgPath, []byte(globalCfg), 0600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	// Build allowed_hosts YAML block
	allowedHostsYAML := "    allowed_hosts: []\n"
	if len(opts.AllowedHosts) > 0 {
		var sb strings.Builder
		sb.WriteString("    allowed_hosts:\n")
		for _, h := range opts.AllowedHosts {
			fmt.Fprintf(&sb, "      - %q\n", h)
		}
		allowedHostsYAML = sb.String()
	}

	// Write agent config
	if err := os.MkdirAll(agentsDir, 0700); err != nil {
		t.Fatalf("mkdir agents: %v", err)
	}
	agentCfg := fmt.Sprintf(`
agent_id: "e2e-agent"
proxy_port: %d
rails:
  x402:
    enabled: true
    wallet_address: %q
    preferred_chain: "eip155:84532"
    per_call_max_usd: %q
    daily_limit_usd: %q
    endpoint_mode: %q
    skip_pre_verify: %v
    allowed_networks:
      - "eip155:84532"
    velocity:
      max_per_minute: 30
      max_per_hour: 200
      cooldown_seconds: 60
%s`,
		proxyPort,
		addr,
		strOrDefault(opts.PerCallMaxUSD, "1.00"),
		strOrDefault(opts.DailyLimitUSD, "100.00"),
		strOrDefault(opts.EndpointMode, "open"),
		opts.SkipPreVerify,
		allowedHostsYAML,
	)
	if err := os.WriteFile(filepath.Join(agentsDir, "e2e-agent.yaml"), []byte(agentCfg), 0600); err != nil {
		t.Fatalf("write agent config: %v", err)
	}

	// Store wallet key in vault
	v, err := vault.New(vaultDir)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := v.StoreKey("e2e-agent", testPassphrase, key); err != nil {
		t.Fatalf("store key: %v", err)
	}

	// Load configs and start daemon
	global, err := config.LoadGlobal(globalCfgPath)
	if err != nil {
		t.Fatalf("load global config: %v", err)
	}
	agents, err := config.LoadAgents(agentsDir)
	if err != nil {
		t.Fatalf("load agents: %v", err)
	}

	logger, _ := zap.NewProduction(zap.WithCaller(false))

	d, err := daemon.New(global, agents, testPassphrase, logger)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start in background
	done := make(chan error, 1)
	go func() {
		done <- d.Start(ctx)
	}()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort))

	// Open audit DB for assertions
	db, err := audit.NewSQLiteAuditLogger(dbPath)
	if err != nil {
		cancel()
		t.Fatalf("open audit db: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("daemon did not stop within 5s")
		}
		db.Close()
	})

	return &daemonFixture{
		ProxyURL: proxyURL,
		AuditDB:  db,
		Upstream: upstream,
		DBPath:   dbPath,
		cancel:   cancel,
	}
}

// proxyClient returns an http.Client that routes all requests through the given proxy URL.
func proxyClient(proxyURL string) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
		},
		Timeout: 10 * time.Second,
	}
}

// doRequest makes a GET request through the proxy to the upstream /paid endpoint.
func (f *daemonFixture) doRequest(t *testing.T) *http.Response {
	t.Helper()
	return f.doRequestTo(t, f.Upstream.URL+"/paid")
}

// doRequestTo makes a GET request through the proxy to the given URL.
func (f *daemonFixture) doRequestTo(t *testing.T, rawURL string) *http.Response {
	t.Helper()
	client := proxyClient(f.ProxyURL)
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

// recentTxns returns audit records for e2e-agent written in the last minute.
func (f *daemonFixture) recentTxns(t *testing.T) []x402.TransactionRecord {
	t.Helper()
	txns, err := f.AuditDB.QueryTransactions("e2e-agent", time.Now().Add(-time.Minute), 100)
	if err != nil {
		t.Fatalf("query transactions: %v", err)
	}
	return txns
}

// ─── Mock upstream ─────────────────────────────────────────────────────────────

// startMockUpstream returns a server that:
//   - GET /free  → 200 (no payment)
//   - GET /paid  → 402 with PAYMENT-REQUIRED challenge (first request)
//   - GET /paid with PAYMENT-SIGNATURE → 200 with PAYMENT-RESPONSE
//   - GET /health → 200
func startMockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/free", "/health":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))

		case "/paid":
			if r.Header.Get("PAYMENT-SIGNATURE") == "" {
				challenge := x402.PaymentRequired{
					X402Version: 2,
					Accepts: []x402.PaymentRequirement{{
						Scheme:            "exact",
						Network:           "eip155:84532",
						Amount:            "10000", // $0.01
						Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
						PayTo:             "0x" + strings.Repeat("f", 40),
						MaxTimeoutSeconds: 60,
						Extra:             map[string]any{"name": "USDC", "version": "2"},
					}},
				}
				data, _ := json.Marshal(challenge)
				w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
				w.WriteHeader(http.StatusPaymentRequired)
				return
			}
			// Payment accepted
			resp := x402.PaymentResponse{
				Success:     true,
				Transaction: "0xe2etestdeadbeef" + strconv.FormatInt(time.Now().UnixNano(), 16),
				Network:     "eip155:84532",
				Payer:       "0x" + strings.Repeat("a", 40),
			}
			data, _ := json.Marshal(resp)
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(data))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":"paid content"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ─── Port utilities ────────────────────────────────────────────────────────────

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s did not open within 3s", addr)
}

// ─── Scenario YAML types ───────────────────────────────────────────────────────

// ScenarioFile is the top-level structure of a scenario YAML file.
type ScenarioFile struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Policy      ScenarioPolicy `yaml:"policy"`
	Steps       []ScenarioStep `yaml:"steps"`

	// For single-loop scenarios (velocity_attack.yaml)
	RepeatCount          int    `yaml:"repeat_count"`
	ExpectLastStatus     int    `yaml:"expect_last_status"`
	ExpectLastBodyContains string `yaml:"expect_last_body_contains"`
}

// ScenarioPolicy maps to X402RailConfig fields for the test daemon.
type ScenarioPolicy struct {
	PerCallMaxUSD string   `yaml:"per_call_max_usd"`
	DailyLimitUSD string   `yaml:"daily_limit_usd"`
	EndpointMode  string   `yaml:"endpoint_mode"`
	AllowedHosts  []string `yaml:"allowed_hosts"`
}

// ScenarioStep is one request+assertion within a scenario.
type ScenarioStep struct {
	Description          string  `yaml:"description"`
	OverrideURL          string  `yaml:"override_url"`
	ExpectStatus         int     `yaml:"expect_status"`
	ExpectAuditStatus    string  `yaml:"expect_audit_status"`
	ExpectAmountUSD      float64 `yaml:"expect_amount_usd"`
	ExpectBodyContains   string  `yaml:"expect_body_contains"`
	CheckDailySpentCents int64   `yaml:"check_daily_spent_cents"`
}

// loadScenario reads and unmarshals a scenario YAML file.
func loadScenario(t *testing.T, path string) ScenarioFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scenario %s: %v", path, err)
	}
	var s ScenarioFile
	if err := yaml.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse scenario %s: %v", path, err)
	}
	return s
}

func strOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

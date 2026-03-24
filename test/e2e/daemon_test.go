package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/daemon"
	"github.com/agentOnRails/agent-on-rails/internal/vault"
)

// TestDaemon_HappyPath starts a full daemon and makes a real proxied request
// through the TCP proxy to a mock x402 upstream.
func TestDaemon_HappyPath(t *testing.T) {
	f := startDaemon(t, defaultOpts())

	resp := f.doRequest(t)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Audit record should be written promptly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recs := f.recentTxns(t); len(recs) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	recs := f.recentTxns(t)
	if len(recs) == 0 {
		t.Fatal("expected at least one audit record, got none")
	}
	if recs[0].Status != "allowed" {
		t.Fatalf("expected audit status 'allowed', got %q", recs[0].Status)
	}
}

// TestDaemon_FreeEndpoint verifies that requests to endpoints that return 200
// (no 402) are passed through without attempting payment.
func TestDaemon_FreeEndpoint(t *testing.T) {
	f := startDaemon(t, defaultOpts())

	resp := f.doRequestTo(t, f.Upstream.URL+"/free")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for free endpoint, got %d", resp.StatusCode)
	}

	// No audit records should be written for free endpoints.
	time.Sleep(100 * time.Millisecond)
	recs := f.recentTxns(t)
	if len(recs) != 0 {
		t.Fatalf("expected no audit records for free endpoint, got %d", len(recs))
	}
}

// TestDaemon_ConfigPersisted verifies that budget state survives a daemon
// restart by rehydrating from the SQLite audit log.
func TestDaemon_ConfigPersisted(t *testing.T) {
	upstream := startMockUpstream(t)

	// Daemon with $0.01 daily limit (one payment exhausts it).
	opts := daemonOptions{
		PerCallMaxUSD: "0.10",
		DailyLimitUSD: "0.01",
		EndpointMode:  "open",
		SkipPreVerify: true,
	}
	f := startDaemonWithUpstream(t, opts, upstream)

	// First request — should succeed and exhaust the $0.01 budget.
	resp1 := f.doRequest(t)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", resp1.StatusCode)
	}

	// Wait for audit record to be persisted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recs := f.recentTxns(t); len(recs) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Stop the first daemon.
	f.cancel()
	time.Sleep(200 * time.Millisecond)

	// Start a second daemon pointing at the same DB and vault.
	f2 := startDaemonWithUpstream(t, opts, upstream)
	// Override the DB path to reuse the first daemon's DB.
	// The second daemon starts with a fresh temp dir, so we need to
	// redirect it at the same DB. We do this by making a second call
	// using the already-registered fixture's audit DB handle but a new proxy.
	// NOTE: The second daemon has its own budget (starts at 0 spent) because
	// startDaemonWithUpstream creates a new tmpDir. To properly test
	// rehydration we need to share the DB path — so we use a manual setup.
	f2.cancel() // cancel the auto-started second daemon immediately

	// Manual restart sharing the same DB and vault.
	f3 := restartDaemon(t, opts, f.DBPath, upstream)

	// Second request should be blocked — budget was already spent and
	// rehydrated from the shared DB.
	resp2 := f3.doRequest(t)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("after restart: expected 403 (budget exhausted), got %d", resp2.StatusCode)
	}
}

// TestDaemon_MultiAgentIsolation verifies that two agents on different ports
// have independent budgets: spending by one does not affect the other.
func TestDaemon_MultiAgentIsolation(t *testing.T) {
	upstream := startMockUpstream(t)

	// Both agents share $0.01 daily limit so a single payment exhausts each one.
	opts := daemonOptions{
		PerCallMaxUSD: "0.10",
		DailyLimitUSD: "0.01",
		EndpointMode:  "open",
		SkipPreVerify: true,
	}

	f1 := startDaemonWithUpstream(t, opts, upstream)
	f2 := startDaemonWithUpstream(t, opts, upstream)

	// Make one payment through agent 1's port.
	resp := f1.doRequest(t)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent1 first request: expected 200, got %d", resp.StatusCode)
	}

	// Agent 1 is now exhausted.
	time.Sleep(150 * time.Millisecond)
	resp2 := f1.doRequest(t)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("agent1 second request: expected 403 (exhausted), got %d", resp2.StatusCode)
	}

	// Agent 2 is still untouched — first payment should succeed.
	resp3 := f2.doRequest(t)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("agent2 first request: expected 200 (independent budget), got %d", resp3.StatusCode)
	}
}

// TestDaemon_GracefulShutdown verifies that cancelling the daemon context
// causes Start() to return cleanly with no error.
func TestDaemon_GracefulShutdown(t *testing.T) {
	f := startDaemon(t, defaultOpts())

	// Make a request to confirm it's up.
	resp := f.doRequest(t)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-shutdown request: expected 200, got %d", resp.StatusCode)
	}

	// Cancel triggers graceful shutdown (already wired via t.Cleanup in helpers).
	// Here we cancel early and confirm the proxy is no longer accepting connections.
	f.cancel()
	time.Sleep(300 * time.Millisecond)

	client := proxyClient(f.ProxyURL)
	client.Timeout = 500 * time.Millisecond
	_, err := client.Get(f.Upstream.URL + "/health")
	if err == nil {
		t.Fatal("expected connection refused after daemon shutdown, but request succeeded")
	}
}

// TestDaemon_VaultWrongPassphrase verifies that daemon.New() returns an error
// when the passphrase does not match the stored vault key.
func TestDaemon_VaultWrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	vaultDir := filepath.Join(tmpDir, "vaults")
	agentsDir := filepath.Join(tmpDir, "agents")
	globalCfgPath := filepath.Join(tmpDir, "aor.yaml")

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	proxyPort := freePort(t)

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
    per_call_max_usd: "1.00"
    daily_limit_usd: "100.00"
    endpoint_mode: "open"
    skip_pre_verify: true
    allowed_networks:
      - "eip155:84532"
    velocity:
      max_per_minute: 30
      max_per_hour: 200
      cooldown_seconds: 60
    allowed_hosts: []
`, proxyPort, addr)
	if err := os.WriteFile(filepath.Join(agentsDir, "e2e-agent.yaml"), []byte(agentCfg), 0600); err != nil {
		t.Fatalf("write agent config: %v", err)
	}

	v, err := vault.New(vaultDir)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := v.StoreKey("e2e-agent", "correct-passphrase", key); err != nil {
		t.Fatalf("store key: %v", err)
	}

	global, err := config.LoadGlobal(globalCfgPath)
	if err != nil {
		t.Fatalf("load global config: %v", err)
	}
	agents, err := config.LoadAgents(agentsDir)
	if err != nil {
		t.Fatalf("load agents: %v", err)
	}

	logger, _ := zap.NewProduction(zap.WithCaller(false))
	_, err = daemon.New(global, agents, "wrong-passphrase", logger)
	if err == nil {
		t.Fatal("expected daemon.New to return error with wrong passphrase, got nil")
	}
	if !strings.Contains(err.Error(), "load wallet") {
		t.Fatalf("expected error to mention 'load wallet', got: %v", err)
	}
}

// TestDaemon_MissingAgentConfig verifies that daemon.New() succeeds but
// returns a daemon with no agents when the agents directory is empty.
// The daemon in this case starts with 0 agent servers and Start() returns
// immediately when context is cancelled.
func TestDaemon_MissingAgentConfig(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	vaultDir := filepath.Join(tmpDir, "vaults")
	agentsDir := filepath.Join(tmpDir, "agents") // empty
	globalCfgPath := filepath.Join(tmpDir, "aor.yaml")

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
	if err := os.MkdirAll(agentsDir, 0700); err != nil {
		t.Fatalf("mkdir agents: %v", err)
	}

	global, err := config.LoadGlobal(globalCfgPath)
	if err != nil {
		t.Fatalf("load global config: %v", err)
	}
	agents, err := config.LoadAgents(agentsDir)
	if err != nil {
		t.Fatalf("load agents: %v", err)
	}

	if len(agents) != 0 {
		t.Fatalf("expected 0 agents from empty dir, got %d", len(agents))
	}

	logger, _ := zap.NewProduction(zap.WithCaller(false))
	d, err := daemon.New(global, agents, "any-passphrase", logger)
	if err != nil {
		t.Fatalf("daemon.New with empty agents: %v", err)
	}

	// Start should return cleanly after context cancel.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop within 3s after context cancel")
	}
}

// ─── restartDaemon ────────────────────────────────────────────────────────────

// restartDaemon starts a new daemon that reuses an existing audit DB (to test
// budget rehydration across restarts). It creates a fresh vault and config but
// points the daemon at the given dbPath.
func restartDaemon(t *testing.T, opts daemonOptions, dbPath string, upstream *httptest.Server) *daemonFixture {
	t.Helper()

	tmpDir := t.TempDir()
	vaultDir := filepath.Join(tmpDir, "vaults")
	agentsDir := filepath.Join(tmpDir, "agents")
	globalCfgPath := filepath.Join(tmpDir, "aor.yaml")

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	proxyPort := freePort(t)

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
    allowed_hosts: []
`,
		proxyPort, addr,
		strOrDefault(opts.PerCallMaxUSD, "1.00"),
		strOrDefault(opts.DailyLimitUSD, "100.00"),
		strOrDefault(opts.EndpointMode, "open"),
		opts.SkipPreVerify,
	)
	if err := os.WriteFile(filepath.Join(agentsDir, "e2e-agent.yaml"), []byte(agentCfg), 0600); err != nil {
		t.Fatalf("write agent config: %v", err)
	}

	v, err := vault.New(vaultDir)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := v.StoreKey("e2e-agent", testPassphrase, key); err != nil {
		t.Fatalf("store key: %v", err)
	}

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
		t.Fatalf("daemon.New (restart): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort))

	// Reopen the shared DB for assertions.
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
			t.Log("restarted daemon did not stop within 5s")
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

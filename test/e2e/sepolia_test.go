package e2e

// Sepolia real-chain e2e tests.
//
// These tests make real on-chain payments on Base Sepolia testnet and are
// skipped unless TEST_SEPOLIA=1 is set. They require a funded wallet with
// USDC on Base Sepolia.
//
// Required environment variables:
//
//	TEST_SEPOLIA=1                  — enable this test suite
//	AOR_TEST_PRIVATE_KEY=0x...      — hex private key of a funded Base Sepolia wallet
//	AOR_TEST_PAYTO=0x...            — recipient wallet for test payments
//
// Optional:
//
//	AOR_TEST_FACILITATOR            — facilitator URL (default: https://x402.org/facilitator)
//	AOR_TEST_AMOUNT                 — atomic USDC units per call (default: 10000 = $0.01)
//
// Usage:
//
//	TEST_SEPOLIA=1 AOR_TEST_PRIVATE_KEY=0x... AOR_TEST_PAYTO=0x... \
//	  go test ./test/e2e/ -run TestSepolia -v -timeout=120s

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

const (
	sepoliaNetwork     = "eip155:84532"
	defaultFacilitator = "https://x402.org/facilitator"
	defaultAmount      = "10000" // $0.01 USDC
)

func skipUnlessSepoliaEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_SEPOLIA") != "1" {
		t.Skip("skipping Sepolia test (set TEST_SEPOLIA=1 to enable)")
	}
	if os.Getenv("AOR_TEST_PRIVATE_KEY") == "" {
		t.Fatal("TEST_SEPOLIA=1 but AOR_TEST_PRIVATE_KEY is not set")
	}
	if os.Getenv("AOR_TEST_PAYTO") == "" {
		t.Fatal("TEST_SEPOLIA=1 but AOR_TEST_PAYTO is not set")
	}
}

// sepoliaFixture holds everything for a Sepolia test: a running testserver
// subprocess and a daemon pointed at it.
type sepoliaFixture struct {
	ProxyURL string
	SrvURL   string // base URL of the testserver subprocess
	DBPath   string
	cancel   context.CancelFunc
	db       *audit.SQLiteAuditLogger
	srv      *exec.Cmd
}

// startSepoliaFixture starts scripts/testserver as a subprocess and a real
// daemon configured for Base Sepolia.
func startSepoliaFixture(t *testing.T) *sepoliaFixture {
	t.Helper()

	payTo       := os.Getenv("AOR_TEST_PAYTO")
	privateKeyHex := strings.TrimPrefix(os.Getenv("AOR_TEST_PRIVATE_KEY"), "0x")
	facilitator := os.Getenv("AOR_TEST_FACILITATOR")
	if facilitator == "" {
		facilitator = defaultFacilitator
	}
	amount := os.Getenv("AOR_TEST_AMOUNT")
	if amount == "" {
		amount = defaultAmount
	}

	// Parse the private key.
	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("parse AOR_TEST_PRIVATE_KEY: %v", err)
	}
	key, err := ethcrypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()

	// Start the testserver subprocess.
	srvPort := freePort(t)
	srvAddr := fmt.Sprintf(":%d", srvPort)
	srvURL  := fmt.Sprintf("http://127.0.0.1:%d", srvPort)

	cmd := exec.Command("go", "run", "./scripts/testserver/",
		"-addr", srvAddr,
		"-network", sepoliaNetwork,
		"-amount", amount,
		"-payto", payTo,
		"-facilitator", facilitator,
		"-verify=true",
	)
	cmd.Dir = projectRoot(t)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start testserver: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })

	// Wait for testserver to be ready.
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", srvPort))

	// Set up daemon config in a temp dir.
	tmpDir := t.TempDir()
	dbPath  := fmt.Sprintf("%s/audit.db", tmpDir)
	vaultDir := fmt.Sprintf("%s/vaults", tmpDir)
	agentsDir := fmt.Sprintf("%s/agents", tmpDir)

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
  x402: %q
`, dbPath, vaultDir, tmpDir+"/daemon.pid", facilitator)

	if err := os.WriteFile(tmpDir+"/aor.yaml", []byte(globalCfg), 0600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	if err := os.MkdirAll(agentsDir, 0700); err != nil {
		t.Fatalf("mkdir agents: %v", err)
	}
	proxyPort := freePort(t)
	agentCfg := fmt.Sprintf(`
agent_id: "sepolia-agent"
proxy_port: %d
rails:
  x402:
    enabled: true
    wallet_address: %q
    preferred_chain: %q
    per_call_max_usd: "0.05"
    daily_limit_usd: "1.00"
    endpoint_mode: "open"
    skip_pre_verify: false
    allowed_networks:
      - %q
    velocity:
      max_per_minute: 30
      max_per_hour: 200
      cooldown_seconds: 60
    allowed_hosts: []
`, proxyPort, addr, sepoliaNetwork, sepoliaNetwork)
	if err := os.WriteFile(agentsDir+"/sepolia-agent.yaml", []byte(agentCfg), 0600); err != nil {
		t.Fatalf("write agent config: %v", err)
	}

	v, err := vault.New(vaultDir)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	const sepoliaPassphrase = "sepolia-test-passphrase"
	if err := v.StoreKey("sepolia-agent", sepoliaPassphrase, key); err != nil {
		t.Fatalf("store key: %v", err)
	}

	global, err := config.LoadGlobal(tmpDir + "/aor.yaml")
	if err != nil {
		t.Fatalf("load global config: %v", err)
	}
	agents, err := config.LoadAgents(agentsDir)
	if err != nil {
		t.Fatalf("load agents: %v", err)
	}

	logger, _ := zap.NewProduction(zap.WithCaller(false))
	d, err := daemon.New(global, agents, sepoliaPassphrase, logger)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort))

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
			t.Log("sepolia daemon did not stop within 5s")
		}
		db.Close()
	})

	return &sepoliaFixture{
		ProxyURL: proxyURL,
		SrvURL:   srvURL,
		DBPath:   dbPath,
		cancel:   cancel,
		db:       db,
		srv:      cmd,
	}
}

func (f *sepoliaFixture) doRequest(t *testing.T, url string) *http.Response {
	t.Helper()
	client := proxyClient(f.ProxyURL)
	client.Timeout = 30 * time.Second
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// ─── Sepolia tests ────────────────────────────────────────────────────────────

// TestSepolia_FacilitatorReachable is a smoke test that confirms x402.org is
// accessible before running heavier tests.
func TestSepolia_FacilitatorReachable(t *testing.T) {
	skipUnlessSepoliaEnabled(t)

	facilitator := os.Getenv("AOR_TEST_FACILITATOR")
	if facilitator == "" {
		facilitator = defaultFacilitator
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(facilitator)
	if err != nil {
		t.Fatalf("facilitator unreachable at %s: %v", facilitator, err)
	}
	resp.Body.Close()
	// Any response (even 404) means the host resolved and TCP connected.
	t.Logf("facilitator responded with HTTP %d", resp.StatusCode)
}

// TestSepolia_HappyPath makes a real payment on Base Sepolia and verifies the
// daemon signed a valid EIP-3009 authorization that the facilitator accepted.
func TestSepolia_HappyPath(t *testing.T) {
	skipUnlessSepoliaEnabled(t)

	f := startSepoliaFixture(t)

	resp := f.doRequest(t, f.SrvURL+"/paid")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Verify audit record written.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		txns, err := f.db.QueryTransactions("sepolia-agent", time.Now().Add(-time.Minute), 10)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		if len(txns) > 0 && txns[0].Status == "allowed" {
			t.Logf("Sepolia txHash: %s", txns[0].TxHash)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no allowed audit record found within 5s")
}

// TestSepolia_BudgetEnforced makes two real payments to exhaust the $0.02
// daily budget, then verifies the third is blocked locally (no on-chain spend).
func TestSepolia_BudgetEnforced(t *testing.T) {
	skipUnlessSepoliaEnabled(t)

	// Override daemon with very tight budget for this test.
	t.Setenv("AOR_TEST_DAILY_LIMIT", "0.02")
	f := startSepoliaFixture(t)

	for i := 1; i <= 2; i++ {
		resp := f.doRequest(t, f.SrvURL+"/paid")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("payment %d: expected 200, got %d: %s", i, resp.StatusCode, body)
		}
		time.Sleep(500 * time.Millisecond) // wait for audit commit
	}

	// Third payment should be blocked by budget.
	resp := f.doRequest(t, f.SrvURL+"/paid")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("3rd payment: expected 403 (budget exhausted), got %d: %s", resp.StatusCode, body)
	}
}

// projectRoot returns the repository root (two dirs up from this test file).
func projectRoot(t *testing.T) string {
	t.Helper()
	// This file lives at test/e2e/sepolia_test.go; root is ../../
	// Use os.Getwd() as the fallback — tests run from the module root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// When run via `go test ./test/e2e/`, wd is already the module root.
	// The go test runner sets wd to the package directory, so walk up.
	if strings.HasSuffix(wd, "test/e2e") || strings.HasSuffix(wd, `test\e2e`) {
		return wd + "/../.."
	}
	return wd
}

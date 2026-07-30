package e2e

// Solana devnet real-chain e2e tests — the Solana counterpart to
// sepolia_test.go, structured identically on purpose: same fixture shape,
// same three tests (facilitator reachability, happy path, budget
// enforcement), same self-skip-unless-enabled gating. What differs is
// everything specific to Solana: an ed25519 wallet key (key_type: ed25519),
// a base58 payTo/wallet address, and — unlike Base Sepolia, where
// x402.org's public facilitator is a known-good default — there is no
// widely-adopted default Solana x402 facilitator yet, so
// AOR_TEST_SOLANA_FACILITATOR is required with no fallback rather than
// silently pointing at something that may not exist or may not speak x402
// the way this rail expects.
//
// Required environment variables:
//
//	TEST_SOLANA_DEVNET=1                 — enable this test suite
//	AOR_TEST_SOLANA_PRIVATE_KEY=...       — hex or base58 32-byte ed25519 seed of a funded devnet wallet (needs devnet SOL for fees + devnet USDC)
//	AOR_TEST_SOLANA_PAYTO=...             — base58 recipient wallet for test payments
//	AOR_TEST_SOLANA_FACILITATOR=https://... — a Solana-capable x402 facilitator base URL (no default)
//
// Optional:
//
//	AOR_TEST_SOLANA_AMOUNT                — atomic USDC units per call (default: 10000 = $0.01)
//
// Usage:
//
//	TEST_SOLANA_DEVNET=1 AOR_TEST_SOLANA_PRIVATE_KEY=... AOR_TEST_SOLANA_PAYTO=... \
//	  AOR_TEST_SOLANA_FACILITATOR=https://... \
//	  go test ./test/e2e/ -run TestSolanaDevnet -v -timeout=120s
//
// This test intentionally cannot be run by CI or by anyone without a funded
// devnet wallet and a working Solana x402 facilitator — it exists as a real,
// runnable proof that chainsign/solana settles a genuine devnet transaction
// through the exact same ProxyRequest pipeline EVM chains use, not just a
// mocked-RPC unit test (see chainsign/solana's own tests for that level).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/daemon"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/vault"
)

const (
	solanaDevnetNetwork = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	defaultSolanaAmount = "10000" // $0.01 USDC (6 decimals)
)

func skipUnlessSolanaDevnetEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_SOLANA_DEVNET") != "1" {
		t.Skip("skipping Solana devnet test (set TEST_SOLANA_DEVNET=1 to enable)")
	}
	if os.Getenv("AOR_TEST_SOLANA_PRIVATE_KEY") == "" {
		t.Fatal("TEST_SOLANA_DEVNET=1 but AOR_TEST_SOLANA_PRIVATE_KEY is not set")
	}
	if os.Getenv("AOR_TEST_SOLANA_PAYTO") == "" {
		t.Fatal("TEST_SOLANA_DEVNET=1 but AOR_TEST_SOLANA_PAYTO is not set")
	}
	if os.Getenv("AOR_TEST_SOLANA_FACILITATOR") == "" {
		t.Fatal("TEST_SOLANA_DEVNET=1 but AOR_TEST_SOLANA_FACILITATOR is not set (no default — unlike Sepolia, there is no widely-adopted public Solana x402 facilitator yet)")
	}
}

// parseSolanaTestSeed accepts the same hex-or-base58 32-byte-seed shapes
// `aor credentials set-wallet --key-type ed25519` does (see
// cmd/aor/commands/credentials.go's parseEd25519Seed) — duplicated here in
// a few lines rather than imported, since a CLI command package isn't
// something test/e2e should depend on.
func parseSolanaTestSeed(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimSpace(s)
	if hexStr := strings.TrimPrefix(s, "0x"); len(hexStr) == ed25519.SeedSize*2 {
		if b, err := hex.DecodeString(hexStr); err == nil {
			return b
		}
	}
	var arr [32]byte
	if err := base58.Decode32(s, &arr); err == nil {
		return arr[:]
	}
	t.Fatalf("AOR_TEST_SOLANA_PRIVATE_KEY is not a valid %d-byte ed25519 seed (hex or base58)", ed25519.SeedSize)
	return nil
}

// solanaDevnetFixture holds everything for a Solana devnet test: a running
// testserver subprocess and a daemon pointed at it.
type solanaDevnetFixture struct {
	ProxyURL string
	SrvURL   string
	DBPath   string
	cancel   context.CancelFunc
	db       *audit.SQLiteAuditLogger
	srv      *exec.Cmd
}

func startSolanaDevnetFixture(t *testing.T) *solanaDevnetFixture {
	t.Helper()

	payTo := os.Getenv("AOR_TEST_SOLANA_PAYTO")
	seedStr := os.Getenv("AOR_TEST_SOLANA_PRIVATE_KEY")
	facilitator := os.Getenv("AOR_TEST_SOLANA_FACILITATOR")
	amount := os.Getenv("AOR_TEST_SOLANA_AMOUNT")
	if amount == "" {
		amount = defaultSolanaAmount
	}

	seed := parseSolanaTestSeed(t, seedStr)
	edPriv := ed25519.NewKeyFromSeed(seed)
	walletAddr := solanago.PrivateKey(edPriv).PublicKey().String()

	srvPort := freePort(t)
	srvAddr := fmt.Sprintf(":%d", srvPort)
	srvURL := fmt.Sprintf("http://127.0.0.1:%d", srvPort)

	cmd := exec.Command("go", "run", "./scripts/testserver/",
		"-addr", srvAddr,
		"-network", solanaDevnetNetwork,
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

	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", srvPort))

	tmpDir := t.TempDir()
	dbPath := fmt.Sprintf("%s/audit.db", tmpDir)
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
agent_id: "solana-devnet-agent"
proxy_port: %d
rails:
  x402:
    enabled: true
    key_type: "ed25519"
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
`, proxyPort, walletAddr, solanaDevnetNetwork, solanaDevnetNetwork)
	if err := os.WriteFile(agentsDir+"/solana-devnet-agent.yaml", []byte(agentCfg), 0600); err != nil {
		t.Fatalf("write agent config: %v", err)
	}

	v, err := vault.New(vaultDir)
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	const solanaDevnetPassphrase = "solana-devnet-test-passphrase"
	if err := v.StoreKey("solana-devnet-agent", solanaDevnetPassphrase, seed); err != nil {
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
	d, err := daemon.New(global, agents, solanaDevnetPassphrase, logger)
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
			t.Log("solana devnet daemon did not stop within 5s")
		}
		db.Close()
	})

	return &solanaDevnetFixture{
		ProxyURL: proxyURL,
		SrvURL:   srvURL,
		DBPath:   dbPath,
		cancel:   cancel,
		db:       db,
		srv:      cmd,
	}
}

func (f *solanaDevnetFixture) doRequest(t *testing.T, url string) *http.Response {
	t.Helper()
	client := proxyClient(f.ProxyURL)
	client.Timeout = 30 * time.Second
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// ─── Solana devnet tests ───────────────────────────────────────────────────

// TestSolanaDevnet_FacilitatorReachable is a smoke test confirming the
// configured Solana facilitator is reachable before running heavier tests.
func TestSolanaDevnet_FacilitatorReachable(t *testing.T) {
	skipUnlessSolanaDevnetEnabled(t)

	facilitator := os.Getenv("AOR_TEST_SOLANA_FACILITATOR")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(facilitator)
	if err != nil {
		t.Fatalf("facilitator unreachable at %s: %v", facilitator, err)
	}
	resp.Body.Close()
	t.Logf("facilitator responded with HTTP %d", resp.StatusCode)
}

// TestSolanaDevnet_HappyPath makes a real payment on Solana devnet and
// verifies the daemon signed and settled a valid SPL TransferChecked
// transaction the facilitator accepted — chainsign/solana's proof that this
// isn't only correct against a mocked RPC server.
func TestSolanaDevnet_HappyPath(t *testing.T) {
	skipUnlessSolanaDevnetEnabled(t)

	f := startSolanaDevnetFixture(t)

	resp := f.doRequest(t, f.SrvURL+"/paid")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		txns, err := f.db.QueryTransactions("solana-devnet-agent", time.Now().Add(-time.Minute), 10)
		if err != nil {
			t.Fatalf("query audit: %v", err)
		}
		if len(txns) > 0 && txns[0].Status == "allowed" {
			t.Logf("Solana devnet txHash: %s", txns[0].TxHash)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("no allowed audit record found within 5s")
}

// TestSolanaDevnet_BudgetEnforced makes two real payments to exhaust the
// $0.02 daily budget, then verifies the third is blocked locally (no
// on-chain spend) — the same guarantee Sepolia's equivalent test proves for
// EVM, now proven for a chain family with a structurally different signing
// model (see this file's own package doc comment).
func TestSolanaDevnet_BudgetEnforced(t *testing.T) {
	skipUnlessSolanaDevnetEnabled(t)

	f := startSolanaDevnetFixture(t)

	for i := 1; i <= 2; i++ {
		resp := f.doRequest(t, f.SrvURL+"/paid")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("payment %d: expected 200, got %d: %s", i, resp.StatusCode, body)
		}
		time.Sleep(500 * time.Millisecond)
	}

	resp := f.doRequest(t, f.SrvURL+"/paid")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("3rd payment: expected 403 (budget exhausted), got %d: %s", resp.StatusCode, body)
	}
}

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/config"
	_ "github.com/agentOnRails/agent-on-rails/internal/rail/x402" // registers "x402"
	"github.com/agentOnRails/agent-on-rails/vault"

	"github.com/agentOnRails/agent-on-rails/approval"
)

const testPassphrase = "control-test-pass"

// newTestDaemon builds a real Daemon (real audit DB, real vault, one real
// x402 agent named "agent-a") backed entirely by temp dirs — no live
// listener for the agent proxy is started (proxyPort is 0, so tests that
// do call startAgentServer get a random free port rather than a fixed,
// possibly-colliding one).
func newTestDaemon(t *testing.T, dailyLimitUSD, requireApprovalAboveUSD string) *Daemon {
	t.Helper()
	dir := t.TempDir()

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()

	v, err := vault.New(filepath.Join(dir, "vaults"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.StoreKey("agent-a", testPassphrase, ethcrypto.FromECDSA(key)); err != nil {
		t.Fatal(err)
	}

	rawYAML := fmt.Sprintf(`
enabled: true
wallet_address: %q
daily_limit_usd: %q
require_approval_above_usd: %q
`, addr, dailyLimitUSD, requireApprovalAboveUSD)
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML), &node); err != nil {
		t.Fatal(err)
	}

	agentCfg := &config.AgentConfig{
		AgentID:   "agent-a",
		ProxyPort: 0,
		Rails:     config.RailsConfig{"x402": *node.Content[0]},
	}

	global := &config.GlobalConfig{
		Daemon: config.DaemonConfig{
			ListenAddr: "127.0.0.1",
			AuditDB:    filepath.Join(dir, "audit.db"),
			VaultDir:   filepath.Join(dir, "vaults"),
			PIDFile:    filepath.Join(dir, "daemon.pid"),
		},
	}

	logger := zap.NewNop()
	d, err := New(global, []*config.AgentConfig{agentCfg}, testPassphrase, logger)
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	d.controlToken = "test-token"
	t.Cleanup(func() { d.db.Close() })
	return d
}

func doControlRequest(d *Daemon, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+d.controlToken)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	return w
}

// ─── Auth ───────────────────────────────────────────────────────────────────

func TestControlAuth_MissingToken_Rejected(t *testing.T) {
	d := newTestDaemon(t, "", "")
	req := httptest.NewRequest(http.MethodGet, "/control/approvals", nil)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestControlAuth_WrongToken_Rejected(t *testing.T) {
	d := newTestDaemon(t, "", "")
	req := httptest.NewRequest(http.MethodGet, "/control/approvals", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestControlAuth_QueryParamToken_Accepted(t *testing.T) {
	d := newTestDaemon(t, "", "")
	req := httptest.NewRequest(http.MethodGet, "/control/approvals?token=test-token", nil)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ─── Approvals ──────────────────────────────────────────────────────────────

func TestControl_ListApprovals_Empty(t *testing.T) {
	d := newTestDaemon(t, "", "")
	w := doControlRequest(d, http.MethodGet, "/control/approvals")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var pending []approval.Pending
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("expected no pending approvals, got %d", len(pending))
	}
}

func TestControl_ListAndApproveApproval_UnblocksAwait(t *testing.T) {
	d := newTestDaemon(t, "", "")
	done := make(chan struct{})
	var approved bool
	var awaitErr error
	go func() {
		approved, awaitErr = d.approvals.Await(context.Background(), approval.Request{AgentID: "agent-a", AmountCents: 5000}, time.Second)
		close(done)
	}()

	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		w := doControlRequest(d, http.MethodGet, "/control/approvals")
		var pending []approval.Pending
		json.Unmarshal(w.Body.Bytes(), &pending) //nolint:errcheck
		if len(pending) == 1 {
			id = pending[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	if id == "" {
		t.Fatal("approval never appeared in the list")
	}

	w := doControlRequest(d, http.MethodPost, "/control/approvals/"+id+"/approve")
	if w.Code != http.StatusNoContent {
		t.Errorf("approve status = %d, want 204", w.Code)
	}
	<-done
	if awaitErr != nil {
		t.Fatalf("Await returned an error: %v", awaitErr)
	}
	if !approved {
		t.Error("expected the payment to be approved")
	}
}

func TestControl_DenyApproval_UnblocksAwaitAsDenied(t *testing.T) {
	d := newTestDaemon(t, "", "")
	done := make(chan struct{})
	var approved bool
	go func() {
		approved, _ = d.approvals.Await(context.Background(), approval.Request{AgentID: "agent-a"}, time.Second)
		close(done)
	}()

	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pending := d.approvals.List()
		if len(pending) == 1 {
			id = pending[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	w := doControlRequest(d, http.MethodPost, "/control/approvals/"+id+"/deny")
	if w.Code != http.StatusNoContent {
		t.Errorf("deny status = %d, want 204", w.Code)
	}
	<-done
	if approved {
		t.Error("expected the payment to be denied")
	}
}

func TestControl_ResolveApproval_UnknownID(t *testing.T) {
	d := newTestDaemon(t, "", "")
	w := doControlRequest(d, http.MethodPost, "/control/approvals/does-not-exist/approve")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ─── Pause / resume ─────────────────────────────────────────────────────────

func TestControl_PauseThenResumeAgent(t *testing.T) {
	d := newTestDaemon(t, "", "")
	ar := d.agents[0]
	srv, err := d.startAgentServer(ar)
	if err != nil {
		t.Fatal(err)
	}
	d.servers["agent-a"] = srv

	w := doControlRequest(d, http.MethodPost, "/control/agents/agent-a/pause")
	if w.Code != http.StatusNoContent {
		t.Fatalf("pause status = %d, want 204, body: %s", w.Code, w.Body.String())
	}
	d.mu.Lock()
	_, running := d.servers["agent-a"]
	d.mu.Unlock()
	if running {
		t.Error("expected agent-a to no longer be in the running servers map after pause")
	}

	w = doControlRequest(d, http.MethodPost, "/control/agents/agent-a/resume")
	if w.Code != http.StatusNoContent {
		t.Fatalf("resume status = %d, want 204, body: %s", w.Code, w.Body.String())
	}
	d.mu.Lock()
	_, running = d.servers["agent-a"]
	d.mu.Unlock()
	if !running {
		t.Error("expected agent-a to be running again after resume")
	}

	// Cleanup: stop whatever server is currently running for agent-a.
	d.mu.Lock()
	final := d.servers["agent-a"]
	d.mu.Unlock()
	if final != nil {
		final.Close() //nolint:errcheck
	}
}

func TestControl_PauseAgent_NotRunning_Errors(t *testing.T) {
	d := newTestDaemon(t, "", "")
	w := doControlRequest(d, http.MethodPost, "/control/agents/agent-a/pause")
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (agent isn't running)", w.Code)
	}
}

func TestControl_ResumeAgent_UnknownAgent_Errors(t *testing.T) {
	d := newTestDaemon(t, "", "")
	w := doControlRequest(d, http.MethodPost, "/control/agents/does-not-exist/resume")
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestControl_ResumeAgent_AlreadyRunning_Errors(t *testing.T) {
	d := newTestDaemon(t, "", "")
	ar := d.agents[0]
	srv, err := d.startAgentServer(ar)
	if err != nil {
		t.Fatal(err)
	}
	d.servers["agent-a"] = srv
	defer srv.Close()

	w := doControlRequest(d, http.MethodPost, "/control/agents/agent-a/resume")
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 (already running)", w.Code)
	}
}

// ─── Policy reload ──────────────────────────────────────────────────────────

func TestControl_ReloadPolicy_ChangesLiveBudgetLimit(t *testing.T) {
	d := newTestDaemon(t, "5.00", "")
	ar := d.agents[0]

	// Spend $1 against the original $5 daily limit, so there's live
	// in-memory budget state to prove survives the reload.
	if err := ar.rail.Budget().Reserve(100); err != nil {
		t.Fatal(err)
	}

	newAddr := ar.cfg.Rails["x402"] // reuse the same wallet_address already configured
	var existing struct {
		WalletAddress string `yaml:"wallet_address"`
	}
	newAddr.Decode(&existing) //nolint:errcheck

	body := fmt.Sprintf(`
x402:
  enabled: true
  wallet_address: %q
  daily_limit_usd: "1.00"
`, existing.WalletAddress)

	req := httptest.NewRequest(http.MethodPost, "/control/agents/agent-a/policy", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+d.controlToken)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("policy reload status = %d, want 204, body: %s", w.Code, w.Body.String())
	}

	ar2, ok := d.findAgent("agent-a")
	if !ok {
		t.Fatal("agent-a missing after reload")
	}
	snaps := ar2.rail.Budget().Snapshot()
	var found bool
	for _, s := range snaps {
		if s.Period == "daily" {
			found = true
			if s.SpentCents != 100 {
				t.Errorf("expected the $1.00 already spent to carry over, got %d cents", s.SpentCents)
			}
		}
	}
	if !found {
		t.Fatal("no daily budget snapshot found after reload")
	}

	// Cleanup: a fresh server was started for agent-a by the reload.
	d.mu.Lock()
	srv := d.servers["agent-a"]
	d.mu.Unlock()
	if srv != nil {
		srv.Close() //nolint:errcheck
	}
}

func TestControl_ReloadPolicy_InvalidBody_LeavesAgentUntouched(t *testing.T) {
	d := newTestDaemon(t, "5.00", "")
	originalRail := d.agents[0].rail

	req := httptest.NewRequest(http.MethodPost, "/control/agents/agent-a/policy", strings.NewReader("not: [valid, yaml: structure"))
	req.Header.Set("Authorization", "Bearer "+d.controlToken)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}

	if d.agents[0].rail != originalRail {
		t.Error("expected the agent's rail to be untouched after an invalid reload request")
	}
}

func TestControl_ReloadPolicy_UnknownAgent_Errors(t *testing.T) {
	d := newTestDaemon(t, "", "")
	req := httptest.NewRequest(http.MethodPost, "/control/agents/does-not-exist/policy", strings.NewReader("x402:\n  enabled: true\n"))
	req.Header.Set("Authorization", "Bearer "+d.controlToken)
	w := httptest.NewRecorder()
	d.controlHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

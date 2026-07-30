package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/config"
	aormcp "github.com/agentOnRails/agent-on-rails/internal/mcp"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// buildMCPServer wires up an internal/mcp.Server the same way cmd/aor/commands/mcp.go
// does — a client of the daemon fixture's own proxy port, never given a private key.
func buildMCPServer(t *testing.T, f *daemonFixture, clientTimeout time.Duration) *aormcp.Server {
	t.Helper()

	global, err := config.LoadGlobal(f.ConfigPath)
	if err != nil {
		t.Fatalf("load global config: %v", err)
	}
	agentCfg, err := config.LoadAgent(filepath.Join(f.AgentsDir, "e2e-agent.yaml"))
	if err != nil {
		t.Fatalf("load agent config: %v", err)
	}
	railCfg, err := x402.ParseRailConfig(agentCfg.Rails["x402"])
	if err != nil {
		t.Fatalf("parse rails.x402: %v", err)
	}
	policy, err := x402.BuildPolicy(global.Facilitators.X402, railCfg)
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	httpClient, err := aormcp.BuildProxyClient(f.ProxyAddr, nil, clientTimeout)
	if err != nil {
		t.Fatalf("build proxy client: %v", err)
	}

	logger, _ := zap.NewProduction(zap.WithCaller(false))
	return aormcp.New(agentCfg, railCfg, policy, httpClient, f.ProxyAddr, f.AuditDB, logger)
}

// callTool invokes a registered tool by name directly through the mcp-go
// server's own handler lookup — the same handler ServeStdio would dispatch
// to, without spinning up a real stdio transport.
func callTool(t *testing.T, srv *aormcp.Server, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	built := srv.Build()
	tool := built.GetTool(name)
	if tool == nil {
		t.Fatalf("tool %q not registered", name)
	}
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}}
	result, err := tool.Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("tool %q handler returned error: %v", name, err)
	}
	return result
}

func resultText(t *testing.T, result *mcplib.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// TestMCP_RequestPayment_ThroughRealDaemon confirms request_payment forwards
// through the daemon's own proxy (not an embedded engine) and that the
// resulting payment is recorded in the shared audit log exactly like a
// direct proxy client's would be.
func TestMCP_RequestPayment_ThroughRealDaemon(t *testing.T) {
	f := startDaemon(t, defaultOpts())
	srv := buildMCPServer(t, f, 10*time.Second)

	result := callTool(t, srv, "request_payment", map[string]any{
		"url":          f.Upstream.URL + "/paid",
		"task_context": "e2e-mcp-test",
	})
	if result.IsError {
		t.Fatalf("request_payment returned an error result: %s", resultText(t, result))
	}
	if !strings.Contains(resultText(t, result), "paid content") {
		t.Fatalf("expected upstream body in result, got: %s", resultText(t, result))
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(f.recentTxns(t)) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	txns := f.recentTxns(t)
	if len(txns) == 0 {
		t.Fatal("expected an audit record for the MCP-mediated payment, got none")
	}
	if txns[0].Status != "allowed" {
		t.Fatalf("expected audit status 'allowed', got %q", txns[0].Status)
	}
	if txns[0].TaskContext != "e2e-mcp-test" {
		t.Fatalf("expected task_context to survive the network hop via X-Sentinel-Task, got %q", txns[0].TaskContext)
	}
}

// TestMCP_RequestPayment_BlockedByBudget confirms budget enforcement (a
// single live tracker on the daemon side) applies to MCP-mediated payments
// exactly as it does to any other client of the proxy.
func TestMCP_RequestPayment_BlockedByBudget(t *testing.T) {
	upstream := startMockUpstream(t)
	// $0.01 daily limit — the mock upstream's single $0.01 charge exhausts it.
	f := startDaemonWithUpstream(t, daemonOptions{
		PerCallMaxUSD: "0.10",
		DailyLimitUSD: "0.01",
		EndpointMode:  "open",
		SkipPreVerify: true,
	}, upstream)
	srv := buildMCPServer(t, f, 10*time.Second)

	first := callTool(t, srv, "request_payment", map[string]any{"url": f.Upstream.URL + "/paid"})
	if first.IsError {
		t.Fatalf("first request_payment should succeed, got error: %s", resultText(t, first))
	}
	time.Sleep(150 * time.Millisecond)

	second := callTool(t, srv, "request_payment", map[string]any{"url": f.Upstream.URL + "/paid"})
	if !second.IsError {
		t.Fatalf("second request_payment should be blocked by the exhausted daily budget, got: %s", resultText(t, second))
	}
	if !strings.Contains(resultText(t, second), "blocked") {
		t.Fatalf("expected a 'blocked' error message, got: %s", resultText(t, second))
	}
}

// TestMCP_RequestPayment_DaemonUnreachable confirms request_payment fails
// with a clear, actionable error — not a raw dial error — when aor start
// isn't running for this agent.
func TestMCP_RequestPayment_DaemonUnreachable(t *testing.T) {
	f := startDaemon(t, defaultOpts())
	// Point the client at a port nothing is listening on instead of the
	// fixture's real daemon.
	deadPort := freePort(t)
	f.ProxyAddr = fmt.Sprintf("127.0.0.1:%d", deadPort)

	srv := buildMCPServer(t, f, 2*time.Second)
	result := callTool(t, srv, "request_payment", map[string]any{"url": f.Upstream.URL + "/paid"})
	if !result.IsError {
		t.Fatalf("expected an error result when the daemon is unreachable, got: %s", resultText(t, result))
	}
	text := resultText(t, result)
	if !strings.Contains(text, "aor start") {
		t.Fatalf("expected the error to point at `aor start`, got: %s", text)
	}
}

// TestMCP_GetBalance_WorksWithoutLiveTracker confirms get_balance is computed
// fresh from the shared audit log/config rather than a rail's in-memory
// tracker — it should reflect a payment made moments ago through the daemon.
func TestMCP_GetBalance_WorksWithoutLiveTracker(t *testing.T) {
	f := startDaemon(t, defaultOpts())
	srv := buildMCPServer(t, f, 10*time.Second)

	if r := callTool(t, srv, "request_payment", map[string]any{"url": f.Upstream.URL + "/paid"}); r.IsError {
		t.Fatalf("request_payment failed: %s", resultText(t, r))
	}
	time.Sleep(150 * time.Millisecond)

	result := callTool(t, srv, "get_balance", nil)
	if result.IsError {
		t.Fatalf("get_balance returned an error: %s", resultText(t, result))
	}
	text := resultText(t, result)
	if !strings.Contains(text, `"spent_usd": "$0.01"`) {
		t.Fatalf("expected daily spend to reflect the $0.01 payment, got: %s", text)
	}
}

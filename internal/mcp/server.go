// Package mcp implements an MCP (Model Context Protocol) server for AgentOnRails.
//
// It exposes four tools over stdio transport so any MCP-compatible agent
// (Claude Desktop, Cursor, GPT-4o with tools, etc.) can make intentional
// payments as tool calls:
//
//   - request_payment  — fetch a paid resource through the x402 rail
//   - get_balance      — wallet address + remaining budget per period
//   - get_spend_history — paginated transaction audit log
//   - get_policy       — active spend policy (no private keys)
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpsrv "github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// Server wraps the MCP toolset for a single AgentOnRails agent.
type Server struct {
	agentCfg *config.AgentConfig
	policy   *x402.X402Policy
	rail     *x402.X402Rail
	auditDB  *audit.SQLiteAuditLogger
	logger   *zap.Logger
}

// New creates an MCP Server. policy must already have PrivateKey populated.
func New(
	agentCfg *config.AgentConfig,
	policy *x402.X402Policy,
	rail *x402.X402Rail,
	auditDB *audit.SQLiteAuditLogger,
	logger *zap.Logger,
) *Server {
	return &Server{
		agentCfg: agentCfg,
		policy:   policy,
		rail:     rail,
		auditDB:  auditDB,
		logger:   logger,
	}
}

// Build constructs the mcp-go MCPServer with all tools registered.
func (s *Server) Build() *mcpsrv.MCPServer {
	srv := mcpsrv.NewMCPServer(
		"AgentOnRails",
		"1.0.0",
		mcpsrv.WithToolCapabilities(true),
		mcpsrv.WithRecovery(),
		mcpsrv.WithInstructions(fmt.Sprintf(
			"AgentOnRails payment proxy for agent %q. "+
				"Use request_payment to fetch paid resources via the x402 rail, "+
				"get_balance to check remaining budget, "+
				"get_spend_history to review past transactions, and "+
				"get_policy to inspect active spend controls.",
			s.agentCfg.AgentID,
		)),
	)

	srv.AddTool(s.requestPaymentTool(), s.handleRequestPayment)
	srv.AddTool(s.getBalanceTool(), s.handleGetBalance)
	srv.AddTool(s.getSpendHistoryTool(), s.handleGetSpendHistory)
	srv.AddTool(s.getPolicyTool(), s.handleGetPolicy)

	return srv
}

// ServeStdio starts the MCP server over stdin/stdout (blocking).
// ctx is accepted for interface uniformity but ServeStdio exits on SIGTERM/SIGINT.
func (s *Server) ServeStdio(_ context.Context) error {
	// Write mcp-go internal errors to stderr so they don't corrupt the stdio transport.
	errLog := log.New(os.Stderr, "[aor-mcp] ", 0)
	return mcpsrv.ServeStdio(s.Build(), mcpsrv.WithErrorLogger(errLog))
}

// ─── Tool: request_payment ────────────────────────────────────────────────────

func (s *Server) requestPaymentTool() mcplib.Tool {
	return mcplib.NewTool("request_payment",
		mcplib.WithDescription(
			"Make an HTTP request to a payment-enabled API endpoint. "+
				"AgentOnRails will automatically handle any x402 payment challenge, "+
				"enforce the active spend policy, and return the response body. "+
				"Use this tool to access any resource that may require a micropayment.",
		),
		mcplib.WithString("url",
			mcplib.Required(),
			mcplib.Description("Full URL of the resource (e.g. https://api.example.com/v1/data)"),
		),
		mcplib.WithString("method",
			mcplib.Description("HTTP method"),
			mcplib.Enum("GET", "POST", "PUT", "DELETE", "PATCH"),
			mcplib.DefaultString("GET"),
		),
		mcplib.WithString("body",
			mcplib.Description("Request body for POST/PUT/PATCH requests"),
		),
		mcplib.WithString("content_type",
			mcplib.Description("Content-Type header (defaults to application/json when body is set)"),
		),
		mcplib.WithString("task_context",
			mcplib.Description("Label recorded in the audit log to identify this task"),
		),
	)
}

func (s *Server) handleRequestPayment(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	rawURL, err := req.RequireString("url")
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}

	method := strings.ToUpper(req.GetString("method", "GET"))
	body := req.GetString("body", "")
	taskCtx := req.GetString("task_context", "mcp:request_payment")
	contentType := req.GetString("content_type", "")

	// Validate URL — must be absolute with a host.
	parsed, parseErr := url.Parse(rawURL)
	if parseErr != nil || parsed.Host == "" {
		return mcplib.NewToolResultError(
			fmt.Sprintf("invalid url %q: must be an absolute URL with a host (e.g. https://api.example.com/data)", rawURL),
		), nil
	}

	// Build synthetic HTTP request.
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	httpReq, buildErr := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if buildErr != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("build request: %s", buildErr)), nil
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	} else if body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Run through the x402 payment rail, capturing the response.
	w := httptest.NewRecorder()
	s.rail.ProxyRequest(ctx, w, httpReq, s.agentCfg.AgentID, taskCtx)
	result := w.Result()
	defer result.Body.Close()

	// Limit response body to 8 KiB to keep MCP messages reasonable.
	respBodyBytes, _ := io.ReadAll(io.LimitReader(result.Body, 8192))
	respBody := string(respBodyBytes)

	// Blocked by policy (403 Forbidden or 429 Too Many Requests from the rail).
	if result.StatusCode == http.StatusForbidden || result.StatusCode == http.StatusTooManyRequests {
		return mcplib.NewToolResultError(
			fmt.Sprintf("request blocked (HTTP %d): %s", result.StatusCode, strings.TrimSpace(respBody)),
		), nil
	}

	// Upstream error — surface as tool error so the agent can retry or re-plan.
	if result.StatusCode >= 500 {
		return mcplib.NewToolResultError(
			fmt.Sprintf("upstream error (HTTP %d): %s", result.StatusCode, strings.TrimSpace(respBody)),
		), nil
	}

	// Build output: response body + payment footer.
	var sb strings.Builder
	sb.WriteString(respBody)

	if pr := result.Header.Get("Payment-Response"); pr != "" {
		// A payment was made — include the settlement receipt.
		sb.WriteString(fmt.Sprintf("\n\n[AgentOnRails: payment settled — PAYMENT-RESPONSE: %s]", pr))
	}

	s.logger.Debug("mcp request_payment",
		zap.String("agent", s.agentCfg.AgentID),
		zap.String("url", rawURL),
		zap.Int("status", result.StatusCode),
		zap.String("task", taskCtx),
	)

	return mcplib.NewToolResultText(sb.String()), nil
}

// ─── Tool: get_balance ────────────────────────────────────────────────────────

func (s *Server) getBalanceTool() mcplib.Tool {
	return mcplib.NewTool("get_balance",
		mcplib.WithDescription(
			"Return the wallet address, preferred network, and remaining budget for each "+
				"configured spend window (daily, weekly, monthly).",
		),
	)
}

type balanceResult struct {
	AgentID        string         `json:"agent_id"`
	WalletAddress  string         `json:"wallet_address"`
	PreferredChain string         `json:"preferred_chain"`
	Budgets        []budgetPeriod `json:"budgets"`
}

type budgetPeriod struct {
	Period       string `json:"period"`
	LimitUSD     string `json:"limit_usd"`
	SpentUSD     string `json:"spent_usd"`
	RemainingUSD string `json:"remaining_usd"`
	ResetAt      string `json:"reset_at"`
}

func (s *Server) handleGetBalance(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	snapshots := s.rail.Budget().Snapshot()

	limitByCents := map[string]int64{
		"daily":   s.policy.DailyLimitCents,
		"weekly":  s.policy.WeeklyLimitCents,
		"monthly": s.policy.MonthlyLimitCents,
	}

	budgets := make([]budgetPeriod, 0, len(snapshots))
	for _, snap := range snapshots {
		limitCents := limitByCents[snap.Period]
		spentUSD := fmt.Sprintf("$%.2f", float64(snap.SpentCents)/100)

		var limitStr, remainStr string
		if limitCents == 0 {
			limitStr = "unlimited"
			remainStr = "unlimited"
		} else {
			limitStr = fmt.Sprintf("$%.2f", float64(limitCents)/100)
			rem := limitCents - snap.SpentCents
			if rem < 0 {
				rem = 0
			}
			remainStr = fmt.Sprintf("$%.2f", float64(rem)/100)
		}

		budgets = append(budgets, budgetPeriod{
			Period:       snap.Period,
			LimitUSD:     limitStr,
			SpentUSD:     spentUSD,
			RemainingUSD: remainStr,
			ResetAt:      snap.ResetAt.Format(time.RFC3339),
		})
	}

	out := balanceResult{
		AgentID:        s.agentCfg.AgentID,
		WalletAddress:  s.policy.WalletAddress,
		PreferredChain: s.policy.PreferredChain,
		Budgets:        budgets,
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	return mcplib.NewToolResultText(string(b)), nil
}

// ─── Tool: get_spend_history ──────────────────────────────────────────────────

func (s *Server) getSpendHistoryTool() mcplib.Tool {
	return mcplib.NewTool("get_spend_history",
		mcplib.WithDescription(
			"Query the payment transaction audit log. Returns transactions with endpoint, "+
				"amount paid, status, and blockchain transaction hash.",
		),
		mcplib.WithString("since",
			mcplib.Description("How far back to look: e.g. '1h', '24h', '7d', '30d' (default '24h')"),
			mcplib.DefaultString("24h"),
		),
		mcplib.WithNumber("limit",
			mcplib.Description("Maximum transactions to return (1–100, default 20)"),
			mcplib.DefaultNumber(20),
			mcplib.Min(1),
			mcplib.Max(100),
		),
		mcplib.WithString("status",
			mcplib.Description("Filter by transaction status (omit for all)"),
			mcplib.Enum("allowed", "blocked", "failed"),
		),
	)
}

type txRow struct {
	ID          string  `json:"id"`
	Timestamp   string  `json:"timestamp"`
	Endpoint    string  `json:"endpoint"`
	Method      string  `json:"method"`
	AmountUSD   string  `json:"amount_usd"`
	Network     string  `json:"network,omitempty"`
	Status      string  `json:"status"`
	BlockReason string  `json:"block_reason,omitempty"`
	TxHash      string  `json:"tx_hash,omitempty"`
	TaskContext string  `json:"task_context,omitempty"`
	LatencyMS   int64   `json:"latency_ms"`
}

func (s *Server) handleGetSpendHistory(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sinceStr := req.GetString("since", "24h")
	limit := int(req.GetFloat("limit", 20))
	statusFilter := req.GetString("status", "")

	since, err := parseSince(sinceStr)
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	txns, err := s.auditDB.QueryTransactions(s.agentCfg.AgentID, since, limit)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("query failed: %s", err)), nil
	}

	// Post-filter by status if requested.
	if statusFilter != "" {
		filtered := txns[:0]
		for _, t := range txns {
			if t.Status == statusFilter {
				filtered = append(filtered, t)
			}
		}
		txns = filtered
	}

	rows := make([]txRow, len(txns))
	for i, t := range txns {
		amtStr := "free"
		if t.AmountUSD > 0 {
			amtStr = fmt.Sprintf("$%.4f", t.AmountUSD)
		}
		rows[i] = txRow{
			ID:          t.ID,
			Timestamp:   t.Timestamp.Format(time.RFC3339),
			Endpoint:    t.Endpoint,
			Method:      t.Method,
			AmountUSD:   amtStr,
			Network:     t.Network,
			Status:      t.Status,
			BlockReason: t.BlockReason,
			TxHash:      t.TxHash,
			TaskContext: t.TaskContext,
			LatencyMS:   t.LatencyMS,
		}
	}

	b, _ := json.MarshalIndent(rows, "", "  ")
	return mcplib.NewToolResultText(string(b)), nil
}

// ─── Tool: get_policy ─────────────────────────────────────────────────────────

func (s *Server) getPolicyTool() mcplib.Tool {
	return mcplib.NewTool("get_policy",
		mcplib.WithDescription(
			"Return the active spend policy for this agent: spend limits, endpoint controls, "+
				"velocity limits, and facilitator configuration. Private keys are never included.",
		),
	)
}

type policyResult struct {
	AgentID         string         `json:"agent_id"`
	ProxyPort       int            `json:"proxy_port"`
	WalletAddress   string         `json:"wallet_address"`
	PreferredChain  string         `json:"preferred_chain"`
	FacilitatorURL  string         `json:"facilitator_url"`
	SpendLimits     spendLimits    `json:"spend_limits"`
	EndpointPolicy  endpointPolicy `json:"endpoint_policy"`
	Velocity        velocityPolicy `json:"velocity"`
	AllowedNetworks []string       `json:"allowed_networks"`
	SkipPreVerify   bool           `json:"skip_pre_verify"`
}

type spendLimits struct {
	PerCallMaxUSD           string `json:"per_call_max_usd"`
	DailyLimitUSD           string `json:"daily_limit_usd"`
	WeeklyLimitUSD          string `json:"weekly_limit_usd"`
	MonthlyLimitUSD         string `json:"monthly_limit_usd"`
	RequireApprovalAboveUSD string `json:"require_approval_above_usd"`
}

type endpointPolicy struct {
	Mode         string   `json:"mode"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	BlockedHosts []string `json:"blocked_hosts,omitempty"`
}

type velocityPolicy struct {
	MaxPerMinute    int `json:"max_per_minute"`
	MaxPerHour      int `json:"max_per_hour"`
	CooldownSeconds int `json:"cooldown_seconds"`
}

func (s *Server) handleGetPolicy(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	p := s.policy
	rc := s.agentCfg.Rails.X402

	maxPerMin := config.DefaultMaxPerMinute
	maxPerHour := config.DefaultMaxPerHour
	cooldown := config.DefaultCooldownSeconds
	if rc != nil {
		if rc.Velocity.MaxPerMinute > 0 {
			maxPerMin = rc.Velocity.MaxPerMinute
		}
		if rc.Velocity.MaxPerHour > 0 {
			maxPerHour = rc.Velocity.MaxPerHour
		}
		if rc.Velocity.CooldownSeconds > 0 {
			cooldown = rc.Velocity.CooldownSeconds
		}
	}

	out := policyResult{
		AgentID:        s.agentCfg.AgentID,
		ProxyPort:      s.agentCfg.ProxyPort,
		WalletAddress:  p.WalletAddress,
		PreferredChain: p.PreferredChain,
		FacilitatorURL: p.FacilitatorURL,
		SpendLimits: spendLimits{
			PerCallMaxUSD:           centsToUSD(p.PerCallMaxCents),
			DailyLimitUSD:           centsToUSD(p.DailyLimitCents),
			WeeklyLimitUSD:          centsToUSD(p.WeeklyLimitCents),
			MonthlyLimitUSD:         centsToUSD(p.MonthlyLimitCents),
			RequireApprovalAboveUSD: centsToUSDOrNone(p.RequireApprovalAboveCents),
		},
		EndpointPolicy: endpointPolicy{
			Mode:         p.EndpointMode,
			AllowedHosts: p.AllowedHosts,
			BlockedHosts: p.BlockedHosts,
		},
		Velocity: velocityPolicy{
			MaxPerMinute:    maxPerMin,
			MaxPerHour:      maxPerHour,
			CooldownSeconds: cooldown,
		},
		AllowedNetworks: p.AllowedNetworks,
		SkipPreVerify:   p.SkipPreVerify,
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	return mcplib.NewToolResultText(string(b)), nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// parseSince converts a human-friendly duration string to a time.Time.
// Supports Go duration strings (e.g. "1h", "30m") plus "Nd" for N days.
func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Now().Add(-24 * time.Hour), nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days < 1 {
			return time.Time{}, fmt.Errorf("invalid since %q: use e.g. '7d' for 7 days", s)
		}
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid since %q: use a Go duration (e.g. '24h') or days suffix (e.g. '7d')", s)
	}
	return time.Now().Add(-d), nil
}

func centsToUSD(cents int64) string {
	if cents == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("$%.2f", float64(cents)/100)
}

func centsToUSDOrNone(cents int64) string {
	if cents == 0 {
		return "none"
	}
	return fmt.Sprintf("$%.2f", float64(cents)/100)
}

// AgentConfigPath returns the expected YAML path for agentID under dir.
// Used by the mcp command to locate an agent config without scanning the directory.
func AgentConfigPath(agentsDir, agentID string) string {
	return filepath.Join(agentsDir, agentID+".yaml")
}

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
//
// request_payment is a client of the daemon's own proxy for this agent — it
// does not embed its own copy of the rail or ever touch the wallet key. That
// means exactly one process (the daemon started by `aor start`) ever holds
// the decrypted key and runs the one live budget tracker; this server simply
// forwards the request the same way any HTTP client behind the proxy would,
// and cannot function at all unless that daemon is running for this agent.
// get_balance/get_spend_history/get_policy don't depend on the daemon — they
// read the shared audit log and config directly, so they still work even
// when it's down.
//
// Policy (budget/velocity/endpoint) is only enforced for requests that
// actually go through request_payment. This server has no way to see or
// control traffic an agent sends via a different tool (shell, browser,
// its own HTTP client) — that's a separate limitation the daemon's proxy
// can't fully close either, short of network-level egress lockdown.
package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpsrv "github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/rail"
)

// Server wraps the MCP toolset for a single AgentOnRails agent.
type Server struct {
	agentCfg   *config.AgentConfig
	railCfg    *x402.X402RailConfig
	policy     *x402.X402Policy
	auditDB    *audit.SQLiteAuditLogger
	logger     *zap.Logger
	httpClient *http.Client // client of the daemon's proxy for this agent
	proxyAddr  string       // e.g. "127.0.0.1:8402" — for error messages only
}

// New creates an MCP Server. policy is used for read-only display only
// (get_balance/get_policy) — it must NOT have PrivateKey populated; this
// server never signs anything itself. httpClient must already be configured
// to route requests through the daemon's proxy for this agent (Transport.Proxy
// set to proxyAddr, and TLSClientConfig.RootCAs trusting the daemon's
// interception CA if https_intercept is enabled) — see BuildProxyClient.
func New(
	agentCfg *config.AgentConfig,
	railCfg *x402.X402RailConfig,
	policy *x402.X402Policy,
	httpClient *http.Client,
	proxyAddr string,
	auditDB *audit.SQLiteAuditLogger,
	logger *zap.Logger,
) *Server {
	return &Server{
		agentCfg:   agentCfg,
		railCfg:    railCfg,
		policy:     policy,
		auditDB:    auditDB,
		logger:     logger,
		httpClient: httpClient,
		proxyAddr:  proxyAddr,
	}
}

// BuildProxyClient builds an *http.Client that routes requests through the
// daemon's forward-proxy port for one agent — the same way any other HTTP
// client behind the proxy (HTTP_PROXY/HTTPS_PROXY) would. If caCertPEM is
// non-nil, it's added to the client's own trust pool so HTTPS targets work
// when the daemon has https_intercept enabled, with no trust-store change
// required on the caller's end — this client is the only thing that needs
// to trust it.
func BuildProxyClient(proxyAddr string, caCertPEM []byte, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("parse proxy addr %q: %w", proxyAddr, err)
	}

	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	if caCertPEM != nil {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("interception CA cert is not valid PEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &http.Client{Transport: transport, Timeout: timeout}, nil
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
				"get_policy to inspect active spend controls. "+
				"IMPORTANT: these tools are the only path that enforces spend limits, "+
				"velocity limits, and endpoint policy. Any request you make with a "+
				"different tool (shell, browser, direct HTTP) bypasses this policy "+
				"entirely and is not budgeted, limited, or audited. Always route "+
				"requests to URLs that may require payment through request_payment "+
				"instead of fetching them yourself. request_payment requires the "+
				"AgentOnRails proxy daemon (`aor start`) to already be running for "+
				"this agent — if it isn't, the call fails with a clear error rather "+
				"than silently skipping policy.",
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
				"Use this tool to access any resource that may require a micropayment. "+
				"Requires the AgentOnRails proxy daemon (aor start) to be running for "+
				"this agent — this tool is a client of that daemon, not a separate engine.",
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
	// Read by ReverseProxyHandler.ServeHTTP on the daemon side (rail.go's
	// headerSentinelTask) so the task label survives the network hop instead
	// of being a same-process function argument.
	httpReq.Header.Set("X-Sentinel-Task", taskCtx)

	// Send through the daemon's proxy for this agent — the same path any
	// other HTTP client behind the proxy uses. A transport-level failure here
	// almost always means the daemon isn't running for this agent.
	result, doErr := s.httpClient.Do(httpReq)
	if doErr != nil {
		return mcplib.NewToolResultError(fmt.Sprintf(
			"could not reach the AgentOnRails proxy for agent %q at %s (%s) — "+
				"is `aor start` running for this agent? request_payment is a client "+
				"of that daemon, not a standalone payment engine.",
			s.agentCfg.AgentID, s.proxyAddr, doErr,
		)), nil
	}
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

// budgetWindow describes one spend period's boundaries — computed fresh per
// call rather than read from a live tracker, so this works whether or not
// the daemon is currently running.
type budgetWindowDef struct {
	period     string
	limitCents int64
	since      time.Time
	resetAt    time.Time
}

func (s *Server) handleGetBalance(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	now := time.Now().UTC()
	windows := []budgetWindowDef{
		{period: "daily", limitCents: s.policy.DailyLimitCents, since: rail.DayStart(now), resetAt: rail.NextDayStart(now)},
		{period: "weekly", limitCents: s.policy.WeeklyLimitCents, since: rail.CurrentWeekStart(now), resetAt: rail.NextWeekStart(now)},
		{period: "monthly", limitCents: s.policy.MonthlyLimitCents, since: rail.CurrentMonthStart(now), resetAt: rail.NextMonthStart(now)},
	}

	budgets := make([]budgetPeriod, 0, len(windows))
	for _, w := range windows {
		spentUSD, err := s.auditDB.SpendSummary(s.agentCfg.AgentID, w.since)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("query spend for %s: %s", w.period, err)), nil
		}
		spentCents := int64(spentUSD * 100)

		var limitStr, remainStr string
		if w.limitCents == 0 {
			limitStr = "unlimited"
			remainStr = "unlimited"
		} else {
			limitStr = fmt.Sprintf("$%.2f", float64(w.limitCents)/100)
			rem := w.limitCents - spentCents
			if rem < 0 {
				rem = 0
			}
			remainStr = fmt.Sprintf("$%.2f", float64(rem)/100)
		}

		budgets = append(budgets, budgetPeriod{
			Period:       w.period,
			LimitUSD:     limitStr,
			SpentUSD:     fmt.Sprintf("$%.2f", spentUSD),
			RemainingUSD: remainStr,
			ResetAt:      w.resetAt.Format(time.RFC3339),
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
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	AmountUSD   string `json:"amount_usd"`
	Network     string `json:"network,omitempty"`
	Status      string `json:"status"`
	BlockReason string `json:"block_reason,omitempty"`
	TxHash      string `json:"tx_hash,omitempty"`
	TaskContext string `json:"task_context,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
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
	rc := s.railCfg

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

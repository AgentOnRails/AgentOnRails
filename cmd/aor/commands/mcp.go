package commands

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
	aormcp "github.com/agentOnRails/agent-on-rails/internal/mcp"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

var mcpAgentID string

// mcpClientTimeout must comfortably exceed the longest a request can
// legitimately block — a payment held for human approval, up to the agent's
// approval_timeout_sec (default 300s per README). This is the client-side
// bound on that same wait, not a new limit of its own.
const mcpClientTimeout = 6 * time.Minute

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start an MCP server for an agent (stdio transport)",
	Long: `Start a Model Context Protocol server for a single agent over stdin/stdout.

The server exposes four tools that any MCP-compatible AI agent can call:
  request_payment   — fetch a paid resource through the x402 rail
  get_balance       — wallet address + remaining budget per spend window
  get_spend_history — query the transaction audit log
  get_policy        — inspect active spend controls (no private keys)

Add to Claude Desktop's MCP server config (~/.claude/claude_desktop_config.json):

  {
    "mcpServers": {
      "aor-my-agent": {
        "command": "aor",
        "args": ["mcp", "--agent", "my-agent"]
      }
    }
  }

IMPORTANT: request_payment is a client of the daemon's own proxy for this
agent, not a separate payment engine — it does not decrypt the wallet key
or track budget itself. "aor start" must already be running for this agent
or every request_payment call will fail with a clear connection error. If
the daemon's aor.yaml has daemon.https_intercept: false (the default),
payments on https:// endpoints won't be seen or handled through this tool
either — a warning is printed at startup, but it still starts, so plain
HTTP test setups (scripts/testserver) keep working unmodified.

get_balance/get_spend_history/get_policy read the shared audit log and
config directly — they work even when the daemon isn't running.

This is not a substitute for running the proxy: an agent with any other way
to reach the network (a shell tool, a browser tool, its own HTTP client)
can bypass these tools entirely for a given request, and nothing here can
see or stop that — closing that gap needs network-level egress lockdown,
not this command.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpAgentID == "" {
			return fmt.Errorf("--agent is required (e.g. aor mcp --agent my-agent)")
		}

		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		agentPath := aormcp.AgentConfigPath(agentsDir, mcpAgentID)
		agentCfg, err := config.LoadAgent(agentPath)
		if err != nil {
			return fmt.Errorf("load agent %q: %w\n(run `aor agents list` to see configured agents)", mcpAgentID, err)
		}

		rawCfg, ok := agentCfg.Rails["x402"]
		if !ok {
			return fmt.Errorf("agent %q does not have rails.x402 configured", mcpAgentID)
		}
		railCfg, err := x402.ParseRailConfig(rawCfg)
		if err != nil {
			return fmt.Errorf("parse rails.x402: %w", err)
		}
		if !railCfg.Enabled {
			return fmt.Errorf("agent %q does not have the x402 rail enabled — set rails.x402.enabled: true", mcpAgentID)
		}

		// Read-only: this policy is never given a PrivateKey. Only the daemon
		// this server forwards to ever decrypts the wallet key.
		policy, err := x402.BuildPolicy(global.Facilitators.X402, railCfg)
		if err != nil {
			return fmt.Errorf("build policy: %w", err)
		}

		db, err := audit.NewSQLiteAuditLogger(config.ExpandHomePath(global.Daemon.AuditDB))
		if err != nil {
			return fmt.Errorf("open audit db: %w", err)
		}
		defer db.Close()

		// MCP writes to stdio — use warn-level logging to stderr only.
		logger, err := buildLogger("warn")
		if err != nil {
			return err
		}
		defer logger.Sync() //nolint:errcheck

		proxyAddr := net.JoinHostPort(global.Daemon.ListenAddr, strconv.Itoa(agentCfg.ProxyPort))

		var caCertPEM []byte
		if global.Daemon.HTTPSIntercept {
			pem, caErr := x402.LoadCACertPEM(config.ExpandHomePath(global.Daemon.CADir))
			if caErr != nil {
				logger.Warn("https_intercept is enabled but the interception CA isn't on disk yet — "+
					"HTTPS-paid endpoints won't be handled through request_payment until `aor start` "+
					"has run at least once to generate it",
					zap.Error(caErr))
			} else {
				caCertPEM = pem
			}
		} else {
			logger.Warn("daemon.https_intercept is false — request_payment will not see or handle " +
				"payments on https:// endpoints (only plain HTTP). Set daemon.https_intercept: true " +
				"in aor.yaml and restart `aor start` if you need HTTPS support.")
		}

		httpClient, err := aormcp.BuildProxyClient(proxyAddr, caCertPEM, mcpClientTimeout)
		if err != nil {
			return fmt.Errorf("build proxy client: %w", err)
		}

		// Loud, not just documented in --help: MCP mode's policy enforcement
		// only covers calls the agent actually makes through request_payment
		// — any other way the agent has to reach the network (a shell tool,
		// a browser tool, its own HTTP client) bypasses it entirely, unlike
		// the transparent HTTP(S) proxy ("aor start"), which sees everything
		// regardless of how the agent was told to call out. Printed every
		// startup so this can't be missed the way a --help paragraph can.
		logger.Warn("MCP mode only enforces policy on calls made through this server's tools " +
			"(request_payment, etc.) — any other network path the agent has (shell, browser, its " +
			"own HTTP client) bypasses it entirely. The transparent proxy (`aor start`) covers all " +
			"outbound traffic regardless of how the agent makes it; this does not.")

		srv := aormcp.New(agentCfg, railCfg, policy, httpClient, proxyAddr, db, logger)
		return srv.ServeStdio(context.Background())
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpAgentID, "agent", "", "Agent ID to serve (required) — matches the filename in ~/.aor/agents/")
	_ = mcpCmd.MarkFlagRequired("agent")
}

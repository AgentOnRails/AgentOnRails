package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
	aormcp "github.com/agentOnRails/agent-on-rails/internal/mcp"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/internal/vault"
)

var (
	mcpAgentID    string
	mcpPassphrase string
)

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
        "args": ["mcp", "--agent", "my-agent"],
        "env": { "AOR_PASSPHRASE": "your-passphrase" }
      }
    }
  }

The wallet passphrase can be supplied via --passphrase or AOR_PASSPHRASE.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpPassphrase == "" {
			mcpPassphrase = os.Getenv("AOR_PASSPHRASE")
		}
		if mcpPassphrase == "" {
			return fmt.Errorf("wallet passphrase required: use --passphrase or set AOR_PASSPHRASE")
		}
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

		if agentCfg.Rails.X402 == nil || !agentCfg.Rails.X402.Enabled {
			return fmt.Errorf("agent %q does not have the x402 rail enabled — set rails.x402.enabled: true", mcpAgentID)
		}

		policy, err := config.BuildX402Policy(global, agentCfg)
		if err != nil {
			return fmt.Errorf("build policy: %w", err)
		}

		v, err := vault.New(config.ExpandHomePath(global.Daemon.VaultDir))
		if err != nil {
			return fmt.Errorf("open vault: %w", err)
		}

		key, err := v.LoadKey(mcpAgentID, mcpPassphrase)
		if err != nil {
			return fmt.Errorf("load wallet for %q: %w\n(run `aor credentials set-wallet %s` to store the key)", mcpAgentID, err, mcpAgentID)
		}

		derivedAddr := ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
		if !strings.EqualFold(derivedAddr, policy.WalletAddress) {
			return fmt.Errorf(
				"wallet mismatch for agent %q: loaded key maps to %s but config wallet_address is %s\n"+
					"Update wallet_address in the agent config or re-run `aor credentials set-wallet %s`",
				mcpAgentID, derivedAddr, policy.WalletAddress, mcpAgentID,
			)
		}
		policy.PrivateKey = key

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

		rail, err := x402.NewX402Rail(policy, db, logger)
		if err != nil {
			return fmt.Errorf("init x402 rail: %w", err)
		}

		// Rehydrate in-memory budget from the persisted DB state.
		if states, hydErr := db.RehydrateBudget(mcpAgentID); hydErr != nil {
			logger.Warn("budget rehydration failed — starting from zero", zap.Error(hydErr))
		} else {
			for _, s := range states {
				rail.Budget().Seed(s.Period, s.SpentCents)
			}
		}

		srv := aormcp.New(agentCfg, policy, rail, db, logger)
		return srv.ServeStdio(context.Background())
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpAgentID, "agent", "", "Agent ID to serve (required) — matches the filename in ~/.aor/agents/")
	mcpCmd.Flags().StringVar(&mcpPassphrase, "passphrase", "", "Wallet decryption passphrase (prefer AOR_PASSPHRASE env var)")
	_ = mcpCmd.MarkFlagRequired("agent")
}

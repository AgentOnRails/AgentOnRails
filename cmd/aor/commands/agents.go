package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/internal/config"
)

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage configured agents",
}

var agentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		agents, err := config.LoadAgents(agentsDir)
		if err != nil {
			return fmt.Errorf("load agents: %w", err)
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT ID\tPORT\tX402\tCHAIN\tENDPOINT MODE")
		for _, a := range agents {
			x402Enabled := "disabled"
			chain := "-"
			mode := "-"
			if a.Rails.X402 != nil && a.Rails.X402.Enabled {
				x402Enabled = "enabled"
				chain = a.Rails.X402.PreferredChain
				mode = a.Rails.X402.EndpointMode
				if mode == "" {
					mode = "open"
				}
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n",
				a.AgentID, a.ProxyPort, x402Enabled, chain, mode)
		}
		return tw.Flush()
	},
}

// ─── agents create ────────────────────────────────────────────────────────────

type chainOption struct {
	label   string
	caip2   string
	testnet bool
}

var chainOptions = []chainOption{
	{"Base mainnet     ", "eip155:8453", false},
	{"Ethereum mainnet ", "eip155:1", false},
	{"Optimism         ", "eip155:10", false},
	{"Arbitrum One     ", "eip155:42161", false},
	{"Polygon          ", "eip155:137", false},
	{"Base Sepolia     ", "eip155:84532", true},
}

var agentsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Interactive wizard to create a new agent config",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		in := bufio.NewReader(os.Stdin)

		fmt.Println("Creating a new agent configuration.")
		fmt.Println()

		// Agent ID
		agentID := prompt(in, "Agent ID", "my-agent")
		if agentID == "" {
			return fmt.Errorf("agent ID cannot be empty")
		}

		// Proxy port
		portStr := prompt(in, "Proxy port", "8402")
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port %q", portStr)
		}

		// Wallet address
		walletAddr := prompt(in, "Wallet address (0x...)", "")
		if walletAddr == "" {
			return fmt.Errorf("wallet address is required")
		}

		// Chain selection
		fmt.Println()
		for i, c := range chainOptions {
			tag := ""
			if c.testnet {
				tag = "  ← testnet"
			}
			if i == 0 {
				tag += "  ← recommended"
			}
			fmt.Printf("  %d) %s (%s)%s\n", i+1, c.label, c.caip2, tag)
		}
		fmt.Println()
		chainStr := prompt(in, "Preferred chain", "1")
		chainIdx, err := strconv.Atoi(chainStr)
		if err != nil || chainIdx < 1 || chainIdx > len(chainOptions) {
			return fmt.Errorf("invalid choice %q", chainStr)
		}
		chain := chainOptions[chainIdx-1]

		fmt.Println()

		// Spend limits
		dailyLimit  := prompt(in, "Daily spend limit (USD, 0 = unlimited)", "5.00")
		perCallMax  := prompt(in, "Per-call maximum  (USD, 0 = unlimited)", "0.10")

		// Endpoint mode
		fmt.Println()
		fmt.Println("  Endpoint mode:")
		fmt.Println("    open       — pay any host")
		fmt.Println("    allowlist  — only pay hosts you explicitly list")
		fmt.Println("    blocklist  — pay any host except those you block")
		fmt.Println()
		endpointMode := prompt(in, "Endpoint mode", "open")
		if endpointMode != "open" && endpointMode != "allowlist" && endpointMode != "blocklist" {
			return fmt.Errorf("invalid endpoint mode %q", endpointMode)
		}

		// Determine output path
		destDir := config.ExpandHomePath(agentsDir)
		if err := os.MkdirAll(destDir, 0700); err != nil {
			return fmt.Errorf("create agents dir: %w", err)
		}
		outPath := filepath.Join(destDir, agentID+".yaml")

		if _, err := os.Stat(outPath); err == nil {
			overwrite := prompt(in, fmt.Sprintf("%s already exists. Overwrite?", outPath), "n")
			if !strings.HasPrefix(strings.ToLower(overwrite), "y") {
				fmt.Println("Aborted.")
				return nil
			}
		}

		yaml := buildAgentYAML(agentID, port, walletAddr, chain.caip2, dailyLimit, perCallMax, endpointMode)
		if err := os.WriteFile(outPath, []byte(yaml), 0600); err != nil {
			return fmt.Errorf("write agent config: %w", err)
		}

		fmt.Printf("\nWritten %s\n", outPath)
		fmt.Println()

		// Offer to store wallet key now
		storeNow := prompt(in, "Store encrypted wallet key now?", "Y")
		if strings.HasPrefix(strings.ToLower(storeNow), "y") {
			// Delegate to the existing set-wallet logic by running it inline.
			if err := setWalletCmd.RunE(setWalletCmd, []string{agentID}); err != nil {
				fmt.Fprintf(os.Stderr, "\nWarning: wallet setup failed: %v\n", err)
				fmt.Fprintf(os.Stderr, "Run `aor credentials set-wallet %s` to retry.\n", agentID)
			}
		} else {
			fmt.Printf("\nRun this when ready:\n  aor credentials set-wallet %s\n", agentID)
		}

		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  export AOR_PASSPHRASE=\"your vault passphrase\"")
		fmt.Println("  aor start")
		fmt.Printf("  export HTTP_PROXY=http://localhost:%d\n", port)
		fmt.Println("  aor logs tail")
		return nil
	},
}

// prompt prints a question with a default value and reads one line of input.
func prompt(in *bufio.Reader, question, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", question, defaultVal)
	} else {
		fmt.Printf("  %s: ", question)
	}
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func buildAgentYAML(agentID string, port int, walletAddr, chain, daily, perCall, endpointMode string) string {
	zeroIfEmpty := func(s string) string {
		if s == "" || s == "0" {
			return ""
		}
		return s
	}
	dailyLine   := ""
	perCallLine := ""
	if v := zeroIfEmpty(daily); v != "" {
		dailyLine = fmt.Sprintf("    daily_limit_usd:  %q\n", v)
	}
	if v := zeroIfEmpty(perCall); v != "" {
		perCallLine = fmt.Sprintf("    per_call_max_usd: %q\n", v)
	}

	return fmt.Sprintf(`# AgentOnRails agent configuration
# Generated by: aor agents create
# Edit this file to adjust limits, allowed hosts, and velocity settings.

agent_id: %q
proxy_port: %d

rails:
  x402:
    enabled: true
    wallet_address: %q
    preferred_chain: %q
%s%s    endpoint_mode: %q
    allowed_hosts:  []
    blocked_hosts:  []
    allowed_networks:
      - %q
    velocity:
      max_per_minute: 30
      max_per_hour:   200
      cooldown_seconds: 60
    skip_pre_verify: false
`,
		agentID, port, walletAddr, chain,
		dailyLine, perCallLine,
		endpointMode, chain,
	)
}

func init() {
	agentsCmd.AddCommand(agentsListCmd)
	agentsCmd.AddCommand(agentsCreateCmd)
}

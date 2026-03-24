// Package commands implements the AgentOnRails CLI using Cobra.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	globalConfigPath string
	agentsDir        string
)

// Root is the top-level cobra command.
var Root = &cobra.Command{
	Use:   "aor",
	Short: "AgentOnRails — per-agent payment guardrail proxy",
	Long: `AgentOnRails is a local-first proxy daemon that sits between AI agents
and payment-enabled APIs, enforcing per-agent spend policies via the x402 protocol.

Documentation: https://github.com/agentOnRails/agent-on-rails`,
	SilenceUsage: true,
}

func init() {
	Root.PersistentFlags().StringVar(&globalConfigPath, "config", "~/.aor/aor.yaml",
		"Path to global aor.yaml config file")
	Root.PersistentFlags().StringVar(&agentsDir, "agents-dir", "~/.aor/agents",
		"Directory containing per-agent YAML config files")

	Root.AddCommand(startCmd)
	Root.AddCommand(stopCmd)
	Root.AddCommand(agentsCmd)
	Root.AddCommand(spendCmd)
	Root.AddCommand(auditCmd)
	Root.AddCommand(credentialsCmd)
}

// Execute runs the root command. Called from main().
func Execute() {
	if err := Root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

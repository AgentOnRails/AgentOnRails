package commands

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/daemon"
)

var passphrase string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the AgentOnRails proxy daemon",
	Long: `Start the proxy daemon. One HTTP proxy server is started per configured
agent, listening on its configured proxy_port. All agent traffic is routed
through the x402 payment rail with policy enforcement.

The wallet passphrase can be supplied via the --passphrase flag or the
AOR_PASSPHRASE environment variable.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if passphrase == "" {
			passphrase = os.Getenv("AOR_PASSPHRASE")
		}
		if passphrase == "" {
			return fmt.Errorf("wallet passphrase required: use --passphrase or set AOR_PASSPHRASE")
		}

		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		agents, err := config.LoadAgents(agentsDir)
		if err != nil {
			return fmt.Errorf("load agents: %w", err)
		}
		if len(agents) == 0 {
			return fmt.Errorf("no agent configs found in %s", agentsDir)
		}

		logger, err := buildLogger(global.Daemon.LogLevel)
		if err != nil {
			return err
		}
		defer logger.Sync()

		d, err := daemon.New(global, agents, passphrase, logger)
		if err != nil {
			return fmt.Errorf("init daemon: %w", err)
		}

		logger.Info("AgentOnRails daemon starting",
			zap.Int("agents", len(agents)),
		)

		return d.Start(context.Background())
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running AgentOnRails daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		pid, err := daemon.ReadPID(global.Daemon.PIDFile)
		if err != nil {
			return err
		}

		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find process %d: %w", pid, err)
		}

		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
		}

		// Poll for the PID file to disappear (daemon removes it on clean exit).
		fmt.Printf("Sent SIGTERM to daemon (PID %d); waiting for shutdown", pid)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			if _, err := daemon.ReadPID(global.Daemon.PIDFile); err != nil {
				fmt.Println(" stopped.")
				return nil
			}
			fmt.Print(".")
		}
		fmt.Println("\nWarning: daemon did not stop within 15 s — it may still be shutting down.")
		return nil
	},
}

func init() {
	startCmd.Flags().StringVar(&passphrase, "passphrase", "", "Wallet decryption passphrase (prefer AOR_PASSPHRASE env var)")
}

func buildLogger(level string) (*zap.Logger, error) {
	var cfg zap.Config
	switch level {
	case "debug":
		cfg = zap.NewDevelopmentConfig()
	default:
		cfg = zap.NewProductionConfig()
	}
	return cfg.Build()
}

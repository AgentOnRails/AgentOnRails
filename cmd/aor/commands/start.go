package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/daemon"
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
	Long: `Stop the running daemon gracefully.

Tries the control API's /control/shutdown first (works on every OS, since
it just makes an HTTP request) and falls back to sending the process a
SIGTERM if the control API is disabled or unreachable. That fallback only
works on Unix — Windows does not support sending SIGTERM to another
process, so on Windows the control API (on by default; see
daemon.control_disabled) is the only way "aor stop" can shut the daemon
down without killing it by hand.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		pid, err := daemon.ReadPID(global.Daemon.PIDFile)
		if err != nil {
			return err
		}

		if !global.Daemon.ControlDisabled {
			if shutErr := requestShutdownViaControlAPI(global); shutErr == nil {
				fmt.Printf("Requested shutdown via control API (PID %d); waiting for shutdown", pid)
				return waitForDaemonStop(global.Daemon.PIDFile)
			} else {
				fmt.Fprintf(os.Stderr, "control API shutdown request failed (%v); falling back to a process signal\n", shutErr)
			}
		}

		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find process %d: %w", pid, err)
		}

		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("send SIGTERM to %d: %w (on Windows this is expected — SIGTERM isn't supported; enable the control API (daemon.control_disabled: false, the default) so this fallback isn't needed)", pid, err)
		}

		fmt.Printf("Sent SIGTERM to daemon (PID %d); waiting for shutdown", pid)
		return waitForDaemonStop(global.Daemon.PIDFile)
	},
}

// requestShutdownViaControlAPI asks the running daemon's control API to shut
// down gracefully — the same code path SIGTERM triggers (drain servers,
// persist budgets, close the audit DB, remove the PID file), just reached
// over HTTP instead of an OS signal. This is the only mechanism that works
// on every OS "aor start" runs on.
func requestShutdownViaControlAPI(global *config.GlobalConfig) error {
	tokenPath := config.ExpandHomePath(global.Daemon.ControlTokenFile)
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("read control token: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+global.Daemon.ControlAddr+"/control/shutdown", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tokenBytes)))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control API returned %s", resp.Status)
	}
	return nil
}

// waitForDaemonStop polls for the PID file to disappear (the daemon removes
// it on clean exit) regardless of which shutdown path triggered it.
func waitForDaemonStop(pidFile string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if _, err := daemon.ReadPID(pidFile); err != nil {
			fmt.Println(" stopped.")
			return nil
		}
		fmt.Print(".")
	}
	fmt.Println("\nWarning: daemon did not stop within 15 s — it may still be shutting down.")
	return nil
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

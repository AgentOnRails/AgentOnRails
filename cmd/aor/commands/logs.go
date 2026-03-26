package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Stream and inspect logs",
}

var logsTailCmd = &cobra.Command{
	Use:   "tail [agent-id]",
	Short: "Stream the audit log in real time (Ctrl+C to stop)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		db, err := audit.NewSQLiteAuditLogger(config.ExpandHomePath(global.Daemon.AuditDB))
		if err != nil {
			return fmt.Errorf("open audit db: %w", err)
		}
		defer db.Close()

		agentID := ""
		if len(args) == 1 {
			agentID = args[0]
		}

		if agentID != "" {
			fmt.Printf("Tailing audit log for agent %q (Ctrl+C to stop)...\n\n", agentID)
		} else {
			fmt.Print("Tailing audit log for all agents (Ctrl+C to stop)...\n\n")
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tAGENT\tSTATUS\tAMOUNT\tENDPOINT\tTX")
		tw.Flush()

		// Track the most recent timestamp we've printed so we only emit new rows.
		// Seed with "now minus 1s" so we show any in-flight transactions immediately.
		seen := make(map[string]bool)
		watermark := time.Now().Add(-time.Second)

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-quit:
				fmt.Println()
				return nil

			case <-ticker.C:
				txns, err := db.QueryTransactions(agentID, watermark, 100)
				if err != nil {
					// DB may not exist yet if daemon hasn't made a payment — keep polling.
					continue
				}

				for _, t := range txns {
					if seen[t.ID] {
						continue
					}
					seen[t.ID] = true
					if t.Timestamp.After(watermark) {
						watermark = t.Timestamp
					}

					amount := "-"
					if t.AmountUSD > 0 {
						amount = fmt.Sprintf("$%.4f", t.AmountUSD)
					}
					txHash := t.TxHash
					if len(txHash) > 12 {
						txHash = txHash[:10] + "…"
					}
					endpoint := truncate(t.Endpoint, 45)

					status := t.Status
					if t.BlockReason != "" {
						status = fmt.Sprintf("%s (%s)", t.Status, truncate(t.BlockReason, 30))
					}

					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
						t.Timestamp.Format("01-02 15:04:05"),
						t.AgentID,
						status,
						amount,
						endpoint,
						txHash,
					)
					tw.Flush()

					// Purge old entries from seen map to avoid unbounded growth.
					// Keep watermark intact so already-printed rows are not repeated.
					if len(seen) > 500 {
						seen = make(map[string]bool)
					}
				}
			}
		}
	},
}

func init() {
	logsCmd.AddCommand(logsTailCmd)
	Root.AddCommand(logsCmd)
}

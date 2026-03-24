package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
)

var (
	auditSince string
	auditLimit int
)

var auditCmd = &cobra.Command{
	Use:   "audit [agent-id]",
	Short: "Show transaction audit log",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return err
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

		var since time.Time
		if auditSince != "" {
			dur, err := parseSinceDuration(auditSince)
			if err != nil {
				return err
			}
			since = time.Now().Add(-dur)
		}

		txns, err := db.QueryTransactions(agentID, since, auditLimit)
		if err != nil {
			return fmt.Errorf("query transactions: %w", err)
		}

		if len(txns) == 0 {
			fmt.Println("No transactions found.")
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tAGENT\tSTATUS\tAMOUNT\tENDPOINT\tTX HASH")
		for _, t := range txns {
			amount := "-"
			if t.AmountUSD > 0 {
				amount = fmt.Sprintf("$%.4f", t.AmountUSD)
			}
			txHash := t.TxHash
			if len(txHash) > 12 {
				txHash = txHash[:10] + "…"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
				t.Timestamp.Format("01-02 15:04:05"),
				t.AgentID,
				t.Status,
				amount,
				truncate(t.Endpoint, 50),
				txHash,
			)
		}
		return tw.Flush()
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditSince, "since", "", "Only show transactions from the last duration (e.g. 24h, 7d)")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of rows to return")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// parseSinceDuration extends time.ParseDuration to support a plain integer
// followed by "d" (days), e.g. "7d" = 168h. This matches common CLI conventions
// and the examples shown in --help text.
func parseSinceDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid --since value %q: use a duration like 24h, 7d, or 168h", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --since value %q: use a duration like 24h, 7d, or 168h", s)
	}
	return d, nil
}

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/audit"
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
		fmt.Fprintln(tw, "TIME\tAGENT\tSTATUS\tAMOUNT\tENDPOINT\tTX HASH\tCALLER DID\tBLOCK REASON")
		for _, t := range txns {
			amount := "-"
			if t.AmountUSD > 0 {
				amount = fmt.Sprintf("$%.4f", t.AmountUSD)
			}
			txHash := t.TxHash
			if len(txHash) > 12 {
				txHash = txHash[:10] + "…"
			}
			callerDID := t.CallerDID
			if callerDID == "" {
				callerDID = "-"
			} else {
				callerDID = truncate(callerDID, 20)
			}
			blockReason := t.BlockReason
			if blockReason == "" {
				blockReason = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				t.Timestamp.Format("01-02 15:04:05"),
				t.AgentID,
				t.Status,
				amount,
				truncate(t.Endpoint, 50),
				txHash,
				callerDID,
				blockReason,
			)
		}
		return tw.Flush()
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check the audit log's hash chain for tampering",
	Long: `Walks every transaction row in the order it was written and recomputes
each one's expected hash from its own fields plus the row before it.

Every row's hash chains in the one before it, so editing or deleting any row
(e.g. by opening audit.db directly instead of going through the daemon)
breaks the stored hash of every row written after it — not just its own.
This command reports the first row where that break shows up.

A clean result means every row this command can see is exactly what the
daemon wrote, in the order it wrote it. Exits non-zero if a break is found,
so this is safe to use as a scripted integrity check.`,
	Args: cobra.NoArgs,
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

		brk, err := db.VerifyChain()
		if err != nil {
			return fmt.Errorf("verify audit chain: %w", err)
		}
		if brk == nil {
			fmt.Println("OK — audit log hash chain verified, no tampering detected.")
			return nil
		}

		fmt.Printf("TAMPERING DETECTED at row %d (transaction %s, %s):\n", brk.RowID, brk.TransactionID, brk.Timestamp.Format(time.RFC3339))
		fmt.Printf("  expected hash: %s\n", brk.Expected)
		fmt.Printf("  stored hash:   %s\n", brk.Stored)
		fmt.Println("This row (or one before it) does not match what the daemon originally wrote.")
		return fmt.Errorf("audit log hash chain broken at transaction %s", brk.TransactionID)
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditSince, "since", "", "Only show transactions from the last duration (e.g. 24h, 7d)")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of rows to return")
	auditCmd.AddCommand(auditVerifyCmd)
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

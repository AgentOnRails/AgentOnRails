package commands

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/internal/audit"
	"github.com/agentOnRails/agent-on-rails/internal/config"
)

var spendCmd = &cobra.Command{
	Use:   "spend [agent-id]",
	Short: "Show budget usage for an agent",
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

		var agentIDs []string
		if len(args) == 1 {
			agentIDs = []string{args[0]}
		} else {
			agents, err := config.LoadAgents(agentsDir)
			if err != nil {
				return err
			}
			for _, a := range agents {
				agentIDs = append(agentIDs, a.AgentID)
			}
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "AGENT\tPERIOD\tSPENT (USD)\tSINCE")
		for _, id := range agentIDs {
			periods := []struct {
				name  string
				since time.Time
			}{
				{"daily", time.Now().UTC().Truncate(24 * time.Hour)},
				{"weekly", weekStart(time.Now().UTC())},
				{"monthly", monthStart(time.Now().UTC())},
			}
			for _, p := range periods {
				spent, err := db.SpendSummary(id, p.since)
				if err != nil {
					return err
				}
				fmt.Fprintf(tw, "%s\t%s\t$%.4f\t%s\n",
					id, p.name, spent, p.since.Format("2006-01-02"))
			}
		}
		return tw.Flush()
	},
}

func weekStart(t time.Time) time.Time {
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	return t.Truncate(24 * time.Hour).AddDate(0, 0, -(wd - 1))
}

func monthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}

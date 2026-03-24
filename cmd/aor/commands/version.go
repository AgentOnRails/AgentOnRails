package commands

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the AgentOnRails version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AgentOnRails %s (%s %s/%s)\n",
			version.Version,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH,
		)
	},
}

func init() {
	Root.AddCommand(versionCmd)
}

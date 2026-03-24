// Command aor is the AgentOnRails CLI and daemon entry point.
package main

import "github.com/agentOnRails/agent-on-rails/cmd/aor/commands"

func main() {
	commands.Execute()
}

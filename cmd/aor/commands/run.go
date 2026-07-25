package commands

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/daemon"
)

var runAgentID string

var runCmd = &cobra.Command{
	Use:   "run --agent <agent-id> -- <command> [args...]",
	Short: "Run a command with this agent's proxy wired in via env vars — no OS trust store changes",
	Long: `Runs <command> as a subprocess with HTTP_PROXY/HTTPS_PROXY pointed at this
agent's proxy port. If the daemon has https_intercept enabled, the CA
certificate is also scoped to this one subprocess via REQUESTS_CA_BUNDLE,
SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, and CURL_CA_BUNDLE — env vars most HTTP
clients already respect (Python requests/httpx, Node fetch, curl). Nothing
is installed into the system trust store; trust exists only for this one
process tree and disappears when it exits.

Runtimes that ignore those env vars (some Go binaries, the JVM, some system
tools) need "aor trust install" instead, which installs the CA into the OS
trust store.

Requires "aor start" to already be running for this agent — this command
only sets environment variables, it doesn't start the daemon.

Example:
  aor run --agent my-agent -- python my_agent.py
  aor run --agent my-agent -- curl https://api.example.com/data`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if runAgentID == "" {
			return fmt.Errorf("--agent is required")
		}

		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		agents, err := config.LoadAgents(agentsDir)
		if err != nil {
			return fmt.Errorf("load agents: %w", err)
		}
		var agentCfg *config.AgentConfig
		for _, a := range agents {
			if a.AgentID == runAgentID {
				agentCfg = a
				break
			}
		}
		if agentCfg == nil {
			return fmt.Errorf("no agent %q found in %s", runAgentID, agentsDir)
		}

		if _, pidErr := daemon.ReadPID(global.Daemon.PIDFile); pidErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v — start it first with `aor start`\n", pidErr)
		}

		env := buildRunEnv(global, agentCfg)

		child := exec.Command(args[0], args[1:]...)
		child.Env = env
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		if err := child.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("run %s: %w", args[0], err)
		}
		return nil
	},
}

// buildRunEnv computes the child process environment: the current process's
// environment plus proxy vars for agentCfg's port, plus (if https_intercept
// is on and the CA already exists on disk) CA-trust env vars scoped to this
// process only.
func buildRunEnv(global *config.GlobalConfig, agentCfg *config.AgentConfig) []string {
	listenAddr := global.Daemon.ListenAddr
	if listenAddr == "" {
		listenAddr = config.DefaultListenAddr
	}
	proxyURL := fmt.Sprintf("http://%s:%d", listenAddr, agentCfg.ProxyPort)

	env := append(os.Environ(),
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)

	if global.Daemon.HTTPSIntercept {
		caPath := filepath.Join(config.ExpandHomePath(global.Daemon.CADir), "aor-ca.crt")
		if _, statErr := os.Stat(caPath); statErr != nil {
			fmt.Fprintf(os.Stderr, "warning: https_intercept is enabled but %s does not exist yet — it's created on daemon start; HTTPS payments won't be intercepted for this run\n", caPath)
		} else {
			env = append(env,
				"REQUESTS_CA_BUNDLE="+caPath,
				"SSL_CERT_FILE="+caPath,
				"NODE_EXTRA_CA_CERTS="+caPath,
				"CURL_CA_BUNDLE="+caPath,
			)
		}
	}

	return env
}

func init() {
	runCmd.Flags().StringVar(&runAgentID, "agent", "", "agent ID whose proxy/CA to wire in (required)")
	Root.AddCommand(runCmd)
}

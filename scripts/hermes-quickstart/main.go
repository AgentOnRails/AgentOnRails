// hermes-quickstart gets a funded, MCP-ready AgentOnRails agent up in the
// fewest possible steps for a Hermes (or any MCP-compatible client) user:
// build the aor binary, initialize ~/.aor, generate (or reuse) a burner
// wallet and agent config via internal/bootstrap — the same non-interactive
// path scripts/demo already proved — wait for testnet USDC, start the proxy
// daemon in the background, then print the exact MCP server config to point
// a client at and hand off to `aor mcp --agent hermes-agent` over stdio.
//
// aor mcp is a client of that daemon, not a standalone payment engine — it
// cannot process payments unless `aor start` is already running for this
// agent, which is why this script starts it for you rather than leaving it
// as a second manual step.
//
// The only manual step is claiming from the Circle faucet
// (captcha/wallet-connect) — everything else runs unattended.
//
// Run from the repo root:
//
//	go run ./scripts/hermes-quickstart
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/agentOnRails/agent-on-rails/internal/bootstrap"
)

const (
	agentID         = "hermes-agent"
	proxyPort       = 8498
	network         = bootstrap.BaseSepoliaNetwork
	fundWaitTimeout = 15 * time.Minute
	daemonUpTimeout = 30 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "\nhermes-quickstart failed:", err)
		os.Exit(1)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("determine home directory: %w", err)
	}
	aorDir := filepath.Join(home, ".aor")

	step("Building aor")
	tmpDir, err := os.MkdirTemp("", "aor-hermes-quickstart-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	aorBin := filepath.Join(tmpDir, exeName("aor"))
	if err := goBuild(aorBin, "./cmd/aor"); err != nil {
		return err
	}

	step("Initializing " + aorDir)
	configPath := filepath.Join(aorDir, "aor.yaml")
	_, statErr := os.Stat(configPath)
	configAlreadyExisted := statErr == nil
	if out, err := exec.Command(aorBin, "init").CombinedOutput(); err != nil {
		return fmt.Errorf("aor init: %w\n%s", err, out)
	}
	// MCP-mediated payments only see and handle https:// endpoints if the
	// daemon has interception on — enable it for a config we just created
	// ourselves (known content, safe to patch); for a pre-existing config,
	// don't touch it, just say so.
	if !configAlreadyExisted {
		if err := enableHTTPSIntercept(configPath); err != nil {
			fmt.Printf("  (couldn't enable https_intercept automatically: %s — add `https_intercept: true`\n", err)
			fmt.Printf("   under `daemon:` in %s yourself for HTTPS support)\n", configPath)
		}
	} else if !httpsInterceptEnabled(configPath) {
		fmt.Printf("  Note: %s already exists with daemon.https_intercept unset/false — MCP-mediated\n", configPath)
		fmt.Println("  payments on https:// endpoints won't be handled until you enable it yourself " +
			"and restart the daemon.")
	}

	step("Creating (or reusing) the burner wallet and agent config")
	address, passphrase, err := bootstrap.CreateFundable(aorDir, bootstrap.AgentOptions{
		AgentID:       agentID,
		ProxyPort:     proxyPort,
		Network:       network,
		DailyLimitUSD: "5.00",
		PerCallMaxUSD: "0.25",
	})
	if err != nil {
		return err
	}
	agentsDir := filepath.Join(aorDir, "agents")
	fmt.Printf("  Wallet:  %s\n  Config:  %s\n", address.Hex(), filepath.Join(agentsDir, agentID+".yaml"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	step("Waiting for testnet USDC")
	if err := bootstrap.WaitForBaseSepoliaUSDC(ctx, address, fundWaitTimeout); err != nil {
		return err
	}

	step("Starting the AgentOnRails proxy daemon")
	daemonLog, err := os.CreateTemp("", "aor-hermes-daemon-*.log")
	if err != nil {
		return fmt.Errorf("create daemon log file: %w", err)
	}
	defer daemonLog.Close()

	daemonCmd := exec.CommandContext(ctx, aorBin, "start", "--config", configPath, "--agents-dir", agentsDir)
	daemonCmd.Env = append(os.Environ(), "AOR_PASSPHRASE="+passphrase)
	daemonCmd.Stdout = daemonLog
	daemonCmd.Stderr = daemonLog
	if err := daemonCmd.Start(); err != nil {
		return fmt.Errorf("start aor daemon: %w", err)
	}
	fmt.Printf("  Daemon log: %s\n", daemonLog.Name())

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := waitForPort(ctx, proxyAddr, daemonUpTimeout); err != nil {
		return fmt.Errorf("daemon did not come up on %s within %s: %w (see %s)", proxyAddr, daemonUpTimeout, err, daemonLog.Name())
	}
	fmt.Printf("  Daemon is up on %s.\n", proxyAddr)

	mcpArgs := []string{"mcp", "--agent", agentID, "--config", configPath, "--agents-dir", agentsDir}

	step("Funded and ready")
	fmt.Println("Point your MCP client (Hermes, Claude Desktop, Claude Code, Cursor, ...) at:")
	fmt.Printf("\n  command: %s\n  args:    %v\n", aorBin, mcpArgs)
	fmt.Println("\nOr paste this into an MCP server config file:")
	fmt.Printf(`
  {
    "mcpServers": {
      "agentonrails": {
        "command": %q,
        "args": %s
      }
    }
  }
`, aorBin, jsonArgs(mcpArgs))

	fmt.Println("The AgentOnRails proxy daemon (`aor start`) is already running in the background —")
	fmt.Println("`aor mcp` is a client of it, not a separate payment engine, so this is the real,")
	fmt.Println("enforced setup end to end, not a lighter-weight alternative to it.")
	fmt.Println()
	fmt.Println("Launching `aor mcp` now over this terminal's stdio — Ctrl+C to stop (this also")
	fmt.Println("stops the daemon started above).")
	fmt.Println("(A real MCP client spawns this same command itself; running it here lets you")
	fmt.Println(" pipe a manual JSON-RPC request at it, or confirm it starts cleanly before")
	fmt.Println(" wiring it into a client config.)")
	fmt.Println()
	fmt.Println("IMPORTANT: even with the daemon running, an agent with any other way to reach")
	fmt.Println("the network (a shell tool, a browser tool, its own HTTP client) can bypass these")
	fmt.Println("tools entirely for a given request — that gap needs network-level egress lockdown,")
	fmt.Println("which is outside what this daemon+MCP pairing alone can guarantee.")

	cmd := exec.CommandContext(ctx, aorBin, mcpArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()

	// Whether aor mcp exited via Ctrl+C or on its own (client disconnected),
	// wind the background daemon down with it rather than leaving it orphaned.
	stop()
	_ = daemonCmd.Wait()
	return runErr
}

func step(msg string) {
	fmt.Printf("\n==> %s\n", msg)
}

func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func goBuild(out, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	if data, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, data)
	}
	return nil
}

// jsonArgs renders args as a JSON string array literal, for the copy-paste
// MCP server config block — deliberately not encoding/json here since the
// values are all simple, already-safe path/flag strings and a hand-rolled
// literal keeps the surrounding printf template readable.
func jsonArgs(args []string) string {
	out := "["
	for i, a := range args {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%q", a)
	}
	return out + "]"
}

// enableHTTPSIntercept patches a freshly-written aor.yaml (the exact
// template cmd/aor/commands/init.go's defaultGlobalConfig produces) to turn
// on HTTPS interception, so MCP-mediated payments handle https:// endpoints
// out of the box. Only ever called on a config this script just created —
// never on a pre-existing one, whose shape/formatting isn't ours to assume.
func enableHTTPSIntercept(cfgPath string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	content := string(data)
	if strings.Contains(content, "https_intercept:") {
		return nil
	}
	const marker = "  pid_file:"
	idx := strings.Index(content, marker)
	if idx == -1 {
		return fmt.Errorf("expected `daemon:` block not found in %s", cfgPath)
	}
	lineEnd := strings.Index(content[idx:], "\n")
	if lineEnd == -1 {
		return fmt.Errorf("unexpected end of file after %q in %s", marker, cfgPath)
	}
	insertAt := idx + lineEnd + 1
	patched := content[:insertAt] + "  https_intercept: true\n" + content[insertAt:]
	return os.WriteFile(cfgPath, []byte(patched), 0600)
}

// httpsInterceptEnabled does a best-effort text check of an existing
// aor.yaml — a full config.LoadGlobal parse isn't warranted just to decide
// whether to print an informational note.
func httpsInterceptEnabled(cfgPath string) bool {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "https_intercept:") {
			return strings.Contains(trimmed, "true")
		}
	}
	return false
}

// waitForPort polls addr until a TCP connection succeeds, ctx is cancelled,
// or timeout elapses.
func waitForPort(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

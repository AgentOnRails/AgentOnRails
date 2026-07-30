// demo is the scripted, zero-real-money walkthrough of the full x402 payment
// flow: generate a burner wallet, print testnet faucet links, wait for the
// wallet to be funded, start a real test API server and the real aor daemon,
// make one demo payment through it, and show where it landed in the audit
// log. The only manual step is claiming from the Circle faucet
// (captcha/wallet-connect) — everything else runs unattended.
//
// Run from the repo root:
//
//	go run ./scripts/demo
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/bootstrap"
)

const (
	agentID         = "demo-agent"
	proxyPort       = 8499
	testserverAddr  = ":4402"
	network         = bootstrap.BaseSepoliaNetwork
	paymentAmount   = "10000" // atomic USDC units = $0.01
	fundWaitTimeout = 15 * time.Minute
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "\ndemo failed:", err)
		os.Exit(1)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("determine home directory: %w", err)
	}
	aorDir := filepath.Join(home, ".aor")

	step("Building aor and testserver")
	tmpDir, err := os.MkdirTemp("", "aor-demo-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	aorBin := filepath.Join(tmpDir, exeName("aor"))
	testserverBin := filepath.Join(tmpDir, exeName("testserver"))
	if err := goBuild(aorBin, "./cmd/aor"); err != nil {
		return err
	}
	if err := goBuild(testserverBin, "./scripts/testserver"); err != nil {
		return err
	}

	step("Initializing " + aorDir)
	if out, err := exec.Command(aorBin, "init").CombinedOutput(); err != nil {
		return fmt.Errorf("aor init: %w\n%s", err, out)
	}

	global, err := config.LoadGlobal(filepath.Join(aorDir, "aor.yaml"))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	step("Creating (or reusing) the burner wallet and agent config")
	address, passphrase, err := bootstrap.CreateFundable(aorDir, bootstrap.AgentOptions{
		AgentID:       agentID,
		ProxyPort:     proxyPort,
		Network:       network,
		DailyLimitUSD: "1.00",
		PerCallMaxUSD: "0.05",
		// Legacy filename predating this repo's extraction into
		// internal/bootstrap — keep it exactly as-is so anyone who already
		// ran this demo and funded that wallet keeps reusing it instead of
		// silently getting a new, unfunded one.
		PassphraseFile: "demo-passphrase",
	})
	if err != nil {
		return err
	}
	fmt.Printf("  Wallet:  %s\n  Config:  %s\n", address.Hex(), filepath.Join(aorDir, "agents", agentID+".yaml"))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	step("Waiting for testnet USDC")
	if err := bootstrap.WaitForBaseSepoliaUSDC(ctx, address, fundWaitTimeout); err != nil {
		return err
	}

	step("Starting testserver")
	testserverLog := filepath.Join(tmpDir, "testserver.log")
	testserverCmd, err := startLogged(testserverBin, testserverLog,
		"-addr", testserverAddr, "-payto", address.Hex(), "-network", network, "-amount", paymentAmount)
	if err != nil {
		return fmt.Errorf("start testserver: %w", err)
	}
	defer killQuiet(testserverCmd)

	step("Starting aor daemon")
	daemonLog := filepath.Join(tmpDir, "aor-start.log")
	daemonCmd, err := startLogged(aorBin, daemonLog,
		"start", "--config", filepath.Join(aorDir, "aor.yaml"), "--agents-dir", filepath.Join(aorDir, "agents"), "--passphrase", passphrase)
	if err != nil {
		return fmt.Errorf("start aor daemon: %w", err)
	}
	defer killQuiet(daemonCmd)
	fmt.Printf("  Logs: %s\n  Logs: %s\n", testserverLog, daemonLog)

	step("Making one demo payment through the proxy")
	txHash, settledNetwork, err := makeDemoPayment(ctx)
	if err != nil {
		return fmt.Errorf("demo payment: %w (see %s and %s)", err, daemonLog, testserverLog)
	}
	fmt.Printf("  Paid $0.01 USDC — tx %s on %s\n", txHash, settledNetwork)

	fmt.Println()
	fmt.Println("Done. The daemon and test server are still running so you can poke around:")
	fmt.Printf("  %s spend %s --config %s\n", aorBin, agentID, filepath.Join(aorDir, "aor.yaml"))
	fmt.Printf("  %s audit %s --config %s\n", aorBin, agentID, filepath.Join(aorDir, "aor.yaml"))
	if dispatch, err := exec.LookPath("aor-pro"); err == nil {
		fmt.Printf("  %s dispatch serve --audit-db %s\n", dispatch, config.ExpandHomePath(global.Daemon.AuditDB))
	} else {
		fmt.Println("  (Dispatch — the audit dashboard — is part of the commercial aor-pro; see the \"Licensing & Commercial Offerings\" section of README.md)")
	}
	fmt.Println("\nCtrl+C to stop.")

	<-ctx.Done()
	fmt.Println("\nShutting down...")
	return nil
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

func startLogged(bin, logPath string, args ...string) (*exec.Cmd, error) {
	f, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	return cmd, nil
}

func killQuiet(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

// makeDemoPayment retries briefly while the daemon and testserver finish
// coming up, then makes exactly one request through the proxy.
func makeDemoPayment(ctx context.Context) (txHash, net string, err error) {
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}

	target := "http://localhost" + testserverAddr + "/paid"
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var result struct {
			Success     bool   `json:"success"`
			Transaction string `json:"transaction"`
			Network     string `json:"network"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return "", "", fmt.Errorf("decode response: %w (%s)", err, body)
		}
		if !result.Success {
			return "", "", fmt.Errorf("payment did not succeed: %s", body)
		}
		return result.Transaction, result.Network, nil
	}
	return "", "", fmt.Errorf("proxy never became ready: %w", lastErr)
}

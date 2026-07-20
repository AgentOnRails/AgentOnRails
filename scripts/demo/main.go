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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/vault"
)

const (
	agentID         = "demo-agent"
	proxyPort       = 8499
	testserverAddr  = ":4402"
	network         = "eip155:84532" // Base Sepolia
	baseSepoliaRPC  = "https://sepolia.base.org"
	baseSepoliaUSDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
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
	v, err := vault.New(config.ExpandHomePath(global.Daemon.VaultDir))
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	passphrasePath := filepath.Join(aorDir, "demo-passphrase")
	address, passphrase, err := loadOrCreateWallet(v, passphrasePath)
	if err != nil {
		return err
	}
	fmt.Printf("  Wallet:     %s\n  Passphrase: %s (stored at %s)\n", address.Hex(), passphrase, passphrasePath)

	step("Writing agent config")
	agentPath := filepath.Join(aorDir, "agents", agentID+".yaml")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0700); err != nil {
		return fmt.Errorf("create agents dir: %w", err)
	}
	if err := os.WriteFile(agentPath, []byte(agentYAML(address)), 0600); err != nil {
		return fmt.Errorf("write agent config: %w", err)
	}
	fmt.Printf("  %s\n", agentPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := waitForFunds(ctx, address); err != nil {
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
		fmt.Println("  (Dispatch — the audit dashboard — is part of the commercial aor-pro; see docs/ROADMAP.md)")
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

// loadOrCreateWallet reuses the previous demo run's burner wallet if one
// exists (so re-running the demo doesn't require re-claiming the faucet),
// otherwise generates a fresh one and stores both the key and its passphrase.
func loadOrCreateWallet(v *vault.Vault, passphrasePath string) (common.Address, string, error) {
	if v.HasKey(agentID) {
		if passBytes, err := os.ReadFile(passphrasePath); err == nil {
			passphrase := string(passBytes)
			if keyBytes, err := v.LoadKey(agentID, passphrase); err == nil {
				key, err := ethcrypto.ToECDSA(keyBytes)
				if err != nil {
					return common.Address{}, "", fmt.Errorf("decode stored key: %w", err)
				}
				return ethcrypto.PubkeyToAddress(key.PublicKey), passphrase, nil
			}
		}
	}

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		return common.Address{}, "", fmt.Errorf("generate wallet: %w", err)
	}
	passBytes := make([]byte, 32)
	if _, err := rand.Read(passBytes); err != nil {
		return common.Address{}, "", fmt.Errorf("generate passphrase: %w", err)
	}
	passphrase := hex.EncodeToString(passBytes)

	if err := v.StoreKey(agentID, passphrase, ethcrypto.FromECDSA(key)); err != nil {
		return common.Address{}, "", fmt.Errorf("store wallet: %w", err)
	}
	if err := os.WriteFile(passphrasePath, []byte(passphrase), 0600); err != nil {
		return common.Address{}, "", fmt.Errorf("save passphrase: %w", err)
	}
	return ethcrypto.PubkeyToAddress(key.PublicKey), passphrase, nil
}

func agentYAML(addr common.Address) string {
	return fmt.Sprintf(`# Generated by: go run ./scripts/demo — safe to delete after the demo.
agent_id: %q
proxy_port: %d

rails:
  x402:
    enabled: true
    wallet_address: %q
    preferred_chain: %q
    daily_limit_usd:  "1.00"
    per_call_max_usd: "0.05"
    endpoint_mode: "open"
    allowed_networks:
      - %q
    velocity:
      max_per_minute: 30
      max_per_hour:   200
      cooldown_seconds: 60
`, agentID, proxyPort, addr.Hex(), network, network)
}

// waitForFunds polls the burner wallet's testnet USDC balance until it's
// funded. Native ETH is not required: x402's EIP-3009 transferWithAuthorization
// is a gasless meta-transaction relayed (and paid for) by the facilitator, so
// the only manual step is the Circle USDC faucet claim.
func waitForFunds(ctx context.Context, addr common.Address) error {
	balance, err := usdcBalance(ctx, addr)
	if err != nil {
		return fmt.Errorf("check USDC balance: %w", err)
	}
	if balance.Sign() > 0 {
		step(fmt.Sprintf("Wallet already funded (%s USDC)", formatUSDC(balance)))
		return nil
	}

	step("Waiting for testnet USDC")
	fmt.Println("  This wallet has no testnet USDC yet. Claim some (one-time, manual — requires a captcha/connect step):")
	fmt.Printf("    1. Copy this address: %s\n", addr.Hex())
	fmt.Println("    2. Open https://faucet.circle.com and select Base Sepolia")
	fmt.Println("  (Optional: https://www.alchemy.com/faucets/base-sepolia for testnet ETH — not required for this demo,")
	fmt.Println("   since the facilitator pays gas on the agent's behalf.)")
	fmt.Println("\n  Polling every 10s, up to 15 minutes...")

	deadline := time.Now().Add(fundWaitTimeout)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			balance, err := usdcBalance(ctx, addr)
			if err == nil && balance.Sign() > 0 {
				fmt.Printf("\n  Funded: %s USDC\n", formatUSDC(balance))
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out after %s waiting for %s to receive testnet USDC", fundWaitTimeout, addr.Hex())
			}
			fmt.Print(".")
		}
	}
}

// usdcBalance calls the USDC contract's balanceOf(holder) via a raw
// eth_call JSON-RPC request — a plain net/http POST rather than pulling in
// go-ethereum's ethclient/rpc packages (and their large transitive
// dependency tree: metrics, p2p, gopsutil, etc.) for one read-only call.
func usdcBalance(ctx context.Context, holder common.Address) (*big.Int, error) {
	selector := []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	data := slices.Concat(selector, common.LeftPadBytes(holder.Bytes(), 32))
	callData := "0x" + hex.EncodeToString(data)

	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": baseSepoliaUSDC, "data": callData},
			"latest",
		},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseSepoliaRPC, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", out.Error.Message)
	}
	hexResult := strings.TrimPrefix(out.Result, "0x")
	if hexResult == "" {
		return big.NewInt(0), nil
	}
	val, ok := new(big.Int).SetString(hexResult, 16)
	if !ok {
		return nil, fmt.Errorf("unexpected eth_call result %q", out.Result)
	}
	return val, nil
}

func formatUSDC(atomic *big.Int) string {
	f := new(big.Float).Quo(new(big.Float).SetInt(atomic), big.NewFloat(1_000_000))
	return f.Text('f', 4)
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

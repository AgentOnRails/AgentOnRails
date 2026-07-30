package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// BaseSepoliaNetwork is the CAIP-2 network identifier for Base Sepolia,
// the testnet every scripted zero-money demo/quickstart in this repo pays
// on.
const BaseSepoliaNetwork = "eip155:84532"

const (
	baseSepoliaRPC  = "https://sepolia.base.org"
	baseSepoliaUSDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
)

// WaitForBaseSepoliaUSDC polls addr's Base Sepolia USDC balance until it's
// funded, printing faucet instructions and a progress dot per poll —
// unchanged behavior from what scripts/demo already proved live against
// the Circle testnet faucet, just reusable by other scripts now.
//
// Native ETH is not required: x402's EIP-3009 transferWithAuthorization is
// a gasless meta-transaction relayed (and paid for) by the facilitator, so
// claiming testnet USDC is the only manual step.
func WaitForBaseSepoliaUSDC(ctx context.Context, addr common.Address, timeout time.Duration) error {
	balance, err := USDCBalance(ctx, addr)
	if err != nil {
		return fmt.Errorf("bootstrap: check USDC balance: %w", err)
	}
	if balance.Sign() > 0 {
		fmt.Printf("Wallet already funded (%s USDC)\n", FormatUSDC(balance))
		return nil
	}

	fmt.Println("This wallet has no testnet USDC yet. Claim some (one-time, manual — requires a captcha/connect step):")
	fmt.Printf("  1. Copy this address: %s\n", addr.Hex())
	fmt.Println("  2. Open https://faucet.circle.com and select Base Sepolia")
	fmt.Println("(Optional: https://www.alchemy.com/faucets/base-sepolia for testnet ETH — not required,")
	fmt.Println(" since the facilitator pays gas on the agent's behalf.)")
	fmt.Printf("\nPolling every 10s, up to %s...\n", timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			balance, err := USDCBalance(ctx, addr)
			if err == nil && balance.Sign() > 0 {
				fmt.Printf("\nFunded: %s USDC\n", FormatUSDC(balance))
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("bootstrap: timed out after %s waiting for %s to receive testnet USDC", timeout, addr.Hex())
			}
			fmt.Print(".")
		}
	}
}

// USDCBalance calls the USDC contract's balanceOf(holder) via a raw
// eth_call JSON-RPC request — a plain net/http POST rather than pulling in
// go-ethereum's ethclient/rpc packages (and their large transitive
// dependency tree: metrics, p2p, gopsutil, etc.) for one read-only call.
func USDCBalance(ctx context.Context, holder common.Address) (*big.Int, error) {
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

// FormatUSDC renders atomic USDC units (6 decimals) as a decimal string.
func FormatUSDC(atomic *big.Int) string {
	f := new(big.Float).Quo(new(big.Float).SetInt(atomic), big.NewFloat(1_000_000))
	return f.Text('f', 4)
}

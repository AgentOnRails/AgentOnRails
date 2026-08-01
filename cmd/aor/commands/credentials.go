package commands

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/gagliardetto/solana-go/base58"

	"github.com/agentOnRails/agent-on-rails/config"
	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	"github.com/agentOnRails/agent-on-rails/vault"
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage agent credentials",
}

var setWalletKeyType string

var setWalletCmd = &cobra.Command{
	Use:   "set-wallet <agent-id>",
	Short: "Encrypt and store a wallet private key for an agent",
	Long: `Prompts for the agent's private key and a passphrase, then encrypts the key
with AES-256-GCM and stores it in the vault.

--key-type selects the format the key is entered in and read back as:
  ecdsa   (default) — hex, with or without 0x prefix — EVM chains
  ed25519            — hex or base58, a 32-byte seed — Solana

This must match the key_type in the agent's own rails.x402 config (empty
there defaults to ecdsa) — a mismatch fails at daemon startup with a wallet
key mismatch error, not here.

The passphrase must match the one used when starting the daemon (AOR_PASSPHRASE).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSetWallet(bufio.NewReader(os.Stdin), args[0])
	},
}

// runSetWallet holds set-wallet's actual logic, taking the buffered stdin
// reader as a parameter rather than constructing its own. This lets "agents
// create" delegate into it using the SAME reader it's already using for the
// rest of the wizard (see agents.go) instead of a fresh one — reading
// secrets via a brand-new bufio.Reader/Scanner per prompt is what caused the
// non-interactive (piped) input bug this replaces: the first reader to touch
// a piped stdin can slurp the whole remaining input into its own internal
// buffer, so any later reader constructed fresh sees EOF and silently
// returns "", even though the data was "typed". Reusing one shared reader
// for every prompt in a single invocation avoids that entirely.
func runSetWallet(in *bufio.Reader, agentID string) error {
	global, err := config.LoadGlobal(globalConfigPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	v, err := vault.New(config.ExpandHomePath(global.Daemon.VaultDir))
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}

	var keyBytes []byte
	var address string

	switch setWalletKeyType {
	case x402.KeyTypeEd25519:
		fmt.Printf("Enter private key (seed) for agent %q (hex or base58, no echo): ", agentID)
		keyStr, err := readSecret(in)
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		seed, err := parseEd25519Seed(keyStr)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		var pubArr [32]byte
		copy(pubArr[:], pub)
		keyBytes = seed
		address = base58.Encode32(&pubArr)

	default: // ecdsa
		fmt.Printf("Enter private key for agent %q (hex, no echo): ", agentID)
		keyHex, err := readSecret(in)
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		keyHex = strings.TrimSpace(strings.TrimPrefix(keyHex, "0x"))

		key, err := ethcrypto.HexToECDSA(keyHex)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
		keyBytes = ethcrypto.FromECDSA(key)
		address = ethcrypto.PubkeyToAddress(key.PublicKey).Hex()
	}

	// Prompt for passphrase
	fmt.Printf("Enter vault passphrase (no echo): ")
	pass, err := readSecret(in)
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	fmt.Printf("Confirm passphrase: ")
	pass2, err := readSecret(in)
	if err != nil {
		return fmt.Errorf("read passphrase confirm: %w", err)
	}
	if pass != pass2 {
		return fmt.Errorf("passphrases do not match")
	}
	if pass == "" {
		return fmt.Errorf("passphrase cannot be empty")
	}

	if err := v.StoreKey(agentID, pass, keyBytes); err != nil {
		return fmt.Errorf("store key: %w", err)
	}

	fmt.Printf("\nWallet stored for agent %q\nAddress: %s\nVault:   %s\n",
		agentID, address, v.AgentVaultPath(agentID))
	return nil
}

// parseEd25519Seed accepts a 32-byte ed25519 seed as either hex (with or
// without 0x prefix) or base58 — base58 because that's the form Solana
// tooling (solana-keygen, wallet exports) commonly uses, hex because every
// other key this CLI accepts already is one.
func parseEd25519Seed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if hexStr := strings.TrimPrefix(s, "0x"); len(hexStr) == ed25519.SeedSize*2 {
		if b, err := hex.DecodeString(hexStr); err == nil {
			return b, nil
		}
	}
	var arr [32]byte
	if err := base58.Decode32(s, &arr); err == nil {
		return arr[:], nil
	}
	return nil, fmt.Errorf("expected a %d-byte ed25519 seed as hex or base58", ed25519.SeedSize)
}

func init() {
	setWalletCmd.Flags().StringVar(&setWalletKeyType, "key-type", x402.KeyTypeECDSA, "key format: ecdsa (EVM) or ed25519 (Solana) — must match the agent's rails.x402.key_type")
	credentialsCmd.AddCommand(setWalletCmd)
}

// readSecret reads one line without terminal echo when possible. On a real
// terminal it reads directly from the fd in raw mode (term.ReadPassword) so
// nothing is echoed; there's no buffering hazard there since a canonical-mode
// tty only ever has what's already been typed available to read. Non-TTY
// (piped/redirected) stdin has no such echo to suppress, so it reads a line
// from the caller's shared bufio.Reader instead — the same reader used for
// every other prompt in the calling command, so piped input lands in order
// no matter how many secrets are read in one invocation. (A previous version
// created a brand-new bufio.Scanner(os.Stdin) per call for this fallback —
// the first such scanner to run could drain the entire remaining pipe into
// its own buffer, leaving every later call to silently read as "".)
func readSecret(in *bufio.Reader) (string, error) {
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		return string(b), err
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/internal/vault"
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage agent credentials",
}

var setWalletCmd = &cobra.Command{
	Use:   "set-wallet <agent-id>",
	Short: "Encrypt and store a wallet private key for an agent",
	Long: `Prompts for the agent's private key (hex, with or without 0x prefix) and
a passphrase, then encrypts the key with AES-256-GCM and stores it in the vault.

The passphrase must match the one used when starting the daemon (AOR_PASSPHRASE).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		agentID := args[0]

		global, err := config.LoadGlobal(globalConfigPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		v, err := vault.New(config.ExpandHomePath(global.Daemon.VaultDir))
		if err != nil {
			return fmt.Errorf("open vault: %w", err)
		}

		// Prompt for private key
		fmt.Printf("Enter private key for agent %q (hex, no echo): ", agentID)
		keyHex, err := readSecret()
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		keyHex = strings.TrimSpace(strings.TrimPrefix(keyHex, "0x"))

		key, err := ethcrypto.HexToECDSA(keyHex)
		if err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}

		// Prompt for passphrase
		fmt.Printf("Enter vault passphrase (no echo): ")
		pass, err := readSecret()
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		fmt.Printf("Confirm passphrase: ")
		pass2, err := readSecret()
		if err != nil {
			return fmt.Errorf("read passphrase confirm: %w", err)
		}
		if pass != pass2 {
			return fmt.Errorf("passphrases do not match")
		}

		if err := v.StoreKey(agentID, pass, key); err != nil {
			return fmt.Errorf("store key: %w", err)
		}

		addr := ethcrypto.PubkeyToAddress(key.PublicKey)
		fmt.Printf("\nWallet stored for agent %q\nAddress: %s\nVault:   %s\n",
			agentID, addr.Hex(), v.AgentVaultPath(agentID))
		return nil
	},
}

func init() {
	credentialsCmd.AddCommand(setWalletCmd)
}

// readSecret reads a line without terminal echo when possible.
func readSecret() (string, error) {
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		return string(b), err
	}
	// Fallback for non-TTY (piped input in CI)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	return "", scanner.Err()
}

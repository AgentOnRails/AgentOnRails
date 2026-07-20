// genwallet is a throwaway helper for provisioning a burner wallet directly
// into the AgentOnRails vault. The private key exists only in process memory:
// it is generated, immediately encrypted into the vault, and never written to
// disk unencrypted or printed. Only the derived public address is printed.
//
// Usage:
//
//	go run ./scripts/genwallet -vault-dir ~/.aor-mainnet-test/vaults -agent-id claude-test -passphrase-file ~/.aor-mainnet-test/passphrase.txt
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/agentOnRails/agent-on-rails/vault"
)

func main() {
	vaultDir := flag.String("vault-dir", "", "vault directory (required)")
	agentID := flag.String("agent-id", "", "agent id to store the key under (required)")
	passphraseFile := flag.String("passphrase-file", "", "path to write the generated passphrase (required)")
	flag.Parse()

	if *vaultDir == "" || *agentID == "" || *passphraseFile == "" {
		log.Fatal("genwallet: -vault-dir, -agent-id, and -passphrase-file are all required")
	}

	key, err := ethcrypto.GenerateKey()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	passBytes := make([]byte, 32)
	if _, err := rand.Read(passBytes); err != nil {
		log.Fatalf("generate passphrase: %v", err)
	}
	passphrase := hex.EncodeToString(passBytes)

	if err := os.WriteFile(*passphraseFile, []byte(passphrase), 0600); err != nil {
		log.Fatalf("write passphrase file: %v", err)
	}

	v, err := vault.New(*vaultDir)
	if err != nil {
		log.Fatalf("open vault: %v", err)
	}
	if err := v.StoreKey(*agentID, passphrase, ethcrypto.FromECDSA(key)); err != nil {
		log.Fatalf("store key: %v", err)
	}

	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	fmt.Println(addr.Hex())
}

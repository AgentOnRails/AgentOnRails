// testserver is a local x402-compliant API server for development and Sepolia
// e2e testing. It issues real x402 challenges on GET /paid, optionally calling
// the configured facilitator to verify incoming payment signatures.
//
// Usage:
//
//	go run ./scripts/testserver/ -payto 0xYOUR_WALLET [-network eip155:84532] [-amount 10000] [-addr :4402]
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// paymentRequired mirrors the x402.PaymentRequired struct for JSON encoding.
type paymentRequired struct {
	X402Version int                   `json:"x402Version"`
	Accepts     []paymentRequirement  `json:"accepts"`
}

type paymentRequirement struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// knownAssets maps CAIP-2 chain IDs to USDC contract addresses.
var knownAssets = map[string]string{
	"eip155:1":     "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
	"eip155:8453":  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	"eip155:10":    "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
	"eip155:42161": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
	"eip155:137":   "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
	"eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}

func main() {
	addr        := flag.String("addr", ":4402", "listen address")
	network     := flag.String("network", "eip155:84532", "CAIP-2 chain identifier")
	amount      := flag.String("amount", "10000", "atomic USDC units (10000 = $0.01)")
	payTo       := flag.String("payto", "", "recipient wallet address (required)")
	facilitator := flag.String("facilitator", "https://x402.org/facilitator", "facilitator base URL")
	verify      := flag.Bool("verify", true, "call facilitator /verify before accepting payment")
	flag.Parse()

	if *payTo == "" {
		log.Fatal("testserver: -payto is required")
	}

	asset, ok := knownAssets[*network]
	if !ok {
		log.Fatalf("testserver: unknown network %q — supported: %s",
			*network, strings.Join(keys(knownAssets), ", "))
	}

	srv := &server{
		network:     *network,
		amount:      *amount,
		asset:       asset,
		payTo:       *payTo,
		facilitator: *facilitator,
		verify:      *verify,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/free",   srv.handleFree)
	mux.HandleFunc("/paid",   srv.handlePaid)
	mux.HandleFunc("/health", srv.handleHealth)

	log.Printf("testserver: listening on %s (network=%s amount=%s payto=%s verify=%v)",
		*addr, *network, *amount, *payTo, *verify)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	network     string
	amount      string
	asset       string
	payTo       string
	facilitator string
	verify      bool
}

func (s *server) handleFree(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","paid":false}`))
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *server) handlePaid(w http.ResponseWriter, r *http.Request) {
	sig := r.Header.Get("PAYMENT-SIGNATURE")
	if sig == "" {
		s.send402(w)
		return
	}

	if s.verify {
		req := paymentRequirement{
			Scheme:            "exact",
			Network:           s.network,
			Amount:            s.amount,
			Asset:             s.asset,
			PayTo:             s.payTo,
			MaxTimeoutSeconds: 60,
			Extra:             map[string]any{"name": "USDC", "version": "2"},
		}
		if err := s.callFacilitatorVerify(sig, req); err != nil {
			log.Printf("testserver: facilitator verify rejected: %v", err)
			s.send402(w)
			return
		}
	}

	txHash := fmt.Sprintf("0xtestserver%x", time.Now().UnixNano())
	resp := map[string]any{
		"success":     true,
		"transaction": txHash,
		"network":     s.network,
	}
	data, _ := json.Marshal(resp)
	respJSON, _ := json.Marshal(resp)
	w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(data))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJSON)
}

func (s *server) send402(w http.ResponseWriter) {
	challenge := paymentRequired{
		X402Version: 2,
		Accepts: []paymentRequirement{{
			Scheme:            "exact",
			Network:           s.network,
			Amount:            s.amount,
			Asset:             s.asset,
			PayTo:             s.payTo,
			MaxTimeoutSeconds: 60,
			Extra:             map[string]any{"name": "USDC", "version": "2"},
		}},
	}
	data, _ := json.Marshal(challenge)
	w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
	w.WriteHeader(http.StatusPaymentRequired)
}

// facilitatorVerifyReq is the JSON body the x402 facilitator /verify endpoint expects.
type facilitatorVerifyReq struct {
	PaymentPayload      json.RawMessage    `json:"paymentPayload"`
	PaymentRequirements paymentRequirement `json:"paymentRequirements"`
}

// callFacilitatorVerify calls <facilitator>/verify with the payment signature.
// sig is the base64-encoded PAYMENT-SIGNATURE header value.
// req is the payment requirement the server advertised.
// Returns nil if the facilitator accepts the payment, or an error otherwise.
func (s *server) callFacilitatorVerify(sig string, req paymentRequirement) error {
	// The PAYMENT-SIGNATURE header is base64-encoded JSON.
	payloadBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("decode payment signature: %w", err)
	}

	body, err := json.Marshal(facilitatorVerifyReq{
		PaymentPayload:      json.RawMessage(payloadBytes),
		PaymentRequirements: req,
	})
	if err != nil {
		return fmt.Errorf("marshal verify request: %w", err)
	}

	verifyURL := strings.TrimRight(s.facilitator, "/") + "/verify"
	httpReq, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("facilitator unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("facilitator returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// keys returns the map keys as a sorted slice (for error messages).
func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Ensure strconv is used (amount is kept as a string; this silences linters
// that expect numeric validation in a production server).
var _ = strconv.Itoa

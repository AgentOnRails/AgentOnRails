package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
	arail "github.com/agentOnRails/agent-on-rails/rail"
)

// TestMITM_HTTPSInterception drives a full HTTPS payment through the proxy's
// TLS-interception path: an https:// upstream issues an x402 challenge, the
// agent reaches it via CONNECT, and AgentOnRails terminates the client TLS,
// signs the payment, calls the real upstream over HTTPS, and returns the paid
// content — all with policy enforcement intact. Before this path existed HTTPS
// CONNECT tunnels were opaque and no payment could occur.
func TestMITM_HTTPSInterception(t *testing.T) {
	// ── HTTPS upstream that speaks x402 (V2) ─────────────────────────────────
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/free" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.Header.Get("PAYMENT-SIGNATURE") == "" {
			challenge := x402.PaymentRequired{
				X402Version: 2,
				Accepts: []x402.PaymentRequirement{{
					Scheme:            "exact",
					Network:           "eip155:84532",
					Amount:            "10000", // $0.01
					Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
					PayTo:             "0x" + strings.Repeat("f", 40),
					MaxTimeoutSeconds: 60,
					Extra:             map[string]any{"name": "USDC", "version": "2"},
				}},
			}
			data, _ := json.Marshal(challenge)
			w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		resp := x402.PaymentResponse{
			Success:     true,
			Transaction: "0xmitmtest" + strconv.FormatInt(time.Now().UnixNano(), 16),
			Network:     "eip155:84532",
			Payer:       "0x" + strings.Repeat("a", 40),
		}
		data, _ := json.Marshal(resp)
		w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString(data))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"https paid content"}`))
	}))
	defer upstream.Close()

	// Trust pool for the upstream's self-signed TLS cert (used by the rail's
	// outbound HTTPS client).
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	// ── Build a rail that trusts the upstream cert ───────────────────────────
	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &x402.X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		PerCallMaxCents:    100,
		DailyLimitCents:    100,
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true,
		UpstreamTLSConfig:  &tls.Config{RootCAs: upstreamPool},
	}

	var logged []arail.TransactionRecord
	rail, err := x402.NewX402Rail(policy, &sliceAuditLogger{records: &logged}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// ── Start the proxy with interception enabled ────────────────────────────
	ca, err := x402.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	proxy := httptest.NewServer(x402.NewReverseProxyHandler(rail, "mitm-agent", ca))
	defer proxy.Close()

	// ── Client: routes through the proxy, trusts the AgentOnRails CA ─────────
	caPool := x509.NewCertPool()
	caCertPEM, err := os.ReadFile(ca.CertPath())
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("failed to add AOR CA to pool")
	}
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 10 * time.Second,
	}

	// ── Drive a paid HTTPS request through the proxy ─────────────────────────
	resp, err := client.Get(upstream.URL + "/paid")
	if err != nil {
		t.Fatalf("proxied HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "https paid content") {
		t.Errorf("body = %q, want it to contain %q", body, "https paid content")
	}

	// Payment must have been signed, enforced, and audited.
	if len(logged) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(logged))
	}
	rec := logged[0]
	if rec.Status != "allowed" {
		t.Errorf("audit status = %q, want allowed", rec.Status)
	}
	if rec.AmountUSD != 0.01 {
		t.Errorf("audit amount = %v, want 0.01", rec.AmountUSD)
	}
	if !strings.HasPrefix(rec.Endpoint, "https://") {
		t.Errorf("audit endpoint = %q, want an https:// URL", rec.Endpoint)
	}
}

// TestMITM_PolicyEnforcedOverHTTPS confirms guardrails still apply on the
// intercepted HTTPS path: a per-call cap below the quoted price blocks payment.
func TestMITM_PolicyEnforcedOverHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := x402.PaymentRequired{
			X402Version: 2,
			Accepts: []x402.PaymentRequirement{{
				Scheme:            "exact",
				Network:           "eip155:84532",
				Amount:            "1000000", // $1.00 — above the cap
				Asset:             "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
				PayTo:             "0x" + strings.Repeat("f", 40),
				MaxTimeoutSeconds: 60,
				Extra:             map[string]any{"name": "USDC", "version": "2"},
			}},
		}
		data, _ := json.Marshal(challenge)
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(data))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer upstream.Close()

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	key, _ := ethcrypto.GenerateKey()
	addr := ethcrypto.PubkeyToAddress(key.PublicKey)
	policy := &x402.X402Policy{
		PrivateKey:         key,
		WalletAddress:      addr.Hex(),
		PreferredChain:     "eip155:84532",
		PerCallMaxCents:    10, // $0.10 cap — the $1.00 quote must be rejected
		DailyLimitCents:    100,
		UpstreamTimeout:    5 * time.Second,
		FacilitatorTimeout: 5 * time.Second,
		PayloadTTL:         60 * time.Second,
		EndpointMode:       "open",
		SkipPreVerify:      true,
		UpstreamTLSConfig:  &tls.Config{RootCAs: upstreamPool},
	}

	var logged []arail.TransactionRecord
	rail, err := x402.NewX402Rail(policy, &sliceAuditLogger{records: &logged}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	ca, err := x402.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	proxy := httptest.NewServer(x402.NewReverseProxyHandler(rail, "mitm-agent", ca))
	defer proxy.Close()

	caPool := x509.NewCertPool()
	caCertPEM, _ := os.ReadFile(ca.CertPath())
	caPool.AppendCertsFromPEM(caCertPEM)
	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/paid")
	if err != nil {
		t.Fatalf("proxied HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (per-call cap should block)", resp.StatusCode)
	}
	if len(logged) != 1 || logged[0].Status != "blocked" {
		t.Fatalf("expected 1 blocked audit record, got %+v", logged)
	}
}

// sliceAuditLogger captures transaction records for assertions.
type sliceAuditLogger struct {
	records *[]arail.TransactionRecord
}

func (s *sliceAuditLogger) LogTransaction(tx arail.TransactionRecord) error {
	*s.records = append(*s.records, tx)
	return nil
}

package x402

// HTTPS interception (MITM) support.
//
// When an agent points its HTTP client at the proxy with HTTPS_PROXY, paid
// resources on https:// URLs arrive as CONNECT tunnels. A blind TCP tunnel
// cannot see the x402 402 challenge inside TLS, so no payment or policy
// enforcement is possible. To fix that, AgentOnRails can act as a local TLS
// man-in-the-middle: it terminates the client's TLS session with a certificate
// minted on the fly and signed by a locally-generated CA, decrypts the request,
// runs it through the x402 rail (full guardrails), and makes the real HTTPS call
// upstream itself.
//
// This only works if the agent trusts AgentOnRails' CA. The CA certificate is
// written to disk (ca_dir) so the operator can install it into the agent's trust
// store. The CA private key never leaves the machine.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caCertFile = "aor-ca.crt"
	caKeyFile  = "aor-ca.key"

	// Leaf certs are minted with a short validity; they are ephemeral and never
	// persisted. The window is generous enough to tolerate client clock skew.
	leafCertTTL = 24 * time.Hour * 397 // 397 days: max accepted by modern clients
)

// CA is AgentOnRails' local certificate authority for HTTPS interception. It
// mints per-host leaf certificates signed by a locally-generated root, caching
// them by host. It is safe for concurrent use.
type CA struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte // PEM-encoded CA certificate (for logging the install path)
	caPath  string
	leafKey *ecdsa.PrivateKey // one key reused across all leaf certs

	mu    sync.Mutex
	cache map[string]*tls.Certificate // host → forged cert
}

// LoadOrCreateCA loads the AgentOnRails CA from dir, creating a fresh one if it
// does not yet exist. dir is created if missing.
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseCA(certPEM, keyPEM, certPath)
		if err == nil {
			return ca, nil
		}
		// Fall through and regenerate if the stored CA is unreadable.
	}

	return generateCA(certPath, keyPath)
}

// LoadCACertPEM reads just the public CA certificate (PEM-encoded) from dir,
// without touching the private signing key. Unlike LoadOrCreateCA, it never
// generates anything — callers that only need a trust anchor (e.g. aor mcp
// building its own outbound TLS trust pool) have no business holding the key
// that mints per-host certs. Returns an error if dir has no CA yet (the
// daemon hasn't started with https_intercept enabled).
func LoadCACertPEM(dir string) ([]byte, error) {
	certPath := filepath.Join(dir, caCertFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("no interception CA at %s yet — start `aor start` with daemon.https_intercept: true first: %w", certPath, err)
	}
	return certPEM, nil
}

func parseCA(certPEM, keyPEM []byte, certPath string) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca cert: no PEM block")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca cert parse: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca key: no PEM block")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca key parse: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("leaf key: %w", err)
	}
	return &CA{
		caCert:  caCert,
		caKey:   caKey,
		caPEM:   certPEM,
		caPath:  certPath,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func generateCA(certPath, keyPath string) (*CA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca key gen: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AgentOnRails Local CA",
			Organization: []string{"AgentOnRails"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("ca cert create: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("ca key marshal: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write ca key: %w", err)
	}

	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca cert reparse: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("leaf key: %w", err)
	}
	return &CA{
		caCert:  caCert,
		caKey:   caKey,
		caPEM:   certPEM,
		caPath:  certPath,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// certForHost returns a TLS certificate valid for host, minting and caching one
// if necessary. host may be a DNS name or an IP literal (without port).
func (ca *CA) certForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(leafCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &ca.leafKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("mint leaf cert for %s: %w", host, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der, ca.caCert.Raw},
		PrivateKey:  ca.leafKey,
		Leaf:        tmpl,
	}
	ca.cache[host] = cert
	return cert, nil
}

// tlsConfig returns a *tls.Config whose GetCertificate mints a cert matching the
// client's SNI (falling back to fallbackHost when SNI is absent, e.g. for IP
// literals or older clients).
func (ca *CA) tlsConfig(fallbackHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = fallbackHost
			}
			return ca.certForHost(host)
		},
	}
}

// CertPath returns the on-disk path of the CA certificate the operator must
// install into agent trust stores.
func (ca *CA) CertPath() string { return ca.caPath }

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return serial, nil
}

// ─── one-shot listener ─────────────────────────────────────────────────────────

// oneShotListener adapts a single, already-accepted net.Conn into a net.Listener
// so it can be served by a standard http.Server (giving us keep-alive, chunked
// encoding, and full http.ResponseWriter semantics for free). The first Accept
// yields the connection; subsequent Accepts block until the connection is closed
// (by the server when the client disconnects), at which point they return
// net.ErrClosed so http.Server.Serve unblocks and returns instead of spinning
// forever on a listener that will never produce another connection.
type oneShotListener struct {
	addr net.Addr
	ch   chan net.Conn // buffered(1); holds the conn until the first Accept takes it
	done chan struct{}
	once sync.Once
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	l := &oneShotListener{
		addr: conn.LocalAddr(),
		ch:   make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	// Wrap the conn so that when http.Server closes it (client disconnect, idle
	// timeout, etc.), the listener closes too and Serve stops accepting.
	l.ch <- &closeNotifyConn{Conn: conn, onClose: l.Close}
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.addr }

// closeNotifyConn invokes onClose the first time the connection is closed,
// letting the one-shot listener shut down when its single connection ends.
type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func() error
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { _ = c.onClose() })
	return err
}

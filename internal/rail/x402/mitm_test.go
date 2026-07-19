package x402

import (
	"net"
	"testing"
	"time"
)

// TestOneShotListener_UnblocksOnConnClose verifies the listener stops accepting
// once its single connection is closed, so http.Server.Serve returns instead of
// blocking forever (which would leak the interception goroutine per tunnel).
func TestOneShotListener_UnblocksOnConnClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	ln := newOneShotListener(server)

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	accepted := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		accepted <- err
	}()

	// The second Accept must be blocked until the connection closes.
	select {
	case <-accepted:
		t.Fatal("second Accept returned before the connection was closed")
	case <-time.After(50 * time.Millisecond):
	}

	// Closing the served connection (as http.Server does on client disconnect)
	// must unblock the second Accept with an error.
	if err := conn.Close(); err != nil {
		t.Fatalf("close accepted conn: %v", err)
	}

	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("second Accept returned nil error after close, want net.ErrClosed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Accept did not return after the connection was closed")
	}
}

// TestCA_MintsCertForHost checks that the CA produces a leaf cert whose SAN
// matches the requested host and that certs are cached per host.
func TestCA_MintsCertForHost(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	cert, err := ca.certForHost("api.example.com")
	if err != nil {
		t.Fatalf("certForHost: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("api.example.com"); err != nil {
		t.Errorf("leaf cert does not cover host: %v", err)
	}

	// IP hosts must land in IPAddresses, not DNSNames.
	ipCert, err := ca.certForHost("127.0.0.1")
	if err != nil {
		t.Fatalf("certForHost(ip): %v", err)
	}
	if err := ipCert.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("leaf cert does not cover IP host: %v", err)
	}

	// Second call for the same host returns the cached cert (same pointer).
	again, _ := ca.certForHost("api.example.com")
	if again != cert {
		t.Error("expected cached certificate to be reused for the same host")
	}
}

// TestLoadOrCreateCA_Persists checks the CA is reused across loads from the same
// directory (so restarts don't invalidate an already-installed CA).
func TestLoadOrCreateCA_Persists(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !ca1.caCert.Equal(ca2.caCert) {
		t.Error("expected the CA to persist and reload identically across calls")
	}
}

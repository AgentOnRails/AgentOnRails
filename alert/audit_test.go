package alert

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/rail"
)

// fakeAuditLogger is a minimal rail.AuditLogger recording every call it
// receives, so tests can assert AuditLogger's wrapping never drops or
// mutates what the inner logger sees.
type fakeAuditLogger struct {
	mu     sync.Mutex
	logged []rail.TransactionRecord
	err    error
}

func (f *fakeAuditLogger) LogTransaction(tx rail.TransactionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logged = append(f.logged, tx)
	return f.err
}

func (f *fakeAuditLogger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.logged)
}

// webhookCapture is a test Slack webhook recording every posted message.
type webhookCapture struct {
	mu       sync.Mutex
	messages []string
}

func (c *webhookCapture) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg slackMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err == nil {
			c.mu.Lock()
			c.messages = append(c.messages, msg.Text)
			c.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func (c *webhookCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.messages)
}

func (c *webhookCapture) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.messages) == 0 {
		return ""
	}
	return c.messages[len(c.messages)-1]
}

func TestAuditLogger_BlockedTransaction_FiresAlertBlock(t *testing.T) {
	capture := &webhookCapture{}
	srv := capture.server()
	defer srv.Close()

	inner := &fakeAuditLogger{}
	logger := &AuditLogger{
		Inner:   inner,
		Alerter: New(srv.URL, 80, zap.NewNop()),
	}

	err := logger.LogTransaction(rail.TransactionRecord{
		AgentID:     "agent-1",
		Endpoint:    "https://api.example.com/paid",
		Status:      "blocked",
		BlockReason: "over daily budget",
	})
	if err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}
	if inner.count() != 1 {
		t.Fatalf("inner logger got %d calls, want 1 — wrapping must still log everything", inner.count())
	}

	assertWebhookCount(t, capture, 1)
	if got := capture.last(); !strings.Contains(got, "blocked") || !strings.Contains(got, "agent-1") || !strings.Contains(got, "over daily budget") {
		t.Fatalf("unexpected Slack message: %q", got)
	}
}

func TestAuditLogger_AllowedTransaction_FiresAlertTransaction(t *testing.T) {
	capture := &webhookCapture{}
	srv := capture.server()
	defer srv.Close()

	inner := &fakeAuditLogger{}
	logger := &AuditLogger{
		Inner:   inner,
		Alerter: New(srv.URL, 80, zap.NewNop()),
	}

	err := logger.LogTransaction(rail.TransactionRecord{
		AgentID:   "agent-1",
		Endpoint:  "https://api.example.com/paid",
		Status:    "allowed",
		AmountUSD: 0.05,
		Network:   "eip155:8453",
		TxHash:    "0xabc123",
	})
	if err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}

	assertWebhookCount(t, capture, 1)
	if got := capture.last(); !strings.Contains(got, "settled") || !strings.Contains(got, "0xabc123") {
		t.Fatalf("unexpected Slack message: %q", got)
	}
}

func TestAuditLogger_FailedTransaction_NoAlert(t *testing.T) {
	// "failed" is neither a block nor a settlement — AlertBlock/AlertTransaction
	// don't fit it, and this test locks in that scope rather than silently
	// growing it.
	capture := &webhookCapture{}
	srv := capture.server()
	defer srv.Close()

	logger := &AuditLogger{
		Inner:   &fakeAuditLogger{},
		Alerter: New(srv.URL, 80, zap.NewNop()),
	}

	if err := logger.LogTransaction(rail.TransactionRecord{AgentID: "agent-1", Status: "failed"}); err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}
	if capture.count() != 0 {
		t.Fatalf("expected no alert for a \"failed\" transaction, got %d", capture.count())
	}
}

func TestAuditLogger_NoWebhookConfigured_StillLogs(t *testing.T) {
	inner := &fakeAuditLogger{}
	logger := &AuditLogger{
		Inner:   inner,
		Alerter: New("", 80, zap.NewNop()),
	}

	if err := logger.LogTransaction(rail.TransactionRecord{AgentID: "agent-1", Status: "blocked"}); err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}
	if inner.count() != 1 {
		t.Fatalf("inner logger got %d calls, want 1", inner.count())
	}
}

func TestAuditLogger_InnerLoggingError_StillAlertsAndPropagatesError(t *testing.T) {
	capture := &webhookCapture{}
	srv := capture.server()
	defer srv.Close()

	wantErr := errors.New("audit write failed")
	logger := &AuditLogger{
		Inner:   &fakeAuditLogger{err: wantErr},
		Alerter: New(srv.URL, 80, zap.NewNop()),
	}

	err := logger.LogTransaction(rail.TransactionRecord{AgentID: "agent-1", Status: "blocked"})
	if err != wantErr {
		t.Fatalf("LogTransaction error = %v, want %v", err, wantErr)
	}
	assertWebhookCount(t, capture, 1)
}

// assertWebhookCount checks the webhook call count directly rather than
// polling: Alerter.send posts synchronously with no goroutine dispatch, so
// by the time LogTransaction returns, any webhook call it triggers has
// already completed.
func assertWebhookCount(t *testing.T, c *webhookCapture, want int) {
	t.Helper()
	if got := c.count(); got != want {
		t.Fatalf("webhook call count = %d, want %d", got, want)
	}
}

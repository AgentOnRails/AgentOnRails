package audit

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

func newTestLogger(t *testing.T) *SQLiteAuditLogger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := NewSQLiteAuditLogger(path)
	if err != nil {
		t.Fatalf("NewSQLiteAuditLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestLogTransaction(t *testing.T) {
	l := newTestLogger(t)

	tx := x402.TransactionRecord{
		ID:        "test-uuid-1",
		AgentID:   "agent1",
		Timestamp: time.Now().UTC(),
		RailType:  "x402",
		Endpoint:  "https://api.example.com/data",
		Method:    "GET",
		AmountUSD: 0.01,
		AmountRaw: "10000",
		Asset:     "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		Network:   "eip155:8453",
		TxHash:    "0xabc123",
		Status:    "allowed",
		LatencyMS: 42,
	}

	if err := l.LogTransaction(tx); err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}

	txns, err := l.QueryTransactions("agent1", time.Time{}, 10)
	if err != nil {
		t.Fatalf("QueryTransactions: %v", err)
	}
	if len(txns) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(txns))
	}
	got := txns[0]
	if got.ID != tx.ID {
		t.Errorf("ID = %q, want %q", got.ID, tx.ID)
	}
	if got.TxHash != tx.TxHash {
		t.Errorf("TxHash = %q, want %q", got.TxHash, tx.TxHash)
	}
}

func TestSpendSummary(t *testing.T) {
	l := newTestLogger(t)

	for i, status := range []string{"allowed", "allowed", "blocked"} {
		tx := x402.TransactionRecord{
			ID:        fmt.Sprintf("tx-%d", i),
			AgentID:   "agent1",
			Timestamp: time.Now().UTC(),
			RailType:  "x402",
			Endpoint:  "https://api.example.com",
			Method:    "GET",
			AmountUSD: 1.00,
			Status:    status,
		}
		if err := l.LogTransaction(tx); err != nil {
			t.Fatal(err)
		}
	}

	total, err := l.SpendSummary("agent1", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2.00 {
		t.Errorf("SpendSummary = %.2f, want 2.00", total)
	}
}

func TestBudgetRehydration(t *testing.T) {
	l := newTestLogger(t)

	states := []BudgetPeriodState{
		{Period: "daily", SpentCents: 500, ResetAt: time.Now().Add(24 * time.Hour).UTC()},
		{Period: "weekly", SpentCents: 1500, ResetAt: time.Now().Add(7 * 24 * time.Hour).UTC()},
	}

	if err := l.PersistBudget("agent1", states); err != nil {
		t.Fatalf("PersistBudget: %v", err)
	}

	loaded, err := l.RehydrateBudget("agent1")
	if err != nil {
		t.Fatalf("RehydrateBudget: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 periods, got %d", len(loaded))
	}

	byPeriod := make(map[string]BudgetPeriodState)
	for _, s := range loaded {
		byPeriod[s.Period] = s
	}
	if byPeriod["daily"].SpentCents != 500 {
		t.Errorf("daily spent = %d, want 500", byPeriod["daily"].SpentCents)
	}
}

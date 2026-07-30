package audit

import (
	"fmt"
	"testing"
	"time"

	"github.com/agentOnRails/agent-on-rails/rail"
)

func TestVerifyChain_CleanLog_NoBreak(t *testing.T) {
	l := newTestLogger(t)

	for i := range 5 {
		tx := rail.TransactionRecord{
			ID:        idFor(i),
			AgentID:   "agent1",
			Timestamp: time.Now().UTC(),
			RailType:  "x402",
			Endpoint:  "https://api.example.com/data",
			Method:    "GET",
			AmountUSD: 0.01,
			Status:    "allowed",
		}
		if err := l.LogTransaction(tx); err != nil {
			t.Fatalf("LogTransaction: %v", err)
		}
	}

	brk, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brk != nil {
		t.Fatalf("expected a clean chain, got a break at row %d (tx %s)", brk.RowID, brk.TransactionID)
	}
}

func TestVerifyChain_EmptyLog_NoBreak(t *testing.T) {
	l := newTestLogger(t)

	brk, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brk != nil {
		t.Fatalf("expected no break on an empty log, got one at row %d", brk.RowID)
	}
}

func TestVerifyChain_TamperedRow_DetectsBreakAtFirstBadRow(t *testing.T) {
	l := newTestLogger(t)

	for i := range 3 {
		tx := rail.TransactionRecord{
			ID:        idFor(i),
			AgentID:   "agent1",
			Timestamp: time.Now().UTC(),
			RailType:  "x402",
			Endpoint:  "https://api.example.com/data",
			Method:    "GET",
			AmountUSD: 0.01,
			Status:    "allowed",
		}
		if err := l.LogTransaction(tx); err != nil {
			t.Fatalf("LogTransaction: %v", err)
		}
	}

	// Simulate an out-of-band edit (e.g. someone opening the .db file
	// directly) on the second row's amount, without touching its row_hash —
	// exactly what LogTransaction itself never does, since it always
	// computes row_hash from the fields it's about to write.
	if _, err := l.db.Exec(`UPDATE transactions SET amount_usd = 99.99 WHERE id = ?`, idFor(1)); err != nil {
		t.Fatalf("simulate tamper: %v", err)
	}

	brk, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brk == nil {
		t.Fatal("expected VerifyChain to detect the tampered row, got no break")
	}
	if brk.TransactionID != idFor(1) {
		t.Fatalf("break reported at tx %q, want %q (the actually-tampered row)", brk.TransactionID, idFor(1))
	}

	// The row after the tampered one should also fail to verify against it
	// (since its own row_hash was computed from the pre-tamper prevHash) —
	// but VerifyChain should stop at the FIRST break, not report every
	// downstream row too.
}

func TestVerifyChain_DeletedRow_DetectsBreak(t *testing.T) {
	l := newTestLogger(t)

	for i := range 3 {
		tx := rail.TransactionRecord{
			ID:        idFor(i),
			AgentID:   "agent1",
			Timestamp: time.Now().UTC(),
			RailType:  "x402",
			Endpoint:  "https://api.example.com/data",
			Method:    "GET",
			AmountUSD: 0.01,
			Status:    "allowed",
		}
		if err := l.LogTransaction(tx); err != nil {
			t.Fatalf("LogTransaction: %v", err)
		}
	}

	if _, err := l.db.Exec(`DELETE FROM transactions WHERE id = ?`, idFor(1)); err != nil {
		t.Fatalf("simulate deletion: %v", err)
	}

	brk, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brk == nil {
		t.Fatal("expected VerifyChain to detect the gap left by a deleted row, got no break")
	}
	// The surviving row after the deleted one now has a stored row_hash
	// computed against a prevHash that no longer exists in the table.
	if brk.TransactionID != idFor(2) {
		t.Fatalf("break reported at tx %q, want %q (the row after the deleted one)", brk.TransactionID, idFor(2))
	}
}

func TestVerifyChain_LegacyUnhashedRow_NotReportedAsTamper(t *testing.T) {
	l := newTestLogger(t)

	// Insert a row the way a pre-hash-chain version of this code would have
	// (no row_hash) — simulates a database that existed before this column
	// did, upgraded via addColumnIfMissing's backfill-to-'' behavior.
	_, err := l.db.Exec(`
		INSERT INTO transactions
		  (id, agent_id, timestamp, rail_type, endpoint, method, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"legacy-1", "agent1", time.Now().UTC().Unix(), "x402", "https://api.example.com", "GET", "allowed",
	)
	if err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// A normal post-upgrade write follows it.
	if err := l.LogTransaction(rail.TransactionRecord{
		ID: "post-upgrade-1", AgentID: "agent1", Timestamp: time.Now().UTC(),
		RailType: "x402", Endpoint: "https://api.example.com", Method: "GET", Status: "allowed",
	}); err != nil {
		t.Fatalf("LogTransaction: %v", err)
	}

	brk, err := l.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if brk != nil {
		t.Fatalf("a legacy unhashed row must not be reported as a break, got one at row %d (tx %s)", brk.RowID, brk.TransactionID)
	}
}

func TestComputeRowHash_DifferentContent_DifferentHash(t *testing.T) {
	base := rail.TransactionRecord{ID: "a", AgentID: "agent1", Status: "allowed"}
	changed := base
	changed.AmountUSD = 1.23

	if computeRowHash("", base) == computeRowHash("", changed) {
		t.Fatal("expected different content to produce different hashes")
	}
}

func TestComputeRowHash_DifferentPrevHash_DifferentHash(t *testing.T) {
	tx := rail.TransactionRecord{ID: "a", AgentID: "agent1", Status: "allowed"}

	if computeRowHash("prev-a", tx) == computeRowHash("prev-b", tx) {
		t.Fatal("expected different prevHash to produce different hashes for identical content")
	}
}

func idFor(i int) string {
	return fmt.Sprintf("tx-%d", i)
}

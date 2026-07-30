package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/agentOnRails/agent-on-rails/rail"
)

// computeRowHash returns the hex-encoded SHA-256 hash chaining tx to
// prevHash — the row_hash of the transaction immediately before it in
// insertion order, or "" for the first row in a chain. Chaining prevHash
// into every row's hash means a single edited or deleted row breaks every
// row_hash after it, not just its own, which is what lets VerifyChain detect
// tampering anywhere in the log, not only in the most recently written row.
//
// The field order and separator here are the hash format: changing either
// changes what a row hashes to relative to the one before it. That's fine
// going forward (already-written rows keep whatever hash they were written
// with), but must never change retroactively for existing rows.
func computeRowHash(prevHash string, tx rail.TransactionRecord) string {
	h := sha256.New()
	fields := []string{
		prevHash,
		tx.ID,
		tx.AgentID,
		strconv.FormatInt(tx.Timestamp.Unix(), 10),
		tx.RailType,
		tx.Endpoint,
		tx.Method,
		strconv.FormatFloat(tx.AmountUSD, 'f', -1, 64),
		tx.AmountRaw,
		tx.Asset,
		tx.Network,
		tx.TxHash,
		tx.Status,
		tx.BlockReason,
		tx.TaskContext,
		tx.CallerDID,
		strconv.FormatInt(tx.LatencyMS, 10),
	}
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0}) // separator: keeps "ab"+"c" and "a"+"bc" from hashing the same
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ChainBreak describes the first row whose stored row_hash doesn't match
// what its own content plus the row before it should hash to.
type ChainBreak struct {
	RowID         int64
	TransactionID string
	Timestamp     time.Time
	Expected      string
	Stored        string
}

// VerifyChain walks every transaction row in insertion order (SQLite's
// implicit rowid) and recomputes each one's expected row_hash from its own
// fields plus the row before it, returning the first row where the stored
// hash doesn't match. That mismatch is evidence the row itself — or any row
// before it — was edited or deleted outside LogTransaction (e.g. by opening
// the .db file directly), since changing any field of any row changes every
// row_hash chained after it. Returns nil if the whole table verifies clean.
//
// A row with an empty stored row_hash is a legacy row predating this column
// (see migrate's addColumnIfMissing call) — not tampering. It's skipped
// rather than compared against an expected hash, and the chain resets to
// treat the row after it as starting fresh, mirroring how LogTransaction's
// own lastRowHash treats an empty previous hash as "nothing to chain from"
// rather than as a real chained value.
func (a *SQLiteAuditLogger) VerifyChain() (*ChainBreak, error) {
	rows, err := a.db.Query(`
		SELECT rowid, id, agent_id, timestamp, rail_type, endpoint, method,
		       amount_usd, amount_raw, asset, network, tx_hash,
		       status, block_reason, task_context, caller_did, latency_ms,
		       row_hash
		FROM transactions
		ORDER BY rowid ASC`)
	if err != nil {
		return nil, fmt.Errorf("audit: query transactions for verify: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var rowID int64
		var t rail.TransactionRecord
		var tsUnix int64
		var storedHash string
		if err := rows.Scan(
			&rowID, &t.ID, &t.AgentID, &tsUnix, &t.RailType, &t.Endpoint, &t.Method,
			&t.AmountUSD, &t.AmountRaw, &t.Asset, &t.Network, &t.TxHash,
			&t.Status, &t.BlockReason, &t.TaskContext, &t.CallerDID, &t.LatencyMS,
			&storedHash,
		); err != nil {
			return nil, fmt.Errorf("audit: scan row for verify: %w", err)
		}
		t.Timestamp = time.Unix(tsUnix, 0).UTC()

		if storedHash == "" {
			prevHash = ""
			continue
		}

		if expected := computeRowHash(prevHash, t); storedHash != expected {
			return &ChainBreak{
				RowID:         rowID,
				TransactionID: t.ID,
				Timestamp:     t.Timestamp,
				Expected:      expected,
				Stored:        storedHash,
			}, nil
		}
		prevHash = storedHash
	}
	return nil, rows.Err()
}

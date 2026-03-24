// Package audit provides the SQLite-backed audit log for AgentOnRails.
// It implements the x402.AuditLogger interface and also exposes query helpers
// used by the CLI spend/audit commands.
package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// SQLiteAuditLogger writes transaction records to a SQLite database.
type SQLiteAuditLogger struct {
	db *sql.DB
}

// NewSQLiteAuditLogger opens (or creates) the SQLite database at path and
// applies the schema migration. The directory is created if it does not exist.
func NewSQLiteAuditLogger(path string) (*SQLiteAuditLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: migrate: %w", err)
	}

	return &SQLiteAuditLogger{db: db}, nil
}

// Close releases the database connection.
func (a *SQLiteAuditLogger) Close() error { return a.db.Close() }

// LogTransaction implements x402.AuditLogger.
func (a *SQLiteAuditLogger) LogTransaction(tx x402.TransactionRecord) error {
	_, err := a.db.Exec(`
		INSERT INTO transactions
		  (id, agent_id, timestamp, rail_type, endpoint, method,
		   amount_usd, amount_raw, asset, network, tx_hash,
		   status, block_reason, task_context, latency_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tx.ID,
		tx.AgentID,
		tx.Timestamp.Unix(),
		tx.RailType,
		tx.Endpoint,
		tx.Method,
		tx.AmountUSD,
		tx.AmountRaw,
		tx.Asset,
		tx.Network,
		tx.TxHash,
		tx.Status,
		tx.BlockReason,
		tx.TaskContext,
		tx.LatencyMS,
	)
	if err != nil {
		return fmt.Errorf("audit: insert transaction: %w", err)
	}
	return nil
}

// ─── Budget state persistence ──────────────────────────────────────────────────

// BudgetPeriodState holds the persisted spend and reset time for one period.
type BudgetPeriodState struct {
	Period     string
	SpentCents int64
	ResetAt    time.Time
}

// RehydrateBudget returns the current spent amounts for each budget period for
// the given agent, reading from the budget_state table. Returns an empty slice
// if no state has been persisted yet.
func (a *SQLiteAuditLogger) RehydrateBudget(agentID string) ([]BudgetPeriodState, error) {
	rows, err := a.db.Query(`
		SELECT period, spent_cents, reset_at
		FROM budget_state
		WHERE agent_id = ?`, agentID)
	if err != nil {
		return nil, fmt.Errorf("audit: query budget_state: %w", err)
	}
	defer rows.Close()

	var states []BudgetPeriodState
	for rows.Next() {
		var s BudgetPeriodState
		var resetUnix int64
		if err := rows.Scan(&s.Period, &s.SpentCents, &resetUnix); err != nil {
			return nil, err
		}
		s.ResetAt = time.Unix(resetUnix, 0).UTC()
		states = append(states, s)
	}
	return states, rows.Err()
}

// PersistBudget upserts the current spent totals for an agent's budget periods.
// Called by the daemon periodically to ensure restarts don't reset the counters.
func (a *SQLiteAuditLogger) PersistBudget(agentID string, states []BudgetPeriodState) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, s := range states {
		_, err := tx.Exec(`
			INSERT INTO budget_state (agent_id, period, spent_cents, reset_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(agent_id, period) DO UPDATE
			  SET spent_cents = excluded.spent_cents,
			      reset_at    = excluded.reset_at`,
			agentID, s.Period, s.SpentCents, s.ResetAt.Unix(),
		)
		if err != nil {
			return fmt.Errorf("audit: upsert budget_state: %w", err)
		}
	}
	return tx.Commit()
}

// ─── Query helpers for CLI ─────────────────────────────────────────────────────

// TransactionRow is returned by QueryTransactions.
type TransactionRow struct {
	x402.TransactionRecord
}

// QueryTransactions returns recent transactions for agentID, newest first.
// If agentID is empty, transactions for all agents are returned.
// since=0 means no lower bound on timestamp.
func (a *SQLiteAuditLogger) QueryTransactions(agentID string, since time.Time, limit int) ([]x402.TransactionRecord, error) {
	if limit <= 0 {
		limit = 50
	}

	args := []any{}
	where := "WHERE 1=1"

	if agentID != "" {
		where += " AND agent_id = ?"
		args = append(args, agentID)
	}
	if !since.IsZero() {
		where += " AND timestamp >= ?"
		args = append(args, since.Unix())
	}
	args = append(args, limit)

	rows, err := a.db.Query(`
		SELECT id, agent_id, timestamp, rail_type, endpoint, method,
		       amount_usd, amount_raw, asset, network, tx_hash,
		       status, block_reason, task_context, latency_ms
		FROM transactions `+where+`
		ORDER BY timestamp DESC
		LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query transactions: %w", err)
	}
	defer rows.Close()

	var txns []x402.TransactionRecord
	for rows.Next() {
		var t x402.TransactionRecord
		var tsUnix int64
		if err := rows.Scan(
			&t.ID, &t.AgentID, &tsUnix, &t.RailType, &t.Endpoint, &t.Method,
			&t.AmountUSD, &t.AmountRaw, &t.Asset, &t.Network, &t.TxHash,
			&t.Status, &t.BlockReason, &t.TaskContext, &t.LatencyMS,
		); err != nil {
			return nil, err
		}
		t.Timestamp = time.Unix(tsUnix, 0).UTC()
		txns = append(txns, t)
	}
	return txns, rows.Err()
}

// SpendSummary returns total spend in USD for an agent over the given period
// of time (since the given timestamp).
func (a *SQLiteAuditLogger) SpendSummary(agentID string, since time.Time) (float64, error) {
	row := a.db.QueryRow(`
		SELECT COALESCE(SUM(amount_usd), 0)
		FROM transactions
		WHERE agent_id = ? AND status = 'allowed' AND timestamp >= ?`,
		agentID, since.Unix(),
	)
	var total float64
	return total, row.Scan(&total)
}

// ─── Schema migration ──────────────────────────────────────────────────────────

func migrate(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS transactions (
    id           TEXT    NOT NULL PRIMARY KEY,
    agent_id     TEXT    NOT NULL,
    timestamp    INTEGER NOT NULL,
    rail_type    TEXT    NOT NULL,
    endpoint     TEXT    NOT NULL,
    method       TEXT    NOT NULL,
    amount_usd   REAL    NOT NULL DEFAULT 0,
    amount_raw   TEXT    NOT NULL DEFAULT '',
    asset        TEXT    NOT NULL DEFAULT '',
    network      TEXT    NOT NULL DEFAULT '',
    tx_hash      TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL,
    block_reason TEXT    NOT NULL DEFAULT '',
    task_context TEXT    NOT NULL DEFAULT '',
    latency_ms   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_transactions_agent_ts
    ON transactions (agent_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS budget_state (
    agent_id    TEXT    NOT NULL,
    period      TEXT    NOT NULL,
    spent_cents INTEGER NOT NULL DEFAULT 0,
    reset_at    INTEGER NOT NULL,
    PRIMARY KEY (agent_id, period)
);

CREATE TABLE IF NOT EXISTS violations (
    id        TEXT    NOT NULL PRIMARY KEY,
    agent_id  TEXT    NOT NULL,
    timestamp INTEGER NOT NULL,
    rule      TEXT    NOT NULL,
    detail    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_violations_agent_ts
    ON violations (agent_id, timestamp DESC);
`
	_, err := db.Exec(schema)
	return err
}

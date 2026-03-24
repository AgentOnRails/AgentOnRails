-- AgentOnRails audit log schema
-- Applied automatically by NewSQLiteAuditLogger on first open.

CREATE TABLE IF NOT EXISTS transactions (
    id           TEXT    NOT NULL PRIMARY KEY,
    agent_id     TEXT    NOT NULL,
    timestamp    INTEGER NOT NULL,  -- unix seconds
    rail_type    TEXT    NOT NULL,
    endpoint     TEXT    NOT NULL,
    method       TEXT    NOT NULL,
    amount_usd   REAL    NOT NULL DEFAULT 0,
    amount_raw   TEXT    NOT NULL DEFAULT '',
    asset        TEXT    NOT NULL DEFAULT '',
    network      TEXT    NOT NULL DEFAULT '',
    tx_hash      TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL,  -- allowed | blocked | failed
    block_reason TEXT    NOT NULL DEFAULT '',
    task_context TEXT    NOT NULL DEFAULT '',
    latency_ms   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_transactions_agent_ts
    ON transactions (agent_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS budget_state (
    agent_id    TEXT    NOT NULL,
    period      TEXT    NOT NULL,  -- daily | weekly | monthly
    spent_cents INTEGER NOT NULL DEFAULT 0,
    reset_at    INTEGER NOT NULL,  -- unix seconds
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

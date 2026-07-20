// Package rail defines the plugin boundary every AgentOnRails payment rail
// implements — the free x402 rail in this repository, and any commercial
// rail (card, ACH, Lightning/L402) distributed separately. A rail owns one
// payment mechanism: it inspects outbound agent traffic, decides whether and
// how to pay for a resource, enforces its own spend policy, and records what
// happened to the audit log.
package rail

import (
	"context"
	"net/http"
	"time"
)

// Rail proxies an agent's HTTP request, handling any payment challenge the
// upstream returns and enforcing spend policy before money moves.
type Rail interface {
	// ProxyRequest forwards req to its destination, transparently handling
	// any payment challenge, and writes the final response to w.
	// agentID identifies the owning agent for budget/audit purposes; taskContext
	// is a free-form label recorded in the audit log.
	ProxyRequest(ctx context.Context, w http.ResponseWriter, req *http.Request, agentID string, taskContext string)

	// Budget returns the rail's spend tracker, used by the daemon for
	// threshold alerting and startup rehydration from the audit log.
	Budget() *BudgetTracker
}

// AuditLogger is the interface a rail uses to write transaction records.
// Implemented by the SQLite audit backend in the audit package.
type AuditLogger interface {
	LogTransaction(tx TransactionRecord) error
}

// TransactionRecord is written to the audit DB for every request a rail handles.
type TransactionRecord struct {
	ID          string
	AgentID     string
	Timestamp   time.Time
	RailType    string
	Endpoint    string
	Method      string
	AmountUSD   float64
	AmountRaw   string
	Asset       string
	Network     string
	TxHash      string
	Status      string // "allowed" | "blocked" | "failed"
	BlockReason string
	TaskContext string
	LatencyMS   int64
}

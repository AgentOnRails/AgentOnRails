package alert

import "github.com/agentOnRails/agent-on-rails/rail"

// AuditLogger wraps a rail.AuditLogger and additionally fires the matching
// Slack alert for every transaction it logs — AlertBlock for a blocked
// request, AlertTransaction for a settled one. Every rail (x402 today, any
// commercial rail tomorrow) already calls LogTransaction for each outcome,
// so wrapping this one interface wires alerting in for all of them without
// any rail needing to know Alerter exists.
type AuditLogger struct {
	Inner   rail.AuditLogger
	Alerter *Alerter
}

// LogTransaction logs tx via Inner, then best-effort alerts on it — an alert
// failure (or a no-op Alerter with no webhook configured) never affects the
// logged result or its returned error.
func (l *AuditLogger) LogTransaction(tx rail.TransactionRecord) error {
	err := l.Inner.LogTransaction(tx)

	switch tx.Status {
	case "blocked":
		l.Alerter.AlertBlock(tx.AgentID, tx.Endpoint, tx.BlockReason)
	case "allowed":
		l.Alerter.AlertTransaction(tx.AgentID, tx)
	}

	return err
}

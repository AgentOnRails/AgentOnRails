// Package alert sends Slack webhook notifications for AgentOnRails policy events.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402"
)

// Alerter sends notifications to a Slack webhook. All methods are no-ops when
// WebhookURL is empty.
type Alerter struct {
	WebhookURL         string
	BudgetThresholdPct float64 // alert when any budget window exceeds this %
	logger             *zap.Logger
	httpClient         *http.Client
}

// New creates an Alerter. If webhookURL is empty, all alert calls are silently skipped.
func New(webhookURL string, budgetThresholdPct float64, logger *zap.Logger) *Alerter {
	return &Alerter{
		WebhookURL:         webhookURL,
		BudgetThresholdPct: budgetThresholdPct,
		logger:             logger,
		httpClient:         &http.Client{Timeout: 5 * time.Second},
	}
}

// AlertBlock sends a notification when a payment request is blocked by policy.
func (a *Alerter) AlertBlock(agentID, endpoint, reason string) {
	if a.WebhookURL == "" {
		return
	}
	msg := slackMessage{
		Text: fmt.Sprintf(":no_entry: *[AgentOnRails]* Payment blocked\n*Agent:* `%s`\n*Endpoint:* `%s`\n*Reason:* `%s`",
			agentID, endpoint, reason),
	}
	a.send(msg)
}

// AlertBudgetThreshold sends a notification when a budget period crosses the threshold.
// Only fires when pctUsed >= the configured threshold.
func (a *Alerter) AlertBudgetThreshold(agentID, period string, pctUsed float64) {
	if a.WebhookURL == "" || pctUsed < a.BudgetThresholdPct {
		return
	}
	msg := slackMessage{
		Text: fmt.Sprintf(":warning: *[AgentOnRails]* Budget alert\n*Agent:* `%s`\n*Period:* `%s`\n*Used:* `%.1f%%`",
			agentID, period, pctUsed),
	}
	a.send(msg)
}

// AlertTransaction sends a notification for a completed x402 payment.
func (a *Alerter) AlertTransaction(agentID string, tx x402.TransactionRecord) {
	if a.WebhookURL == "" {
		return
	}
	msg := slackMessage{
		Text: fmt.Sprintf(":white_check_mark: *[AgentOnRails]* Payment settled\n*Agent:* `%s`\n*Endpoint:* `%s`\n*Amount:* `$%.4f`\n*Network:* `%s`\n*TxHash:* `%s`",
			agentID, tx.Endpoint, tx.AmountUSD, tx.Network, tx.TxHash),
	}
	a.send(msg)
}

// BudgetThresholdCallback returns a function suitable for use as
// x402.BudgetTracker.OnThreshold. The agentID is captured in the closure.
func (a *Alerter) BudgetThresholdCallback(agentID string) func(period string, pctUsed float64) {
	return func(period string, pctUsed float64) {
		a.AlertBudgetThreshold(agentID, period, pctUsed)
	}
}

// ─── Internal ─────────────────────────────────────────────────────────────────

type slackMessage struct {
	Text string `json:"text"`
}

func (a *Alerter) send(msg slackMessage) {
	body, err := json.Marshal(msg)
	if err != nil {
		a.logger.Warn("slack alert marshal failed", zap.Error(err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.WebhookURL, bytes.NewReader(body))
	if err != nil {
		a.logger.Warn("slack alert request build failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Warn("slack alert send failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.logger.Warn("slack webhook returned non-200", zap.Int("status", resp.StatusCode))
	}
}

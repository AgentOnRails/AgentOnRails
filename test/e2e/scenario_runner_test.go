package e2e

import (
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestScenario_Runner reads all *.yaml files from test/e2e/scenarios/ and
// drives each one against a live daemon instance. This allows policy scenarios
// to be expressed declaratively without writing new Go test code.
func TestScenario_Runner(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	scenariosDir := filepath.Join(filepath.Dir(thisFile), "scenarios")

	matches, err := filepath.Glob(filepath.Join(scenariosDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob scenarios: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("no scenario files found in", scenariosDir)
	}

	for _, path := range matches {
		path := path
		scenario := loadScenario(t, path)

		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()

			opts := daemonOptions{
				PerCallMaxUSD: scenario.Policy.PerCallMaxUSD,
				DailyLimitUSD: scenario.Policy.DailyLimitUSD,
				EndpointMode:  scenario.Policy.EndpointMode,
				AllowedHosts:  scenario.Policy.AllowedHosts,
				SkipPreVerify: true,
			}
			f := startDaemon(t, opts)

			// ── velocity / repeat-loop scenarios ────────────────────────────
			if scenario.RepeatCount > 0 {
				runRepeatScenario(t, f, scenario)
				return
			}

			// ── step-based scenarios ─────────────────────────────────────────
			for i, step := range scenario.Steps {
				// Determine target URL.
				targetURL := f.Upstream.URL + "/paid"
				if step.OverrideURL != "" {
					targetURL = step.OverrideURL
				}

				resp := f.doRequestTo(t, targetURL)
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if step.ExpectStatus != 0 && resp.StatusCode != step.ExpectStatus {
					t.Errorf("step %d (%s): expected HTTP %d, got %d (body: %s)",
						i+1, step.Description, step.ExpectStatus, resp.StatusCode, body)
					continue
				}

				if step.ExpectBodyContains != "" && !contains(string(body), step.ExpectBodyContains) {
					t.Errorf("step %d (%s): body does not contain %q\nbody: %s",
						i+1, step.Description, step.ExpectBodyContains, body)
				}

				if step.ExpectAuditStatus != "" {
					assertAuditStatus(t, f, i+1, step.Description, step.ExpectAuditStatus)
				}

				if step.CheckDailySpentCents > 0 {
					assertDailySpent(t, f, step.CheckDailySpentCents)
				}
			}
		})
	}
}

// runRepeatScenario sends scenario.RepeatCount identical requests and inspects
// only the final response (used for velocity limit tests).
func runRepeatScenario(t *testing.T, f *daemonFixture, scenario ScenarioFile) {
	t.Helper()

	var lastResp *http.Response
	var lastBody []byte

	for i := 0; i < scenario.RepeatCount; i++ {
		resp := f.doRequest(t)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastResp = resp
		lastBody = body
	}

	if scenario.ExpectLastStatus != 0 && lastResp.StatusCode != scenario.ExpectLastStatus {
		t.Errorf("repeat scenario: expected last HTTP %d, got %d (body: %s)",
			scenario.ExpectLastStatus, lastResp.StatusCode, lastBody)
	}

	if scenario.ExpectLastBodyContains != "" && !contains(string(lastBody), scenario.ExpectLastBodyContains) {
		t.Errorf("repeat scenario: last body does not contain %q\nbody: %s",
			scenario.ExpectLastBodyContains, lastBody)
	}
}

// assertAuditStatus polls the audit DB until the most recent transaction for
// the fixture's agent has the expected status (max 2s).
func assertAuditStatus(t *testing.T, f *daemonFixture, stepNum int, desc, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		recs := f.recentTxns(t)
		if len(recs) > 0 {
			got := recs[len(recs)-1].Status
			if got == wantStatus {
				return
			}
			// Keep polling — record may not have been committed yet.
		}
		time.Sleep(50 * time.Millisecond)
	}

	recs := f.recentTxns(t)
	if len(recs) == 0 {
		t.Errorf("step %d (%s): expected audit status %q but no records found", stepNum, desc, wantStatus)
		return
	}
	got := recs[len(recs)-1].Status
	if got != wantStatus {
		t.Errorf("step %d (%s): expected audit status %q, got %q", stepNum, desc, wantStatus, got)
	}
}

// assertDailySpent checks that the total daily spend recorded in the audit DB
// is at least wantCents (1 cent = $0.01).
func assertDailySpent(t *testing.T, f *daemonFixture, wantCents int64) {
	t.Helper()

	recs := f.recentTxns(t)
	var totalCents int64
	for _, r := range recs {
		totalCents += int64(r.AmountUSD * 100)
	}
	if totalCents < wantCents {
		t.Errorf("daily spent: expected at least %d cents, got %d", wantCents, totalCents)
	}
}

func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	return strings.Contains(s, substr)
}

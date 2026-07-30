package rail

import (
	"fmt"
	"sync"
	"time"
)

// BudgetTracker maintains rolling spend windows. All methods are safe for concurrent use.
// It does NOT persist to disk — it is rehydrated from the SQLite audit log at startup.
type BudgetTracker struct {
	mu      sync.Mutex
	windows []budgetWindow

	// OnThreshold is called after a successful Reserve when any window crosses
	// the alert threshold. period and pctUsed are provided for alerting.
	OnThreshold func(period string, pctUsed float64)
}

type budgetWindow struct {
	period     string // "daily" | "weekly" | "monthly"
	limitCents int64
	spentCents int64
	resetAt    time.Time
}

// NewBudgetTracker creates a tracker initialised with the given limits (0 = no limit).
func NewBudgetTracker(dailyLimitCents, weeklyLimitCents, monthlyLimitCents int64) *BudgetTracker {
	now := time.Now().UTC()
	return &BudgetTracker{
		windows: []budgetWindow{
			{
				period:     "daily",
				limitCents: dailyLimitCents,
				spentCents: 0,
				resetAt:    NextDayStart(now),
			},
			{
				period:     "weekly",
				limitCents: weeklyLimitCents,
				spentCents: 0,
				resetAt:    NextWeekStart(now),
			},
			{
				period:     "monthly",
				limitCents: monthlyLimitCents,
				spentCents: 0,
				resetAt:    NextMonthStart(now),
			},
		},
	}
}

// Reserve atomically checks whether amountCents fits in all active windows and,
// if so, debits it. Returns an error naming the first exceeded period.
// If the check fails no debit is applied (all-or-nothing).
func (b *BudgetTracker) Reserve(amountCents int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().UTC()
	for i := range b.windows {
		w := &b.windows[i]
		if now.After(w.resetAt) {
			w.spentCents = 0
			switch w.period {
			case "daily":
				w.resetAt = NextDayStart(now)
			case "weekly":
				w.resetAt = NextWeekStart(now)
			case "monthly":
				w.resetAt = NextMonthStart(now)
			}
		}
		if w.limitCents > 0 && w.spentCents+amountCents > w.limitCents {
			return fmt.Errorf("%s budget exceeded: spent %d + %d > limit %d (cents)",
				w.period, w.spentCents, amountCents, w.limitCents)
		}
	}

	for i := range b.windows {
		b.windows[i].spentCents += amountCents
	}

	// Fire threshold callbacks after the debit.
	if b.OnThreshold != nil {
		for _, w := range b.windows {
			if w.limitCents > 0 {
				pct := float64(w.spentCents) / float64(w.limitCents) * 100
				b.OnThreshold(w.period, pct)
			}
		}
	}

	return nil
}

// Refund subtracts amountCents from all windows without performing a limit check.
// Used to undo a Reserve when a payment fails after signing.
func (b *BudgetTracker) Refund(amountCents int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.windows {
		b.windows[i].spentCents -= amountCents
		if b.windows[i].spentCents < 0 {
			b.windows[i].spentCents = 0
		}
	}
}

// SpentThisPeriod returns the current spend for the named period.
func (b *BudgetTracker) SpentThisPeriod(period string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, w := range b.windows {
		if w.period == period {
			return w.spentCents
		}
	}
	return 0
}

// Seed sets the initial spent value for a period (used during startup rehydration).
func (b *BudgetTracker) Seed(period string, spentCents int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.windows {
		if b.windows[i].period == period {
			b.windows[i].spentCents = spentCents
			return
		}
	}
}

// BudgetSnapshot is a point-in-time copy of one budget window, used for
// persistence across daemon restarts.
type BudgetSnapshot struct {
	Period     string
	SpentCents int64
	ResetAt    time.Time
}

// Snapshot returns the current state of all budget windows. Safe for concurrent use.
func (b *BudgetTracker) Snapshot() []BudgetSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]BudgetSnapshot, len(b.windows))
	for i, w := range b.windows {
		out[i] = BudgetSnapshot{Period: w.period, SpentCents: w.spentCents, ResetAt: w.resetAt}
	}
	return out
}

// DayStart returns the start (UTC midnight) of t's calendar day.
func DayStart(t time.Time) time.Time {
	return t.UTC().Truncate(24 * time.Hour)
}

// NextDayStart returns the start of the calendar day after t's.
func NextDayStart(t time.Time) time.Time {
	return DayStart(t).Add(24 * time.Hour)
}

// CurrentWeekStart returns the start (UTC midnight Monday) of t's week.
func CurrentWeekStart(t time.Time) time.Time {
	return NextWeekStart(t).Add(-7 * 24 * time.Hour)
}

// NextWeekStart returns the start (UTC midnight Monday) of the week after t's.
func NextWeekStart(t time.Time) time.Time {
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	daysUntilMonday := 8 - weekday
	return t.Truncate(24 * time.Hour).Add(time.Duration(daysUntilMonday) * 24 * time.Hour)
}

// CurrentMonthStart returns the start (UTC midnight, day 1) of t's calendar month.
func CurrentMonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}

// NextMonthStart returns the start of the calendar month after t's.
func NextMonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
}

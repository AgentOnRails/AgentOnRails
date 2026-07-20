package rail

import "testing"

func TestBudgetTracker_Reserve_WithinLimit(t *testing.T) {
	bt := NewBudgetTracker(1000, 5000, 10000)

	if err := bt.Reserve(100); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if bt.SpentThisPeriod("daily") != 100 {
		t.Errorf("daily spent = %d, want 100", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_Reserve_ExceedsDaily(t *testing.T) {
	bt := NewBudgetTracker(100, 0, 0)

	if err := bt.Reserve(50); err != nil {
		t.Fatal(err)
	}
	if err := bt.Reserve(60); err == nil {
		t.Error("expected error when daily budget exceeded")
	}
	// Verify no partial debit on failure
	if bt.SpentThisPeriod("daily") != 50 {
		t.Errorf("daily spent = %d after failed reserve, want 50", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_Reserve_ExceedsWeekly(t *testing.T) {
	bt := NewBudgetTracker(10000, 100, 0)

	_ = bt.Reserve(80)
	if err := bt.Reserve(30); err == nil {
		t.Error("expected error when weekly budget exceeded")
	}
}

func TestBudgetTracker_Reserve_NoLimit(t *testing.T) {
	bt := NewBudgetTracker(0, 0, 0) // zero limits = unlimited

	for i := 0; i < 100; i++ {
		if err := bt.Reserve(1000000); err != nil {
			t.Fatalf("unexpected error with no limits: %v", err)
		}
	}
}

func TestBudgetTracker_Refund(t *testing.T) {
	bt := NewBudgetTracker(1000, 0, 0)

	_ = bt.Reserve(500)
	bt.Refund(500)

	if bt.SpentThisPeriod("daily") != 0 {
		t.Errorf("daily spent after refund = %d, want 0", bt.SpentThisPeriod("daily"))
	}

	// After refund, we should be able to reserve again
	if err := bt.Reserve(900); err != nil {
		t.Errorf("reserve after refund failed: %v", err)
	}
}

func TestBudgetTracker_Refund_FloorAtZero(t *testing.T) {
	bt := NewBudgetTracker(1000, 0, 0)

	bt.Refund(999) // Refund without prior reserve — should not go negative
	if bt.SpentThisPeriod("daily") != 0 {
		t.Errorf("daily spent should not go below 0, got %d", bt.SpentThisPeriod("daily"))
	}
}

func TestBudgetTracker_OnThreshold(t *testing.T) {
	bt := NewBudgetTracker(100, 0, 0)

	var fired []float64
	bt.OnThreshold = func(period string, pctUsed float64) {
		if period == "daily" {
			fired = append(fired, pctUsed)
		}
	}

	_ = bt.Reserve(90) // 90%
	if len(fired) == 0 {
		t.Error("threshold callback not fired")
	}
	if fired[0] < 89 || fired[0] > 91 {
		t.Errorf("pctUsed = %.1f, want ~90.0", fired[0])
	}
}

func TestBudgetTracker_Seed(t *testing.T) {
	bt := NewBudgetTracker(1000, 0, 0)

	bt.Seed("daily", 700)
	if bt.SpentThisPeriod("daily") != 700 {
		t.Errorf("daily spent after seed = %d, want 700", bt.SpentThisPeriod("daily"))
	}
	// Reserve should now be constrained
	if err := bt.Reserve(400); err == nil {
		t.Error("expected budget exceeded error after seed")
	}
}

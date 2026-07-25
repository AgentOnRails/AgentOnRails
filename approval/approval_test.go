package approval

import (
	"context"
	"testing"
	"time"
)

func TestAwait_ResolvedApproved(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	var approved bool
	var err error

	go func() {
		approved, err = r.Await(context.Background(), Request{AgentID: "a", RailType: "x402", AmountCents: 500}, time.Second)
		close(done)
	}()

	waitForPending(t, r, 1)
	pending := r.List()
	if err := r.Resolve(pending[0].ID, true); err != nil {
		t.Fatal(err)
	}
	<-done

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !approved {
		t.Error("expected approved=true")
	}
	if got := len(r.List()); got != 0 {
		t.Errorf("expected the entry to be removed after resolution, got %d pending", got)
	}
}

func TestAwait_ResolvedDenied(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	var approved bool

	go func() {
		approved, _ = r.Await(context.Background(), Request{AgentID: "a"}, time.Second)
		close(done)
	}()

	waitForPending(t, r, 1)
	pending := r.List()
	if err := r.Resolve(pending[0].ID, false); err != nil {
		t.Fatal(err)
	}
	<-done

	if approved {
		t.Error("expected approved=false")
	}
}

func TestAwait_Timeout(t *testing.T) {
	r := NewRegistry()
	approved, err := r.Await(context.Background(), Request{AgentID: "a"}, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if approved {
		t.Error("expected approved=false on timeout")
	}
	if got := len(r.List()); got != 0 {
		t.Errorf("expected the entry to be cleaned up after timeout, got %d pending", got)
	}
}

func TestAwait_ContextCancelled(t *testing.T) {
	r := NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error

	go func() {
		_, err = r.Await(ctx, Request{AgentID: "a"}, time.Minute)
		close(done)
	}()

	waitForPending(t, r, 1)
	cancel()
	<-done

	if err == nil {
		t.Error("expected a cancellation error")
	}
}

func TestAwait_DefaultTimeoutUsedWhenZeroOrNegative(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	go func() {
		r.Await(context.Background(), Request{AgentID: "a"}, 0) //nolint:errcheck
		close(done)
	}()
	waitForPending(t, r, 1)
	pending := r.List()
	if err := r.Resolve(pending[0].ID, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Await did not return promptly after Resolve")
	}
}

func TestResolve_UnknownID(t *testing.T) {
	r := NewRegistry()
	if err := r.Resolve("does-not-exist", true); err == nil {
		t.Error("expected an error resolving an unknown ID")
	}
}

func TestResolve_DoubleResolveDoesNotPanic(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	go func() {
		r.Await(context.Background(), Request{AgentID: "a"}, time.Second) //nolint:errcheck
		close(done)
	}()
	waitForPending(t, r, 1)
	pending := r.List()
	id := pending[0].ID

	if err := r.Resolve(id, true); err != nil {
		t.Fatal(err)
	}
	<-done // ensure Await has consumed the first decision and cleaned up

	// A second Resolve after cleanup should report "unknown," not panic.
	if err := r.Resolve(id, false); err == nil {
		t.Error("expected the second resolve to report the ID as unknown")
	}
}

func TestList_OrderedOldestFirst(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{}, 3)
	for i := range 3 {
		go func(n int) {
			r.Await(context.Background(), Request{AgentID: "a", AmountCents: int64(n)}, time.Second) //nolint:errcheck
			done <- struct{}{}
		}(i)
		time.Sleep(5 * time.Millisecond) // stagger CreatedAt
	}
	waitForPending(t, r, 3)

	list := r.List()
	for i := 1; i < len(list); i++ {
		if list[i-1].CreatedAt.After(list[i].CreatedAt) {
			t.Errorf("List is not ordered oldest-first: %v", list)
		}
	}

	for _, p := range list {
		r.Resolve(p.ID, true) //nolint:errcheck
	}
	for range 3 {
		<-done
	}
}

func TestList_ReturnsSnapshotNotLiveView(t *testing.T) {
	r := NewRegistry()
	done := make(chan struct{})
	go func() {
		r.Await(context.Background(), Request{AgentID: "a"}, time.Second) //nolint:errcheck
		close(done)
	}()
	waitForPending(t, r, 1)

	snapshot := r.List()
	if err := r.Resolve(snapshot[0].ID, true); err != nil {
		t.Fatal(err)
	}
	<-done

	if len(snapshot) != 1 {
		t.Fatalf("sanity: expected 1 entry in the snapshot, got %d", len(snapshot))
	}
	if got := len(r.List()); got != 0 {
		t.Errorf("expected a fresh List() call to reflect the resolution, got %d pending", got)
	}
}

// waitForPending polls until the registry has exactly n pending entries or
// fails the test — Await registers its entry from a goroutine, so tests
// need to wait for that registration before calling List/Resolve.
func waitForPending(t *testing.T, r *Registry, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(r.List()) == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending entries, got %d", n, len(r.List()))
}

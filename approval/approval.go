// Package approval implements a shared, rail-agnostic pending-approval
// registry: any rail whose policy requires human sign-off above a spend
// threshold (x402's require_approval_above_usd today) registers a request
// here and blocks until it's approved, denied, or times out, instead of
// failing closed with no path to ever succeed. See CHANGELOG.md's [0.1.0]
// entry for why this exists: RequireApprovalAboveCents was fully parsed and
// enforced but had nowhere to route a pending decision to, so it failed
// closed permanently whenever configured — this is that missing route.
//
// The daemon's control API (daemon/control.go) resolves entries through
// this same Registry, so approving a request via
// POST /control/approvals/{id}/approve unblocks the exact goroutine still
// holding the agent's original HTTP request open in Await.
package approval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultTimeout is used when a caller passes timeout <= 0 to Await.
const DefaultTimeout = 5 * time.Minute

// Request describes one payment awaiting human approval. Rail-agnostic on
// purpose — RailType is a free-form label (e.g. "x402", "card") for
// display, not a type switch anything branches on.
type Request struct {
	AgentID     string
	RailType    string
	Endpoint    string
	AmountCents int64
	TaskContext string
}

// Pending is one entry in the registry, as returned by List — a Request
// plus its assigned ID and when it was created.
type Pending struct {
	Request
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// entry is Pending plus the private machinery Resolve/Await use to hand
// off the decision. Never exposed outside this package.
type entry struct {
	Pending
	decision chan bool
	once     sync.Once
}

// resolve sends approved down decision exactly once; later calls are a
// silent no-op (protects against a duplicate approve+deny race resolving
// twice and panicking on a closed channel).
func (e *entry) resolve(approved bool) {
	e.once.Do(func() {
		e.decision <- approved
		close(e.decision)
	})
}

// Registry tracks payments currently awaiting human approval. Safe for
// concurrent use — one Registry is shared by every agent's rail on a
// daemon, via rail.FactoryParams.Approvals.
type Registry struct {
	mu      sync.Mutex
	pending map[string]*entry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{pending: make(map[string]*entry)}
}

// Await registers req and blocks until Resolve is called for its assigned
// ID, ctx is cancelled, or timeout elapses (DefaultTimeout if timeout <= 0)
// — whichever comes first. The entry is removed from the registry before
// Await returns either way, so List never shows a request that can no
// longer be resolved. A timeout or cancelled context returns approved=false
// with a descriptive error, matching ApprovalFunc's existing contract
// (an error means "treat as not approved," not "crash the request").
func (r *Registry) Await(ctx context.Context, req Request, timeout time.Duration) (approved bool, err error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	id := uuid.NewString()
	e := &entry{
		Pending:  Pending{Request: req, ID: id, CreatedAt: time.Now().UTC()},
		decision: make(chan bool, 1),
	}

	r.mu.Lock()
	r.pending[id] = e
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, id)
		r.mu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case approved := <-e.decision:
		return approved, nil
	case <-timer.C:
		return false, fmt.Errorf("approval: request %s timed out after %s with no response", id, timeout)
	case <-ctx.Done():
		return false, fmt.Errorf("approval: request %s cancelled: %w", id, ctx.Err())
	}
}

// List returns every currently pending request, oldest first. Safe to call
// from an HTTP handler — returns a snapshot, not a live view.
func (r *Registry) List() []Pending {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Pending, 0, len(r.pending))
	for _, e := range r.pending {
		out = append(out, e.Pending)
	}
	// Oldest first — a human approving a queue wants to see what's been
	// waiting longest at the top, not registry-map iteration order.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].CreatedAt.After(out[j].CreatedAt); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Resolve delivers a human decision for the pending request identified by
// id. Returns an error if id is unknown — already resolved (by a prior
// Resolve call, or because it already timed out) is indistinguishable from
// never having existed, which is the right behavior for a caller: either
// way, there is nothing left here to resolve.
func (r *Registry) Resolve(id string, approved bool) error {
	r.mu.Lock()
	e, ok := r.pending[id]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("approval: no pending request with id %q", id)
	}
	e.resolve(approved)
	return nil
}

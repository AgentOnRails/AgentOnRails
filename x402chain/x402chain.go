// Package x402chain exposes a minimal, non-internal way to ask "does this
// CAIP-2 network have a real chainsign.Signer behind it?" — the question
// aor-pro doctor needs answered but cannot ask directly, since
// internal/rail/x402/chainsign sits under this module's internal/ tree and
// Go's internal-import rule blocks any package outside
// github.com/agentOnRails/agent-on-rails, including the separate aor-pro
// module (agent-on-rails-private), from importing it even via the local
// replace directive that links the two repos during development.
//
// Supported reflects the chainsign registry as it actually stands at
// runtime, populated by the same transitive imports (via the daemon
// package) that make rails.x402.preferred_chain work when the daemon
// really starts — so this can never drift from what aor-pro start would
// actually do with the same network value.
package x402chain

import (
	"strings"

	"github.com/agentOnRails/agent-on-rails/internal/rail/x402/chainsign"
)

// Namespace returns the namespace portion of a CAIP-2 identifier (the part
// before the first colon, e.g. "eip155" from "eip155:8453").
func Namespace(network string) string {
	if ns, _, ok := strings.Cut(network, ":"); ok {
		return ns
	}
	return network
}

// Supported reports whether a chainsign.Signer is registered for network's
// CAIP-2 namespace.
func Supported(network string) bool {
	_, ok := chainsign.Get(Namespace(network))
	return ok
}

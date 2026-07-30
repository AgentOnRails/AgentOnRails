package chainsign

// registry maps a CAIP-2 namespace to the Signer that handles it. Mirrors
// rail/registry.go's Register/Get pattern exactly, one level down (chain
// families within x402, not rails within the daemon).
var registry = map[string]Signer{}

// Register makes s available under its own Namespace() for signPayment to
// look up by a payment requirement's network. Intended to be called from a
// concrete Signer implementation's init(), the same way rail.Register is
// called from a rail package's init().
func Register(s Signer) {
	registry[s.Namespace()] = s
}

// Get looks up a registered Signer by CAIP-2 namespace (e.g. "eip155").
func Get(namespace string) (Signer, bool) {
	s, ok := registry[namespace]
	return s, ok
}

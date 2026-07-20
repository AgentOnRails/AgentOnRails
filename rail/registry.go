package rail

import (
	"gopkg.in/yaml.v3"

	"github.com/agentOnRails/agent-on-rails/internal/config"
	"github.com/agentOnRails/agent-on-rails/vault"

	"go.uber.org/zap"
)

// FactoryParams carries everything a rail's Factory needs to build itself for
// one agent: its own raw config block plus the shared daemon-level dependencies
// (vault, audit log, logger) every rail draws on.
type FactoryParams struct {
	AgentID    string
	RawConfig  yaml.Node // this agent's rails.<name> block, undecoded
	Global     *config.GlobalConfig
	Vault      *vault.Vault
	Passphrase string
	Audit      AuditLogger
	Logger     *zap.Logger
}

// Factory builds a Rail for one agent from FactoryParams. It returns
// enabled=false (with a nil Rail and nil error) when the rail's config marks
// it disabled, so the caller can skip it without treating that as a failure.
type Factory func(params FactoryParams) (r Rail, enabled bool, err error)

var registry = map[string]Factory{}

// Register makes a rail Factory available under name (e.g. "x402") for
// daemon config to reference via an agent's rails.<name> block. Intended to
// be called from a rail package's init().
func Register(name string, factory Factory) {
	registry[name] = factory
}

// Get looks up a registered rail Factory by name.
func Get(name string) (Factory, bool) {
	f, ok := registry[name]
	return f, ok
}

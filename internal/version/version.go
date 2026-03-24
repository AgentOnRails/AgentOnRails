// Package version holds the build-time version string for AgentOnRails.
// It is set at link time via:
//
//	go build -ldflags "-X github.com/agentOnRails/agent-on-rails/internal/version.Version=v0.1.0"
package version

// Version is the current release version. Defaults to "dev" for local builds.
var Version = "dev"

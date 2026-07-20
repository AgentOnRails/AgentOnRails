# Contributing to AgentOnRails

## Local development setup

```bash
git clone https://github.com/agentOnRails/agent-on-rails
cd agent-on-rails
go mod download
go build ./...
```

Requires Go 1.24+.

## Running tests

```bash
# Unit tests
go test $(go list ./... | grep -v /test/e2e) -count=1 -race

# Integration tests (uses mock servers — no external services required)
go test ./test/integration/ -v -count=1 -timeout=120s

# Base Sepolia end-to-end (requires a funded testnet wallet)
TEST_SEPOLIA=1 AOR_TEST_PRIVATE_KEY=0x... go test ./test/e2e/ -run TestSepolia -v
```

## Project structure

```
rail/                 — Rail plugin interface + registry (public plugin boundary)
config/               — YAML config loading and validation (public)
vault/                — AES-256-GCM encrypted wallet key storage (public)
daemon/               — HTTP proxy daemon (per-agent server lifecycle, public)
internal/rail/x402/   — x402 payment rail (EIP-3009 signing, proxy logic)
internal/audit/       — SQLite audit log
internal/alert/       — Slack webhook notifications
cmd/aor/              — CLI (Cobra)
test/integration/     — Integration tests (guarded by TEST_INTEGRATION=1)
configs/              — Example configuration files
```

## Submitting changes

1. Fork the repo and create a branch from `main`
2. Add tests for any new behaviour
3. Ensure `go test ./internal/... -race` passes
4. Ensure `go vet ./...` passes with no issues
5. Open a pull request against `main`

## Adding a new payment rail

1. Create `internal/rail/<name>/rail.go` implementing the `rail.Rail` interface
   (`rail/rail.go`) and a `rail.Factory` (`rail/registry.go`)
2. Register the factory under a unique name from an `init()` in your rail
   package (`rail.Register("<name>", Factory)`) — the daemon discovers rails
   by name from each agent's `rails.<name>` YAML block, so nothing in
   `daemon/daemon.go` needs to change
3. Add integration tests in `test/integration/`
4. Update the README roadmap checkbox

See `internal/rail/x402/rail.go` and `internal/rail/x402/factory.go` as the
reference implementation.

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
go test ./internal/... -count=1 -race

# Integration tests (uses mock servers — no external services required)
go test ./test/integration/ -v -count=1 -timeout=120s

# Base Sepolia end-to-end (requires a funded testnet wallet)
TEST_SEPOLIA=1 AOR_TEST_PRIVATE_KEY=0x... go test ./test/e2e/ -run TestSepolia -v
```

## Project structure

```
internal/rail/x402/   — x402 payment rail (EIP-3009 signing, proxy logic)
internal/config/      — YAML config loading and validation
internal/vault/       — AES-256-GCM encrypted wallet key storage
internal/audit/       — SQLite audit log
internal/alert/       — Slack webhook notifications
internal/daemon/      — HTTP proxy daemon (per-agent server lifecycle)
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

1. Create `internal/rail/<name>/rail.go` implementing `AuditLogger` consumer pattern
2. Add rail config struct to `internal/config/schema.go` under `RailsConfig`
3. Wire the rail in `internal/daemon/daemon.go`
4. Add integration tests in `test/integration/`
5. Update the README roadmap checkbox

See `internal/rail/x402/rail.go` as the reference implementation.

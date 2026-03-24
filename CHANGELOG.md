# Changelog

All notable changes to AgentOnRails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-24

### Added
- x402 payment rail: transparent HTTP proxy with EIP-3009 signing
- Per-agent spend guardrails: daily/weekly/monthly budgets, per-call maximum
- Velocity limiter: configurable max requests per minute/hour with cooldown
- Endpoint policy: open / allowlist / blocklist modes
- Network allowlist: restrict payments to specific CAIP-2 chains
- Human approval gate: `require_approval_above_usd` with pluggable `ApprovalFunc`
- AES-256-GCM wallet vault with scrypt key derivation
- SQLite audit log with `aor audit` and `aor spend` CLI commands
- `aor logs tail` for real-time transaction streaming
- `aor init` and `aor agents create` interactive setup wizard
- Slack webhook alerts for blocked payments and budget threshold crossings
- Facilitator pre-verification (`/verify`) before retrying signed requests
- Budget state persistence across daemon restarts via SQLite `budget_state` table
- Supported networks: Base, Ethereum, Optimism, Arbitrum One, Polygon, Base Sepolia
- Local x402-compliant test server (`scripts/testserver`) for end-to-end development
- GitHub Actions CI: unit tests with race detector, staticcheck, build verification

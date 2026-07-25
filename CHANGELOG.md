# Changelog

All notable changes to AgentOnRails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-25

### Added
- x402 payment rail: transparent HTTP proxy with EIP-3009 signing, speaking
  both the V1 `X-PAYMENT` and V2 `PAYMENT-SIGNATURE` protocol variants
- Non-x402 HTTP 402 passthrough (Stripe, Cloudflare, Vercel, and other
  non-x402 APIs reach the agent as-is instead of a 502)
- MCP server mode (`aor mcp`): `request_payment`/`get_balance`/
  `get_spend_history`/`get_policy` tools for Claude Desktop, Claude Code,
  Cursor, and any MCP-compatible client — no HTTP proxy or CA required
- HTTPS interception (`https_intercept`) with a local CA for payment
  handling on HTTPS upstreams through the transparent proxy; `aor run` and
  `aor trust install/uninstall` manage trust for it
- Per-agent spend guardrails: daily/weekly/monthly budgets, per-call maximum
- Velocity limiter: configurable max requests per minute/hour with cooldown
- Endpoint policy: open / allowlist / blocklist modes
- Network allowlist: restrict payments to specific CAIP-2 chains
- Human approval gate: `require_approval_above_usd`, backed by a real
  localhost control API (`GET/POST /control/approvals`, `/control/agents/
  {id}/pause|resume|policy`) — a held payment can now actually be
  approved, denied, or timed out, not just configured
- "upto" x402 scheme support with Permit2 preflight, for servers that
  authorize a maximum and settle actual usage afterward
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

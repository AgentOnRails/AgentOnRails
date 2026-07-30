# Changelog

All notable changes to AgentOnRails are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-30

### Added
- Solana support for the x402 rail, via a new pluggable chain-signer
  registry (`internal/rail/x402/chainsign`) that splits chain-specific
  signing out of the core rail: `chainsign/eip155` (existing EVM/EIP-712
  path) and `chainsign/solana` (ed25519, SPL `TransferChecked`, live
  blockhash fetch). New `key_type` config (`ecdsa`/`ed25519`),
  `aor credentials set-wallet --key-type`, and `aor agents create` now
  prompts for Solana mainnet/devnet alongside the existing EVM chains.
  Solana's signing model has one real difference from every EVM chain
  here: EIP-3009 is gasless, but a Solana transaction always needs a fee
  payer, so a Solana-keyed agent's wallet needs its own small SOL balance
  for network fees.
- Cross-language e2e proof that budget enforcement holds identically for
  curl/Python/Node clients hitting the proxy, not just Go's own client.
- Tamper-evident, hash-chained audit log (`internal/audit/hashchain.go`):
  every row chains to the previous row's hash; `aor audit verify` checks
  the chain end to end.
- `internal/bootstrap`: extracted the wallet/config bootstrap and
  testnet-funding-wait logic `scripts/demo` already used into a reusable
  package, now shared by the new `scripts/hermes-quickstart` partner
  integration path (`docs/hermes-integration.md`).
- Windows install script (`scripts/install.ps1`).

### Changed
- **`aor mcp` no longer bypasses policy controls.** Previously, MCP mode
  built its own independent in-process x402 rail — decrypting the wallet
  key and tracking its own budget state separately from whatever `aor
  start`'s daemon was enforcing. A payment made through MCP could clear
  even if the equivalent daemon-side agent was paused, or its policy had
  just been reloaded, because MCP never talked to the daemon at all. Now
  `aor mcp` is a pure HTTP client of the daemon's own proxy for
  `request_payment` — it no longer decrypts the wallet key or tracks
  budget itself, so `aor start` must already be running or
  `request_payment` fails with a clear error instead of paying under a
  separate, unenforced policy engine. `--passphrase`/`AOR_PASSPHRASE` are
  no longer needed by `aor mcp` as a result. `get_balance`/
  `get_spend_history`/`get_policy` are unaffected — they read the shared
  audit log and config directly and still work with the daemon down.
  HTTPS-paid endpoints through MCP now depend on the daemon's
  `daemon.https_intercept: true` (a warning is printed, not an error, if
  it's off). Remaining, honestly-documented scope limit: this doesn't stop
  an agent with its own separate shell/browser/HTTP tool from bypassing
  these MCP tools entirely for a given call — that needs network-level
  egress lockdown, not this fix (see the README's proxy-vs-MCP scope
  table).
- `scripts/hermes-quickstart` now starts `aor start` in the background
  (enabling `https_intercept` on a freshly-created config) before handing
  off to `aor mcp`, since the latter can no longer function standalone.

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

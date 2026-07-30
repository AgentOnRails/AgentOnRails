# AgentOnRails

**Per-agent payment guardrails for AI agents.** A local-first proxy daemon that sits between your AI agents and payment-enabled APIs, enforcing per-agent spend policies over the [x402 protocol](https://github.com/coinbase/x402).

```
AI agent → http://localhost:8402 → [AgentOnRails] → https://paid-api.example.com
                                        ↑
                            policy check + EIP-3009 sign
                                        ↓
                          x402.org facilitator (operated by Coinbase)
```

## What it does

- **Transparent proxy** — agents point their HTTP client at a local port; no SDK changes required
- **MCP server** — exposes payment tools (`request_payment`, `get_balance`, `get_spend_history`, `get_policy`) to Claude Desktop, Claude Code, Cursor, and any MCP-compatible agent
- **x402 payment rail** — automatically handles HTTP 402 Payment Required challenges: signs EIP-3009 authorizations, pre-verifies with the facilitator, and retries the request. Speaks both x402 protocol variants — the V1 `X-PAYMENT` header format and the newer `PAYMENT-SIGNATURE` header format — replying in whichever the server used
- **Non-x402 402 passthrough** — plain HTTP 402 responses from Stripe, Cloudflare, Vercel, and other non-x402 APIs are forwarded transparently to the agent instead of being replaced with a 502
- **Spend guardrails** — per-agent daily/weekly/monthly budgets, per-call maximums, velocity limits, endpoint allowlists/blocklists
- **Human approval gate** — hold any payment above a configurable amount (`require_approval_above_usd`) for a yes/no from a local control API instead of paying it automatically
- **Encrypted wallet vault** — private keys never touch disk unencrypted; AES-256-GCM + scrypt
- **Audit log** — every transaction written to SQLite; queryable with `aor audit` and `aor spend`

## Supported networks

Chain support is pluggable (`internal/rail/x402/chainsign`) — adding a new
chain family means registering a signer, not forking the rail. Every chain
below has a real, tested signer behind it (not just an allowlist entry).

| Chain | CAIP-2 | Asset address | `key_type` |
|-------|--------|--------------|------------|
| Base | `eip155:8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | `ecdsa` (default) |
| Ethereum Mainnet | `eip155:1` | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | `ecdsa` (default) |
| Optimism | `eip155:10` | `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85` | `ecdsa` (default) |
| Arbitrum One | `eip155:42161` | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` | `ecdsa` (default) |
| Polygon | `eip155:137` | `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` | `ecdsa` (default) |
| Base Sepolia (testnet) | `eip155:84532` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | `ecdsa` (default) |
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | `ed25519` |
| Solana Devnet (testnet) | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` | `ed25519` |

EVM chains use EIP-3009 (`ecdsa` wallets); Solana uses SPL Token
`TransferChecked` (`ed25519` wallets, base58 addresses). `aor agents create`
and `aor credentials set-wallet --key-type ed25519` handle the distinction
for you — see [Create your first agent](#3-create-your-first-agent).

Solana's signing model has one real difference from every EVM chain here:
EIP-3009 is gasless, but a Solana transaction always needs a fee payer, so a
Solana-keyed agent's wallet needs a small SOL balance for network fees (and,
the first time it pays a given recipient, one-time token-account rent) —
not just USDC.

---

## Quick start

### Prerequisites

- A wallet private key (ECDSA / secp256k1 — the same key format used by Ethereum)
- USDC on a [supported network](#supported-networks) — or Base Sepolia USDC for testing (free from the [Circle faucet](https://faucet.circle.com))

### 1. Install

```bash
# macOS via Homebrew (recommended for Mac users)
brew tap agentOnRails/tap
brew install aor

# macOS / Linux (one-liner)
curl -sf https://raw.githubusercontent.com/agentOnRails/agent-on-rails/main/scripts/install.sh | sh

# From source
go install github.com/agentOnRails/agent-on-rails/cmd/aor@latest
```

### 2. Init

```bash
aor init
```

Creates `~/.aor/` with a default config and the right directory structure. Safe to re-run.

### 3. Create your first agent

```bash
aor agents create
```

An interactive wizard walks you through:

```
Creating a new agent configuration.

  Agent ID [my-agent]:
  Proxy port [8402]:

  1) Base mainnet      (eip155:8453)  ← recommended
  2) Ethereum mainnet  (eip155:1)
  3) Optimism          (eip155:10)
  4) Arbitrum One      (eip155:42161)
  5) Polygon           (eip155:137)
  6) Base Sepolia      (eip155:84532)  ← testnet
  7) Solana mainnet    (solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp)
  8) Solana devnet     (solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1)  ← testnet

  Preferred chain [1]: 1
  Wallet address (0x...): 0xYOUR_WALLET
  Daily spend limit (USD, 0 = unlimited) [5.00]:
  Per-call maximum  (USD, 0 = unlimited) [0.10]:
  Endpoint mode [open]:

Written ~/.aor/agents/my-agent.yaml

  Store encrypted wallet key now? [Y]: y
  Enter private key (hex, no echo): ••••••••
  Enter vault passphrase: ••••••••

Next steps:
  export AOR_PASSPHRASE="your vault passphrase"
  aor start
  export HTTP_PROXY=http://localhost:8402
  aor logs tail
```

### 4. Start

```bash
export AOR_PASSPHRASE="your vault passphrase"
aor start
```

### 5. Point your agent at the proxy

```bash
export HTTP_PROXY=http://localhost:8402
export HTTPS_PROXY=http://localhost:8402
```

That's it. Any HTTP client that respects standard proxy env vars works — Python `httpx`/`requests`, Node `fetch`, `curl`, LangChain, CrewAI, etc. No SDK changes required.

**Verified, not just claimed:** `test/e2e/client_compat_test.go` drives one real payment through the running proxy from curl, Python (stdlib `urllib`), and Node (stdlib `http`) — not just Go's own `net/http.Client`, which every other test in this repo uses — and confirms budget/policy enforcement holds identically for all of them, including a test proving one client exhausting the budget blocks a *different* client's next request. Any client speaking the same plain-HTTP proxy protocol (explicit proxy CONNECT / absolute-form requests) — which includes `requests`/`httpx` and most agent frameworks built on them — gets the same guarantee.

Or skip the manual exports and let `aor run` set them for just one process:

```bash
aor run --agent my-agent -- python my_agent.py
```

> **Note on HTTPS targets:** By default, x402 payment interception works for **plain HTTP** upstream URLs. For HTTPS targets the proxy establishes an opaque CONNECT tunnel — traffic passes through but 402 challenges inside the TLS session are not visible and payments are not handled.
>
> If your agent is a brand-new build rather than an existing HTTP client, consider [MCP mode](#mcp-server-mode) instead — it gets full HTTPS support with no CA or interception involved at all.
>
> To handle payments on **HTTPS** endpoints with the proxy, enable TLS interception in `aor.yaml`:
>
> ```yaml
> daemon:
>   https_intercept: true
>   ca_dir: "~/.aor/ca"
> ```
>
> On startup the daemon generates a local CA and logs its path (`~/.aor/ca/aor-ca.crt`). AgentOnRails then terminates the client's TLS locally, inspects the decrypted request for x402 challenges, and makes the real HTTPS call upstream itself. The CA private key never leaves the machine.
>
> Your agent has to trust that CA. Two ways to do it, in order of preference:
>
> 1. **`aor run --agent <id> -- <command>`** — sets `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`/`CURL_CA_BUNDLE` (plus the proxy vars) for that one subprocess only. Most HTTP clients (Python, Node, curl) already respect these — nothing is installed system-wide, and trust disappears when the process exits.
> 2. **`aor trust install`** — for runtimes that ignore those env vars (some Go binaries, the JVM, some system tools), installs the CA into your OS's actual trust store. This changes trust settings other processes on the machine will also see; run `aor trust uninstall` when you're done with it.
>
> If you'd rather not run interception at all, use HTTP endpoints, a TLS-terminating reverse proxy in front of your API, or MCP mode.

```python
import os, httpx
# With https_intercept enabled, HTTPS upstreams are handled too.
os.environ["HTTP_PROXY"] = "http://localhost:8402"
os.environ["HTTPS_PROXY"] = "http://localhost:8402"
response = httpx.get("http://api.paid-service.example.com/data")
# 402 → sign → retry happens transparently
```

```bash
curl -x http://localhost:8402 http://api.paid-service.example.com/data
```

### 6. Watch it work

```bash
aor logs tail
# TIME          AGENT     STATUS   AMOUNT    ENDPOINT
# 03-23 14:05   my-agent  allowed  $0.0100   https://api.example.com/data
```

---

## MCP server mode

In addition to the transparent proxy, AgentOnRails can run as an **MCP (Model Context Protocol) server**. Instead of intercepting HTTP traffic, the agent makes payments via explicit tool calls — useful for Claude Desktop, Claude Code, Cursor, and any other MCP-compatible client.

`aor mcp` is a **client of the daemon's own proxy** for one agent, not a second, independent payment engine — it forwards `request_payment` calls through `aor start`'s already-running proxy port for that agent instead of decrypting the wallet key or tracking budget itself. That means exactly one process ever holds the decrypted key and runs the one live budget tracker, whether a payment came in through MCP or through the transparent proxy — and it means **`aor start` must already be running for this agent, or `request_payment` fails outright** rather than silently paying without policy.

```
Claude Desktop / Claude Code / Cursor
           ↓  MCP stdio (subprocess)
       [aor mcp]  ←  client of  →  [aor start]  (must already be running)
                                        ↓
                          https://paid-api.example.com
```

The one thing this preserves from before: the *calling* agent/developer still never installs a CA or touches an OS trust store. `aor mcp` trusts AgentOnRails' own interception CA internally, so HTTPS-paid endpoints work transparently through it — **as long as the daemon has `daemon.https_intercept: true`** in `aor.yaml`. If it doesn't, `aor mcp` still starts (it prints a warning, not an error, so plain-HTTP test setups keep working) but won't see or handle payments on `https://` endpoints, the same limitation proxy mode already has without interception.

> **Read this even though MCP now requires the daemon.** Requiring `aor
> start` closes the "just skip the proxy" gap for `request_payment` itself,
> but it does **not** close the separate, older gap: if your agent runtime
> has any other way to make a network request (a shell/bash tool, a
> browser tool, its own HTTP client, another MCP server), the agent can
> simply not call `request_payment` for a given request, and that traffic
> is invisible to AgentOnRails — no budget check, no velocity limit, no
> audit entry. Giving an agent a skill or a tool description that *tells*
> it to use AgentOnRails is guidance, not enforcement. Closing that
> requires routing the agent's actual network egress through the proxy for
> everything (`HTTP_PROXY`/`HTTPS_PROXY`) or an OS/container-level egress
> rule that blocks direct internet access — MCP mode alone, even now, can't
> do that by itself.

### Available tools

| Tool | What it does |
|------|-------------|
| `request_payment` | Fetch a URL through the x402 rail — handles 402 challenges, enforces spend policy, returns the response body |
| `get_balance` | Wallet address + remaining budget per spend window (daily / weekly / monthly) |
| `get_spend_history` | Query the transaction audit log; supports `since`, `limit`, and `status` filters |
| `get_policy` | Inspect the active spend policy — limits, endpoint rules, velocity config (no private keys) |

### Prerequisites

You need a configured agent, **and the daemon already running for it**, before starting MCP mode. If you haven't done the [Quick start](#quick-start) yet:

```bash
aor init
aor agents create        # follow the wizard
aor credentials set-wallet my-agent
export AOR_PASSPHRASE="your-vault-passphrase"
aor start                # aor mcp is a client of this — it must be running
```

`aor mcp` itself no longer needs the passphrase or touches the vault — only the daemon decrypts the wallet key.

### Setup: Claude Desktop

Config file location:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "aor-my-agent": {
      "command": "aor",
      "args": ["mcp", "--agent", "my-agent"]
    }
  }
}
```

Restart Claude Desktop. The four tools will appear in the tool picker — but `request_payment` calls will fail with a clear error until `aor start` is running for `my-agent`.

### Setup: Claude Code CLI

```bash
# Add the MCP server
claude mcp add aor-my-agent -- aor mcp --agent my-agent
```

Or edit `~/.claude/settings.json` directly:

```json
{
  "mcpServers": {
    "aor-my-agent": {
      "command": "aor",
      "args": ["mcp", "--agent", "my-agent"]
    }
  }
}
```

### Running multiple agents

Add one entry per agent. Each instance is fully isolated — separate wallet, separate budget tracker, separate audit entries. One running `aor start` daemon serves all of them; it doesn't need to be started per-agent.

```json
{
  "mcpServers": {
    "aor-research": {
      "command": "aor",
      "args": ["mcp", "--agent", "research"]
    },
    "aor-coding": {
      "command": "aor",
      "args": ["mcp", "--agent", "coding"]
    }
  }
}
```

### What it looks like in practice

```
# Agent checks its budget before starting a research task
get_balance
→ {
    "agent_id": "research",
    "wallet_address": "0xABC...",
    "preferred_chain": "eip155:8453",
    "budgets": [
      { "period": "daily",   "limit_usd": "$5.00", "spent_usd": "$0.83", "remaining_usd": "$4.17", "reset_at": "2026-03-26T00:00:00Z" },
      { "period": "weekly",  "limit_usd": "$25.00", "spent_usd": "$3.21", "remaining_usd": "$21.79", "reset_at": "2026-03-30T00:00:00Z" },
      { "period": "monthly", "limit_usd": "$100.00", "spent_usd": "$12.40", "remaining_usd": "$87.60", "reset_at": "2026-04-01T00:00:00Z" }
    ]
  }

# Agent fetches a paid resource
request_payment url="https://api.example.com/papers/summary" task_context="summarize_arxiv_paper"
→ {"title": "Attention Is All You Need", "summary": "..."}
  [AgentOnRails: payment settled — PAYMENT-RESPONSE: eyJzdWNjZXNzI...]

# Agent reviews what it spent
get_spend_history since="1h" limit=5
→ [
    { "timestamp": "2026-03-25T14:05:00Z", "endpoint": "https://api.example.com/papers/summary",
      "amount_usd": "$0.0100", "status": "allowed", "tx_hash": "0xabc...", "task_context": "summarize_arxiv_paper" }
  ]
```

### Proxy mode vs MCP mode

Both modes require `aor start` running — MCP mode is a second interface onto that same daemon, not a no-daemon alternative to it.

| | Proxy mode (`aor start`) | MCP mode (`aor mcp`, on top of `aor start`) |
|---|---|---|
| Daemon required | Yes — it *is* the daemon | Yes — `aor mcp` is a client of it; `request_payment` fails without it |
| Agent changes needed | None — set `HTTP_PROXY` env var | Add server to MCP config |
| Payment visibility | Transparent (agent doesn't see it) | Explicit tool calls |
| HTTPS upstream | Opaque tunnel by default; full interception with `https_intercept` | Full interception with `https_intercept` (handled internally by `aor mcp` — no CA/trust-store change for the agent either way) |
| Works with | Any HTTP client | MCP-compatible agents only |
| **What's actually governed** | **Every request on that port** — the agent cannot route around it without its own separate network path | **Only requests the agent chooses to make via `request_payment`** — anything sent through a different tool bypasses policy entirely, same daemon or not |
| Best for | Drop-in adoption, existing agents; the only mode that guarantees coverage of *all* the agent's traffic | Claude Desktop, Claude Code, Cursor — explicit budget/history visibility on top of the same enforced daemon |

**The remaining gap either mode can have:** an agent with its own separate network access (a shell tool, a browser tool, another MCP server) can simply not route a given request through either mode. Closing that needs routing *all* of the agent's egress through the proxy, or an OS/container-level rule that blocks direct internet access — not something either mode does by default.

---

## Testnet development (Base Sepolia)

The fastest way to develop and test against real x402 endpoints without spending real money.

### Get testnet USDC

1. Get Base Sepolia ETH from the [Alchemy faucet](https://www.alchemy.com/faucets/base-sepolia) (free)
2. Get testnet USDC from the [Circle faucet](https://faucet.circle.com) — select **Base Sepolia**

### Configure for testnet

The default facilitator (`https://x402.org/facilitator`) already targets testnet, so no facilitator change is needed. In your agent config, use Base Sepolia:

```yaml
rails:
  x402:
    preferred_chain: "eip155:84532"
    allowed_networks:
      - "eip155:84532"
```

### Run the local test server

`scripts/testserver` is a real x402-compliant API server that issues $0.01 USDC challenges on `GET /paid`. Use it to test the full payment flow end-to-end:

```bash
# Start the test server (calls x402.org/facilitator to verify signatures)
go run ./scripts/testserver/ \
  -payto 0xYOUR_RECIPIENT_WALLET \
  -network eip155:84532 \
  -amount 10000 \
  -facilitator https://x402.org/facilitator

# In another terminal — make a payment through the proxy
curl -x http://localhost:8402 http://localhost:4402/paid
# {"success":true,"transaction":"0x...","network":"eip155:84532"}
```

Available flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:4402` | Listen address |
| `-network` | `eip155:84532` | CAIP-2 chain ID |
| `-amount` | `10000` | USDC atomic units (10000 = $0.01) |
| `-payto` | *(required)* | Recipient wallet address |
| `-facilitator` | `https://x402.org/facilitator` | Facilitator URL |
| `-verify` | `true` | Call facilitator `/verify` before accepting |

---

## CLI reference

```
aor init
    Create ~/.aor/ config directory with a default aor.yaml.

aor agents create
    Interactive wizard — generates an agent YAML and optionally stores the wallet key.

aor agents list
    List all configured agents and their proxy ports.

aor start [--config ~/.aor/aor.yaml] [--passphrase ...]
    Start the proxy daemon. Passphrase can also be set via AOR_PASSPHRASE env var.

aor stop
    Gracefully stop the running daemon (sends SIGTERM).

aor run --agent <agent-id> -- <command> [args...]
    Run a command with that agent's proxy (and CA, if https_intercept is on)
    wired in via env vars, scoped to that one subprocess. Requires the
    daemon to already be running. See "Note on HTTPS targets" above.

aor trust install
aor trust uninstall
    Install/remove the local interception CA in the OS trust store — the
    fallback for runtimes that don't respect the env vars "aor run" sets.

aor logs tail [agent-id]
    Stream the audit log in real time (polls every 500ms, Ctrl+C to stop).

aor spend [agent-id]
    Show daily/weekly/monthly budget usage per agent.

aor audit [agent-id] [--since 24h] [--limit 50]
    Show the transaction audit log.

aor credentials set-wallet <agent-id>
    Encrypt and store a wallet private key in the vault.

aor mcp --agent <agent-id>
    Start an MCP server for a single agent over stdio. Exposes request_payment,
    get_balance, get_spend_history, and get_policy as MCP tools. request_payment
    is a client of aor start's proxy for this agent and requires it already
    running — no passphrase needed here; only the daemon decrypts the wallet
    key. See MCP server mode section for client config.

aor version
    Print version and build info.
```

---

## Control API: approve payments, pause agents, reload policy

Starting the daemon also starts a small localhost-only, bearer-token-authenticated
HTTP API for controlling it while it runs — no more PID-file signals as the only
lever. On first start it writes a random token to `daemon.control_token_file`
(default `~/.aor/control-token`); every request below needs it, either as
`Authorization: Bearer <token>` or `?token=<token>`.

```
GET  /control/approvals
    List payments currently held for human approval (see require_approval_above_usd
    below) — agent, amount, endpoint, task context, how long it's been waiting.

POST /control/approvals/{id}/approve
POST /control/approvals/{id}/deny
    Resolve one held payment. The agent's original request — which has been
    blocked this whole time — proceeds or fails immediately once you do.

POST /control/agents/{id}/pause
POST /control/agents/{id}/resume
    Stop or start one agent's proxy server without touching any other agent
    or restarting the daemon process.

POST /control/agents/{id}/policy
    Reload one agent's rails.* config from a new YAML body (the same shape as
    that agent's own config file's "rails:" key) without restarting the daemon —
    useful for bumping a spend limit without downtime for every other agent.
```

Example: hold anything over $50 for approval, then approve it from another shell.

```yaml
rails:
  x402:
    require_approval_above_usd: "50.00"
```

```bash
curl -H "Authorization: Bearer $(cat ~/.aor/control-token)" http://127.0.0.1:8420/control/approvals
curl -X POST -H "Authorization: Bearer $(cat ~/.aor/control-token)" \
  http://127.0.0.1:8420/control/approvals/<id>/approve
```

Set `daemon.control_disabled: true` to turn this off entirely.

---

## Configuration reference

### `~/.aor/aor.yaml` (global)

| Field | Default | Description |
|-------|---------|-------------|
| `daemon.listen_addr` | `127.0.0.1` | Interface to bind proxy servers |
| `daemon.log_level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `daemon.audit_db` | `~/.aor/audit.db` | SQLite audit log path |
| `daemon.vault_dir` | `~/.aor/vaults` | Encrypted key storage directory |
| `daemon.control_addr` | `127.0.0.1:8420` | Control API listen address (see above) |
| `daemon.control_token_file` | `~/.aor/control-token` | Where the control API's bearer token is stored |
| `daemon.control_disabled` | `false` | Set `true` to not start the control API at all |
| `alerts.slack_webhook_url` | — | Slack incoming webhook (optional) |
| `alerts.budget_threshold_pct` | `80` | Alert when spend reaches this % of limit |
| `facilitators.x402` | Coinbase CDP | x402 facilitator URL |

### `~/.aor/agents/<name>.yaml` (per-agent)

| Field | Description |
|-------|-------------|
| `agent_id` | Unique identifier (used in audit log and vault) |
| `proxy_port` | TCP port the agent connects to |
| `rails.x402.wallet_address` | Agent's USDC wallet address |
| `rails.x402.preferred_chain` | CAIP-2 chain to prefer when multiple are offered |
| `rails.x402.per_call_max_usd` | Block any single payment above this amount |
| `rails.x402.daily_limit_usd` | Maximum spend per calendar day |
| `rails.x402.weekly_limit_usd` | Maximum spend per week |
| `rails.x402.monthly_limit_usd` | Maximum spend per month |
| `rails.x402.endpoint_mode` | `open` \| `allowlist` \| `blocklist` |
| `rails.x402.allowed_hosts` | Hosts permitted in allowlist mode |
| `rails.x402.blocked_hosts` | Hosts blocked in blocklist mode |
| `rails.x402.allowed_networks` | CAIP-2 chains the agent may pay on |
| `rails.x402.velocity.max_per_minute` | Max payment attempts per minute |
| `rails.x402.velocity.max_per_hour` | Max payment attempts per hour |
| `rails.x402.skip_pre_verify` | Skip facilitator `/verify` call (faster, less safe) |
| `rails.x402.require_approval_above_usd` | Hold payments above this amount for the control API instead of paying automatically |
| `rails.x402.approval_timeout_sec` | How long a held payment waits before failing as denied (default: 300) |

---

## How x402 works

1. Agent sends a normal HTTP request through the proxy
2. Upstream returns `402 Payment Required`
   - **If no x402 markers** (`PAYMENT-REQUIRED` header or `x402Version` in body) — the 402 is forwarded transparently. Stripe card errors, Vercel billing walls, and other non-x402 402s reach the agent as-is.
   - **If x402 markers present** — continue below
3. AgentOnRails parses the `PAYMENT-REQUIRED` challenge, checks policy (budget, allowlist, velocity)
4. Signs an EIP-3009 `transferWithAuthorization` payload with the agent's wallet key
5. Pre-verifies the signature with the Coinbase CDP facilitator (optional but recommended)
6. Retries the original request with a `PAYMENT-SIGNATURE` header
7. The upstream submits the authorization to the USDC contract via the facilitator
8. AgentOnRails logs the transaction to SQLite and forwards the response to the agent

---

## Running tests

```bash
# Unit + integration tests (no daemon, no real chain)
make test

# Full daemon e2e tests (mock upstream, no real money)
make test-e2e

# Real Base Sepolia chain tests (requires funded wallet)
# Get testnet USDC at https://faucet.circle.com (Base Sepolia)
export TEST_SEPOLIA=1
export AOR_TEST_PRIVATE_KEY=0x<your_sepolia_private_key>
export AOR_TEST_PAYTO=0x<recipient_address>
make test-sepolia
```

The Sepolia tests make real on-chain USDC transfers (~$0.02 total). Use a dedicated test wallet.

---

## Licensing & Commercial Offerings

The x402 payment rail and this core proxy — the CLI, budget/policy
enforcement, the audit log, and the `Rail` plugin interface — are
Apache-2.0 and stay free and open source forever. Anyone can self-host,
audit, and use this repository commercially at no cost.

Additional payment rails (card, ACH, Lightning/L402), a privacy rail,
per-agent cryptographic identity, and the GUI cockpit backend are part of a
separate commercial offering, distributed outside this repository. See the
[Roadmap](#roadmap) section below for what's free vs. planned.

Agents managed by the commercial identity module can optionally attach a
cryptographic attestation of which agent made a given call — see
[`docs/attestation-spec.md`](docs/attestation-spec.md) for the complete,
standalone wire format. Verifying it needs no AgentOnRails software: it's
`did:key` + ed25519, both open standards.

---

## Roadmap

- [x] x402 crypto rail (Base, Ethereum, Optimism, Arbitrum, Polygon)
- [x] MCP server mode (`aor mcp`) — Claude Desktop, Claude Code, Cursor
- [x] HTTP 402 passthrough (Stripe, Cloudflare, Vercel ecosystem)
- [x] Control API — approve/deny held payments, pause/resume agents, live policy reload
- [ ] Virtual card rail (Stripe Issuing / Lithic)
- [ ] Bank ACH rail (Stripe Treasury / Plaid Transfer)
- [ ] GUI dashboard
- [ ] Team mode (shared budget pools)
- [ ] L402 (Lightning Network) rail

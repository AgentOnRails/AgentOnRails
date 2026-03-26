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
- **x402 payment rail** — automatically handles HTTP 402 Payment Required challenges: signs EIP-3009 authorizations, pre-verifies with the facilitator, and retries the request
- **Spend guardrails** — per-agent daily/weekly/monthly budgets, per-call maximums, velocity limits, endpoint allowlists/blocklists
- **Encrypted wallet vault** — private keys never touch disk unencrypted; AES-256-GCM + scrypt
- **Audit log** — every transaction written to SQLite; queryable with `aor audit` and `aor spend`

## Supported networks

| Chain | CAIP-2 | USDC address |
|-------|--------|--------------|
| Base | `eip155:8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Ethereum Mainnet | `eip155:1` | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| Optimism | `eip155:10` | `0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85` |
| Arbitrum One | `eip155:42161` | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` |
| Polygon | `eip155:137` | `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` |
| Base Sepolia (testnet) | `eip155:84532` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |

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
  Wallet address (0x...): 0xYOUR_WALLET

  1) Base mainnet      (eip155:8453)  ← recommended
  2) Ethereum mainnet  (eip155:1)
  3) Optimism          (eip155:10)
  4) Arbitrum One      (eip155:42161)
  5) Polygon           (eip155:137)
  6) Base Sepolia      (eip155:84532)  ← testnet

  Preferred chain [1]: 1
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

> **Note on HTTPS targets:** x402 payment interception works for **plain HTTP** upstream URLs. For HTTPS targets the proxy establishes a transparent CONNECT tunnel — traffic passes through but 402 challenges inside the TLS session are not visible and payments are not handled. Use HTTP endpoints (or a TLS-terminating reverse proxy in front of your API) for x402 payments.

```python
import os, httpx
# x402 payments handled — use plain HTTP upstream
os.environ["HTTP_PROXY"] = "http://localhost:8402"
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

```
Claude Desktop / Claude Code / Cursor
           ↓  MCP stdio (subprocess)
       [AgentOnRails]
           ↓
  https://paid-api.example.com
```

No daemon required. `aor mcp` starts as a subprocess, talks over stdin/stdout, and exits when the client closes.

### Available tools

| Tool | What it does |
|------|-------------|
| `request_payment` | Fetch a URL through the x402 rail — handles 402 challenges, enforces spend policy, returns the response body |
| `get_balance` | Wallet address + remaining budget per spend window (daily / weekly / monthly) |
| `get_spend_history` | Query the transaction audit log; supports `since`, `limit`, and `status` filters |
| `get_policy` | Inspect the active spend policy — limits, endpoint rules, velocity config (no private keys) |

### Prerequisites

You need a configured agent before starting. If you haven't done the [Quick start](#quick-start) yet:

```bash
aor init
aor agents create        # follow the wizard
aor credentials set-wallet my-agent
```

### Setup: Claude Desktop

Config file location:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "aor-my-agent": {
      "command": "aor",
      "args": ["mcp", "--agent", "my-agent"],
      "env": {
        "AOR_PASSPHRASE": "your-vault-passphrase"
      }
    }
  }
}
```

Restart Claude Desktop. The four tools will appear in the tool picker.

### Setup: Claude Code CLI

```bash
# Add the MCP server
claude mcp add aor-my-agent -- aor mcp --agent my-agent

# Set your passphrase (add to shell profile to make it persistent)
export AOR_PASSPHRASE="your-vault-passphrase"
```

Or edit `~/.claude/settings.json` directly:

```json
{
  "mcpServers": {
    "aor-my-agent": {
      "command": "aor",
      "args": ["mcp", "--agent", "my-agent"],
      "env": {
        "AOR_PASSPHRASE": "your-vault-passphrase"
      }
    }
  }
}
```

### Running multiple agents

Add one entry per agent. Each instance is fully isolated — separate wallet, separate budget tracker, separate audit entries.

```json
{
  "mcpServers": {
    "aor-research": {
      "command": "aor",
      "args": ["mcp", "--agent", "research"],
      "env": { "AOR_PASSPHRASE": "your-passphrase" }
    },
    "aor-coding": {
      "command": "aor",
      "args": ["mcp", "--agent", "coding"],
      "env": { "AOR_PASSPHRASE": "your-passphrase" }
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

| | Proxy mode (`aor start`) | MCP mode (`aor mcp`) |
|---|---|---|
| Agent changes needed | None — set `HTTP_PROXY` env var | Add server to MCP config |
| Payment visibility | Transparent (agent doesn't see it) | Explicit tool calls |
| HTTPS upstream | CONNECT tunnel — no 402 interception | Full HTTPS support |
| Works with | Any HTTP client | MCP-compatible agents only |
| Best for | Drop-in adoption, existing agents | Claude Desktop, Claude Code, Cursor |

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

aor logs tail [agent-id]
    Stream the audit log in real time (polls every 500ms, Ctrl+C to stop).

aor spend [agent-id]
    Show daily/weekly/monthly budget usage per agent.

aor audit [agent-id] [--since 24h] [--limit 50]
    Show the transaction audit log.

aor credentials set-wallet <agent-id>
    Encrypt and store a wallet private key in the vault.

aor mcp --agent <agent-id> [--passphrase ...]
    Start an MCP server for a single agent over stdio. Exposes request_payment,
    get_balance, get_spend_history, and get_policy as MCP tools. Passphrase can
    also be set via AOR_PASSPHRASE. See MCP server mode section for client config.

aor version
    Print version and build info.
```

---

## Configuration reference

### `~/.aor/aor.yaml` (global)

| Field | Default | Description |
|-------|---------|-------------|
| `daemon.listen_addr` | `127.0.0.1` | Interface to bind proxy servers |
| `daemon.log_level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `daemon.audit_db` | `~/.aor/audit.db` | SQLite audit log path |
| `daemon.vault_dir` | `~/.aor/vaults` | Encrypted key storage directory |
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

---

## How x402 works

1. Agent sends a normal HTTP request through the proxy
2. Upstream returns `402 Payment Required` with a `PAYMENT-REQUIRED` header (base64 JSON challenge)
3. AgentOnRails parses the challenge, checks policy (budget, allowlist, velocity)
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

## Roadmap

- [x] x402 crypto rail (Base, Ethereum, Optimism, Arbitrum, Polygon)
- [x] MCP server mode (`aor mcp`) — Claude Desktop, Claude Code, Cursor
- [ ] HTTP 402 passthrough (Stripe, Cloudflare, Vercel ecosystem)
- [ ] Virtual card rail (Stripe Issuing / Lithic)
- [ ] Bank ACH rail (Stripe Treasury / Plaid Transfer)
- [ ] GUI dashboard
- [ ] Team mode (shared budget pools)
- [ ] L402 (Lightning Network) rail

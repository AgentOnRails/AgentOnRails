# Hermes / MCP integration

AgentOnRails already speaks MCP (Model Context Protocol) natively — `aor
mcp` exposes a running agent's payment rail as four tools over stdio. It is
a client of the daemon's own proxy for that agent, not a separate payment
engine: `aor start` must already be running for the agent, or
`request_payment` fails outright rather than silently paying without
policy. The upside of that design: it's still true that the *calling*
agent/developer never has to install a CA or touch an OS trust store — `aor
mcp` trusts AgentOnRails' own interception CA internally so HTTPS-paid
endpoints work transparently, the same as before. This doc is the
submission artifact for getting that integration in front of Hermes/Nous
for review: what it exposes, how a fresh user gets a funded testnet wallet
in under two minutes, and a sample tool-manifest entry.

## What `aor mcp` exposes

| Tool | What it does |
|---|---|
| `request_payment` | Fetch a paid resource through the x402 rail — pays automatically if the request is within the agent's budget |
| `get_balance` | Wallet address and remaining budget for the current spend period |
| `get_spend_history` | Paginated transaction audit log |
| `get_policy` | Active spend controls (limits, velocity, endpoint policy) — no private keys |

Every call made *through these tools* is governed by the agent's normal
policy: daily/weekly/monthly limits, a per-call max, velocity limits, and
endpoint allow/block rules all apply exactly as they do to any other client
of `aor start`'s HTTP proxy — because that's what `request_payment`
literally is: a client of that same running daemon, not a second copy of
the policy engine. There is exactly one process that ever decrypts the
wallet key and one live budget tracker, regardless of whether a given
payment came in through MCP or through the transparent proxy.

That guarantee only covers traffic that actually reaches the daemon,
though. If the host agent runtime has any other way to make a network
request — a shell tool, a browser tool, its own HTTP client — an agent can
simply not call `request_payment` for a given request, and AgentOnRails
never sees it: no budget check, no velocity limit, no audit entry. A tool
description or skill that *tells* the agent to route payments through
AgentOnRails is guidance the model can ignore, not an enforced boundary.
Closing that specific gap needs network-level egress lockdown (routing all
of the agent's traffic through the proxy, or blocking direct egress
entirely) — something no MCP server, including this one, can do by itself.
Any Hermes deployment that wants to claim "spend is capped" or "endpoints
are restricted" as a hard property, not a best-effort one, needs that
egress lockdown in place, not just this MCP server.

## Getting a funded agent in under two minutes

`aor mcp` itself expects an already-funded, already-configured agent, and
the daemon already running for it — it doesn't create a wallet, claim
testnet funds, or start the proxy for you. Use `scripts/hermes-quickstart`
for all of that:

```
go run ./scripts/hermes-quickstart
```

This builds `aor`, runs `aor init` (enabling `daemon.https_intercept` on a
freshly-created config, so HTTPS-paid endpoints work through MCP out of
the box), generates (or reuses) a burner wallet and an x402 agent config,
then waits for Base Sepolia testnet USDC. The only manual step is claiming
from the Circle faucet — everything else, including agent config
generation and starting `aor start` in the background, runs unattended
(see `internal/bootstrap`, the same non-interactive path `scripts/demo`
uses). Once funded, it starts the daemon, waits for it to come up, prints
the exact MCP server config to point a client at, and hands off to `aor
mcp --agent hermes-agent` on this terminal's stdio, so you can confirm it
starts cleanly before wiring it into a real client. Ctrl+C stops both the
MCP process and the daemon it started.

## Sample MCP server config

```json
{
  "mcpServers": {
    "agentonrails": {
      "command": "aor",
      "args": ["mcp", "--agent", "hermes-agent", "--config", "~/.aor/aor.yaml", "--agents-dir", "~/.aor/agents"]
    }
  }
}
```

`scripts/hermes-quickstart` prints this block with the real paths filled
in at the end of a successful run. No wallet passphrase is needed here —
`aor mcp` never decrypts the wallet key itself; only the `aor start`
daemon it talks to does, and the quickstart script already started that
for you with the right passphrase.

## Installing `aor`

- macOS/Linux: `curl -sf https://raw.githubusercontent.com/agentOnRails/agent-on-rails/main/scripts/install.sh | sh`, or `brew install aor`
- Windows: `iwr https://raw.githubusercontent.com/agentOnRails/agent-on-rails/main/scripts/install.ps1 -useb | iex`
- From source (any OS): `go install github.com/agentOnRails/agent-on-rails/cmd/aor@latest`

## What to record for the two-minute demo

The proposal's launch-content list (`docs/agent-on-rails-business-plan.md`
and the strategic proposal) calls for a real agent, a real policy, and a
real payment or blocked action, with a visible audit record. For a Hermes
demo specifically:

1. Run `scripts/hermes-quickstart`, claim the faucet, let it hand off to `aor mcp`.
2. From a real Hermes session (or any MCP client), call `request_payment` against a paid test endpoint — show the payment clearing under budget.
3. Call `request_payment` again for an amount over the agent's per-call max — show it get blocked by policy, not silently fail.
4. Call `get_spend_history` — show both the successful and blocked attempts recorded.

A first recording of exactly this sequence — registered via `hermes mcp
add`, a real blocked call ($0.30 against a $0.25 per-call max), a real
$0.01 payment settled on Base Sepolia (verified independently against the
chain, not just aor's own log), then `get_spend_history` showing both — is
at `integrations/hermes/demo.gif`. It's a stylized terminal render of the
genuine transcript (real Chrome-based screen recording wasn't available
when this was captured), not a mockup: every command, response, and the
transaction hash in it are real.

## Submitting for Nous review

The integration should go in as a reviewed, opt-in capability — not
unrestricted payment access enabled by default for every Hermes agent.
Package for submission:

- This document.
- The recorded two-minute demo above.
- A link to `OSS-AgentOnRails/docs/attestation-spec.md` (the published
  outbound-signing wire format), for reviewers evaluating provenance/
  trust properties of a payment made through this integration.
- The security posture: local-first, non-custodial, encrypted wallet key
  at rest — decrypted only by the `aor start` daemon, never by `aor mcp`
  itself — with budget/velocity/endpoint policy enforced before any
  payment leaves the machine, **for calls made through `request_payment`**.
  Reviewers evaluating this for default/unattended enablement should
  understand that scope explicitly: an agent with independent network
  access (a shell tool, a browser tool, its own HTTP client) can bypass
  `request_payment` entirely for a given request, and only network-level
  egress lockdown closes that — no MCP server can, by itself.

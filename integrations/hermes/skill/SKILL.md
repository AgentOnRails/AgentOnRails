---
name: agentonrails
description: "Pay for paid APIs and web resources automatically, under a policy-enforced budget, via the AgentOnRails MCP server."
version: 1.0.0
author: AgentOnRails
license: Apache-2.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Payments, MCP, x402, Budgets, Stablecoin, Audit]
    related_skills: []
---

# AgentOnRails Payments

Fetch paid resources — APIs behind an HTTP 402 challenge, x402-enabled
endpoints — by calling the `agentonrails` MCP tools instead of a raw HTTP
client. Every call is checked against the agent's own spend policy
(daily/weekly/monthly limits, a per-call max, velocity limits, endpoint
allow/block) before anything is paid. This skill assumes the
`agentonrails` MCP server is already connected (see
`integrations/hermes/mcp-catalog/manifest.yaml` in this repo, or
`docs/hermes-integration.md` for manual setup).

## Quick reference

| Tool | Use it to |
|---|---|
| `request_payment` | Fetch a URL that requires payment — pays automatically if the request is within budget, returns the response body |
| `get_balance` | Check wallet address and remaining budget for the current spend period, before or after paying |
| `get_spend_history` | List past payments and blocked attempts from the audit log (`since`, `limit`, `status` filters) |
| `get_policy` | Read active limits — no private keys are ever exposed through any tool |

## When to reach for this instead of a browser/HTTP tool

If a resource is behind an x402 or plain HTTP 402 paywall and paying for it
is in scope for the task, use `request_payment` rather than fetching it
with a shell or browser tool. Only `request_payment` calls are governed by
the agent's budget — anything fetched another way bypasses AgentOnRails
entirely, with no budget check and no audit record. If you're unsure
whether a fetch should be paid, check `get_policy` first rather than
guessing.

## Typical flow

1. **Check budget before a large or unfamiliar request** — call
   `get_policy` (limits) and `get_balance` (what's left this period) so an
   over-limit call doesn't come as a surprise mid-task.
2. **Fetch the resource**:
   ```
   request_payment url="https://api.example.com/papers/summary" task_context="summarize_arxiv_paper"
   ```
   A successful call returns the resource body directly, having already
   paid for it. `task_context` is a free-text note that lands in the audit
   log next to the transaction — use it, it's the only thing that makes
   `get_spend_history` readable later.
3. **If it's blocked** — over the per-call max, over a budget window, past
   a velocity limit, or against a non-allowlisted endpoint — the tool
   returns a clear policy error, not a silent failure or a fallback
   payment. Don't retry the same call expecting a different result; report
   the block, or ask before proceeding if the task genuinely needs an
   exception (some agents run with human-approval-above-a-threshold
   configured, in which case the call is held for approval, not
   flat-rejected).
4. **Audit when asked "what did you spend / did you spend"** — use
   `get_spend_history` rather than answering from memory. It records both
   successful payments and blocked attempts, so it's the source of truth
   for what actually happened, not what a chat transcript implies.

## Scope limit — read this before treating spend as capped

`request_payment` is a client of the same daemon (`aor start`) and the same
policy engine the AgentOnRails proxy uses — it is not a second, weaker
payment path. But it only governs calls made *through it*. If this agent
also has a shell tool, a browser tool, or any other way to make network
requests, it can fetch a paid resource some other way and AgentOnRails
never sees it: no budget check, no velocity limit, no audit entry. This
skill is guidance the model can choose to follow — it is not an enforced
boundary. Treat "AgentOnRails caps this agent's spend" as true only for
requests actually routed through `request_payment`, not as a property of
the agent's environment as a whole. Closing that gap needs network-level
egress lockdown (routing all outbound traffic through the proxy, or
blocking direct egress), which is outside what any MCP server — this one
included — can do by itself.

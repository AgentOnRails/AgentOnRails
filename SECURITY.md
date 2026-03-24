# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | yes |

## Reporting a vulnerability

AgentOnRails handles encrypted wallet keys and authorizes on-chain USDC transfers. Please
**do not** open a public GitHub issue for security vulnerabilities.

Instead, use **[GitHub private vulnerability reporting](https://github.com/agentOnRails/agent-on-rails/security/advisories/new)**. This keeps the report confidential until a fix is ready.

Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (redact any real private keys)
- The version or commit hash you tested against

We will coordinate a fix and a disclosure timeline with you before publishing anything publicly.

## Scope

The following are in scope:

- Unauthorized spend or budget bypass
- Private key extraction from the vault
- Signature malleability or payment replay attacks
- Proxy header injection that corrupts audit logs
- Dependency vulnerabilities with a credible exploit path

## Out of scope

- Attacks that require physical access to the machine running `aor`
- Social engineering
- Findings already publicly disclosed or with no realistic exploit path

## Security design notes

- Private keys are stored AES-256-GCM encrypted on disk, derived via scrypt (N=2^15).
  They are held in memory only during daemon runtime.
- The proxy binds to `127.0.0.1` by default and is not intended to be exposed to the network.
- Budget and velocity limits are enforced in-memory and persisted to SQLite; they are not
  a substitute for on-chain allowances.

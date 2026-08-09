# Hermes integration artifacts

Draft files for the two ways `aor` plugs into Nous's `hermes-agent`. Neither
is submitted yet — these are staged here so they can be reviewed, tested
against a real Hermes install, and then copied into a `hermes-agent`
checkout for a PR.

- `mcp-catalog/manifest.yaml` — copy to `optional-mcps/agentonrails/manifest.yaml`
  in a `hermes-agent` checkout to submit `aor` as a reviewed, opt-in catalog
  entry (`hermes mcp install agentonrails` once merged). Until then, add the
  same `mcp_servers.agentonrails` block by hand to `~/.hermes/config.yaml`.
- `skill/SKILL.md` — copy to `skills/<category>/agentonrails/SKILL.md` in a
  `hermes-agent` checkout. Layers usage guidance (when to reach for
  `request_payment` vs. a shell/browser tool, how to read a policy block,
  how to audit spend) on top of the raw MCP tools from the catalog entry
  above — useful even without a merged catalog PR, since a skill just needs
  to exist under `skills/` locally to load.
- `demo.gif` — a real run of the two-minute demo script below against a real
  Hermes install: `hermes mcp add`, a blocked over-budget call, a $0.01
  payment settled on Base Sepolia (tx verified independently against the
  chain), then `get_spend_history` showing both. Also embedded on the
  website (`website/index.html#agents`).

See `docs/hermes-integration.md` for the full integration writeup and the
two-minute demo script both artifacts assume (`scripts/hermes-quickstart`,
agent id `hermes-agent`).

# AgentOnRails Agent Attestation — wire format

This document describes a small, optional HTTP header convention an
AgentOnRails-managed agent can use to cryptographically attest which agent
made a given outbound request — for example, a paid API call. It answers
"which agent sent this," not "should I trust it" — the trust decision is
entirely up to whoever receives the request. Nothing today automatically
checks these headers; publishing this spec is what makes it *possible* for
a counterparty to check them, independently, without adopting any
AgentOnRails software or depending on this project staying online.

Every identifier and primitive here is a widely-used, open standard
(`did:key`, ed25519, SHA-256) — there is nothing proprietary in the format
itself. AgentOnRails' own tooling for generating identities and attaching
these headers automatically is part of its commercial offering, but nothing
about *verifying* them requires that tooling or this project at all: the
algorithm below is complete and self-contained.

## Headers

| Header | Value |
|---|---|
| `AOR-Identity` | The signing agent's [`did:key`](https://w3c-ccg.github.io/did-method-key/) identifier — a self-certifying DID whose public key is recoverable from the identifier itself. No directory lookup is needed to resolve it. |
| `AOR-Timestamp` | Unix seconds (decimal string) at signing time. |
| `AOR-Nonce` | A random per-request value, hex-encoded (16 bytes / 128 bits in the reference implementation — any value with negligible collision probability within your replay window is fine). |
| `AOR-Signature` | `base64(ed25519_sign(private_key, canonical_string))` — see below. |

All four headers must be present to attempt verification; treat a request
missing any of them as unsigned.

## `did:key` → public key

A `did:key` identifier for an ed25519 key is:

```
did:key:z<multibase-encoded multicodec-prefixed public key>
```

Concretely: multicodec-prefix the raw 32-byte ed25519 public key with the
bytes `0xed 0x01`, then multibase-encode the result with the `z` (base58btc)
prefix. Decoding reverses this: base58-decode after stripping the leading
`z`, then strip the two-byte `0xed 0x01` prefix to recover the raw public
key. This is the standard `did:key` method for ed25519 — no AgentOnRails-
specific encoding is involved, so any existing `did:key` library in your
language of choice can parse `AOR-Identity` directly.

## Canonical string

The exact bytes signed are:

```
method + "\n" + request_uri + "\n" + timestamp + "\n" + nonce + "\n" + hex(sha256(body))
```

- `method` — the HTTP method, as sent (e.g. `GET`, `POST`).
- `request_uri` — the request's path plus query string (what
  `req.URL.RequestURI()` returns in Go — e.g. `/papers/summary?id=42`).
  Does not include scheme or host.
- `timestamp` / `nonce` — the exact string values of the `AOR-Timestamp` /
  `AOR-Nonce` headers.
- `hex(sha256(body))` — lowercase hex of the SHA-256 digest of the request
  body (empty body hashes to the SHA-256 of zero bytes, not an empty
  string literal).

Ed25519 hashes internally (SHA-512) as part of signing, so this string is
signed directly — no separate outer hash is applied before `ed25519_sign`.

## Verification algorithm

Given a request and the four headers above:

1. Reject if any of `AOR-Identity` / `AOR-Timestamp` / `AOR-Nonce` /
   `AOR-Signature` is missing.
2. Parse `AOR-Identity` as a `did:key` per above to recover the ed25519
   public key. Reject if it doesn't parse.
3. Parse `AOR-Timestamp` as an integer. Reject if it's outside your
   accepted clock-skew window of now (5 minutes in the reference
   implementation; choose a window appropriate to your own latency and
   clock-sync assumptions).
4. Recompute the canonical string from the request's actual method,
   request URI, the `AOR-Timestamp` value, the `AOR-Nonce` value, and a
   fresh SHA-256 of the actual body received.
5. Base64-decode `AOR-Signature` and verify it against the recomputed
   canonical string with the public key from step 2. Reject on failure.
6. Optional but recommended: track `(AOR-Identity, AOR-Nonce)` pairs
   you've already seen (e.g. in a short-lived cache bounded by your skew
   window) and reject a repeat — this closes the replay window a
   timestamp check alone leaves open, where a captured valid request could
   otherwise be replayed verbatim until it ages out.
7. If all of the above pass, the request is authentically from the agent
   identified by `AOR-Identity`. Whether to *trust* that specific DID —
   allow-list it, rate-limit by it, personalize by it, or ignore it
   entirely — is entirely your own policy; this spec has no opinion on
   that and no registry of "known good" agents exists.

## Reference implementation

A concrete Go implementation of both signing and this exact verification
algorithm exists in AgentOnRails' commercial identity module
(`internal/identity`, package `identity`, functions `SignRequest` /
`VerifyRequest` / `ParsePublicKey` — not distributed in this repository).
This document is the complete, standalone specification of that wire
format; a from-scratch implementation in any language needs nothing beyond
what's written above.

## Non-goals

- This does not establish *authorization* to act, spend, or access
  anything — it only attests *identity*. Authorization is a separate
  concern (see AgentOnRails' Track/Engine split) that a verifier layers on
  top if it wants to.
- This is not a directory or discovery service. Learning which DIDs exist
  or how to reach an agent is out of scope for this document.
- This does not depend on AgentOnRails' infrastructure being available,
  now or in the future — `did:key` resolution and ed25519 verification are
  fully self-contained, standard operations.

# Design specs

These are the design and protocol documents behind `archer-router-mcp`, kept for
provenance and for contributors. They describe *why* the server is built the way
it is; the user-facing docs are the top-level [`README.md`](../../README.md) and
the protocol summary in [`../protocol/`](../protocol/).

Some specs reference sibling MCP servers (`vigi-nvr-mcp`, `tplink-easysmart-mcp`)
and a shared, copied-verbatim `core/` template. Those are part of the same
multi-device engineering effort; only `archer-router-mcp` lives in this repo.
Addresses are RFC 5737 placeholders; there are no secrets or real network data.

| Document | What it is |
|---|---|
| [`00-MASTER-PLAN.md`](00-MASTER-PLAN.md) | The overall plan: three standalone, browser-free MCP servers, the shared `core/` template, the non-negotiables (zero secrets, lockout safety, double-gated writes, redaction), and the phase/task tracker. |
| [`03-ROUTER-SPEC.md`](03-ROUTER-SPEC.md) | This server's spec: the Archer AX53 protocol, the R0–R5 phase plan, and every tool (reads, writes, presence, safety). |
| [`04-BREAKER-PROTOCOL.md`](04-BREAKER-PROTOCOL.md) | The adversarial-review ("breaker") process and the severity rubric used to harden the server. |
| [`05-ROOT-CAUSE-breaker.md`](05-ROOT-CAUSE-breaker.md) | The root-cause analysis that produced the canonical login-breaker design (one atomic, lock-protected, schema-validated ledger) now in `core/`. |
| [`archer-ax53-auth-flow.md`](archer-ax53-auth-flow.md) | The full, source-tagged (`[V]`/`[O]`/`[I]`) reconstruction of the Archer login/transport protocol from the router's own JavaScript bundle. The clean-room reference. |
| [`router-endpoints.json`](router-endpoints.json) | The curated endpoint/capability catalogue (paths, operations, request/response shapes, confidence) derived by static analysis of the UI bundle. |

## Protocol docs

- [`../protocol/archer-ax53.md`](../protocol/archer-ax53.md) — a user-level
  summary of the wire protocol (endpoints, crypto chain, envelopes, errors, flags).
- [`../protocol/archer-ax53-verified.md`](../protocol/archer-ax53-verified.md) —
  the R0 verified-write-body record; starts empty and gates the inferred writes.

# archer-router-mcp

A local, browser-free [MCP](https://modelcontextprotocol.io) server for the
**TP-Link Archer AX53 v1 (AX3000)** router, web UI `AX53v1_1.11.0`, SG-hardened
certification profile (`SG CLS L1 STAGE2`).

It speaks the router's own `/cgi-bin/luci/;stok=<token>/...` protocol natively —
no headless browser at runtime — and is built read-first, write-gated, and
lockout-aware so an LLM client cannot brick the admin account or silently change
the network.

> **Status: Phase R1 (crypto layer).** This build ships the pure, vector-tested
> cryptography (`archer_router_mcp/crypto.py`) and the device-agnostic
> `core/` template. Authenticated sessions and the `router_*` tools arrive in
> later phases. `archer-router-mcp --list-tools` therefore lists no tools yet.

## Design guarantees

- **Public repo, zero secrets.** No real IPs, MACs, hostnames, or captured
  responses. `scripts/check_no_secrets.py` runs in CI and in the release gate.
- **Clean-room MIT.** Reimplemented from first-party protocol docs; no GPL code
  from `tplinkrouterc6u` was copied (see `NOTICE`).
- **Lockout safety.** No automatic login retries; a persistent breaker; an
  `ARCHER_ROUTER_LOGIN_DISABLED` freeze switch. The account locks for ~2 hours
  after a handful of failures, so the client never spends attempts blindly.
- **Writes gated twice.** `ARCHER_ROUTER_ALLOW_WRITES=true` **and**
  `confirm_write=true` per call, plus `ARCHER_ROUTER_DRY_RUN` to preview bodies.
- **Uniform envelope.** Every tool returns `{success, data, error}`; credential
  fields are redacted from all output.

## Development

```bash
pip install -e '.[dev]'
python scripts/gate.py      # ruff + pytest(+coverage) + secret-scan + stub-scan + --list-tools
```

## Layout

| Path | Contents |
|---|---|
| `archer_router_mcp/crypto.py` | Pure crypto: password hash, AES envelope, RSA (PKCS#1 v1.5 + OAEP), chunked signatures, rolling hash, body builders |
| `archer_router_mcp/core/` | Device-agnostic template (config, envelope, errors, redaction, write gate, breaker, serial lock, transport) copied verbatim from the `vigi-nvr-mcp` template |
| `docs/specs/` | Master plan, router spec (phases R0–R5), breaker protocol, verified auth-flow, endpoint catalogue |
| `tests/` | Vector tests for the crypto layer and the copied core |

See `docs/specs/03-ROUTER-SPEC.md` for the full phase plan.

## License

MIT. See `LICENSE` and `NOTICE`.

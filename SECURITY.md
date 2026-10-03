# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/ebenezer-isaac/archer-router-mcp/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). Include a
description, reproduction steps, and the impact. You'll get an acknowledgement as
soon as possible, and a fix or mitigation will be coordinated before any public
disclosure.

Do **not** include real credentials, router passwords, captured responses,
session tokens, MAC addresses, or private IPs in a report — redact them.

## Scope

This server speaks a router's admin protocol and can, when writes are enabled,
change network settings. Security-relevant areas:

- **Credential handling** — the router password is read only from the
  environment, never logged, and never returned by any tool. AES keys/IVs, the
  session token, and the `sysauth` cookie are redacted from all output and
  excluded from exception messages and reprs.
- **Lockout safety** — the account locks for ~2 hours after a few failed logins.
  The breaker exists to prevent an automated client from walking into that lock;
  a bug that spends a login attempt unasked, or fails open on an unwritable state
  dir, is in scope.
- **Write gating** — any path that performs a mutating call without both
  `ARCHER_ROUTER_ALLOW_WRITES=true` and per-call `confirm_write=true`, that
  bypasses the protected-MAC guard, that sends a body under `DRY_RUN`, or that
  sends an inferred write body not yet confirmed by R0, is in scope.
- **Transport** — TLS pin bypass, or an input (tool argument / crafted device
  response) that breaks request encoding, injects into a body, or crashes a tool
  into leaking internals.
- **Session takeover** — evicting the owner's admin session without the explicit
  double gate is in scope.

## Hardening expectations for operators

- Keep `.env` / the `EnvironmentFile` at mode `0600`; never commit secrets.
- Keep `ARCHER_ROUTER_ALLOW_WRITES=false` unless you need writes; populate
  `ARCHER_ROUTER_PROTECTED_MACS` with your own and the server's devices before
  turning writes on.
- Pin the router certificate (`ARCHER_ROUTER_TLS_FINGERPRINT_SHA256`).
- Bind the MCP server to loopback (`ARCHER_MCP_HOST=127.0.0.1`) and reach it only
  over Tailscale/SSH. Never expose it to the LAN or internet.
- Review a write's `DRY_RUN` body before enabling writes, especially for inferred
  tools (see `docs/protocol/archer-ax53-verified.md`).

## Supported versions

This project is pre-1.0; only the latest release receives security fixes.

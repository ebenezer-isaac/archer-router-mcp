# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-03

Initial public release: a local, browser-free MCP server for the TP-Link Archer
AX53 v1 (web UI `AX53v1_1.11.0`, SG-hardened certification profile).

### Added

- **Clean-room protocol layer.** Native Python reimplementation of the Archer
  SG login/request scheme — SHA-256 password hash, AES-128-CBC/PKCS7 envelope,
  RSA PKCS#1 v1.5 password field, RSA-OAEP login signature, chunked HMAC-SHA256
  request signature, and the per-request rolling hash — verified byte-for-byte
  against vectors produced by executing the router's own JavaScript bundle offline.
- **Authentication and session handling** with feature-flag detection from
  `device_config`, HTTPS-plain and HTTP-encrypted wire envelopes, and the single
  admin-session / takeover model.
- **29 MCP tools** under the `router_` prefix: 4 session/health, 14 reads
  (status, WAN, clients, DHCP leases/reservations, Wi-Fi, port-forwards, mesh,
  access control, speed limits, Wi-Fi schedule, IoT isolation, presence
  sample/history), and 11 double-gated writes (reservation add/remove, Wi-Fi
  radio, reboot, block/unblock, access mode, speed limit, schedule, isolate, WoL).
- **Lockout safety:** a persistent, lock-protected, schema-validated login
  breaker (admit-and-reserve is one atomic cross-process step), no auto-retry,
  `exceeded max attempts` honoured as a ~2 h cooldown, `ARCHER_ROUTER_LOGIN_DISABLED`
  freeze, and a `breaker --show|--clear` CLI.
- **Write safety:** double gating (`ARCHER_ROUTER_ALLOW_WRITES` + per-call
  `confirm_write`), `ARCHER_ROUTER_DRY_RUN` body preview, a required
  `ARCHER_ROUTER_PROTECTED_MACS` guard on every MAC-targeting write, whitelist-mode
  lockout prevention, reboot rate-limiting (reserve-before-send), non-idempotent
  writes with read-back outcome reporting, and an `R0_UNCONFIRMED` gate holding
  inferred write bodies until a live capture confirms them.
- **Presence history:** a file-backed, size-capped join/leave/rename log the
  router does not keep, fed by an optional in-server sampler.
- **TLS certificate pinning** by SHA-256 fingerprint (trust-on-first-use), with
  the observed fingerprint reported by `router_status`.
- **Uniform `{success, data, error}` envelope** with recursive redaction of
  credential-bearing fields; tools never raise.
- Packaging, `.env.example`, CI (Ubuntu + Windows, Python 3.11–3.13), release
  gate (`scripts/gate.py`), secret scanner, systemd deploy example, and docs.

[0.1.0]: https://github.com/ebenezer-isaac/archer-router-mcp/releases/tag/v0.1.0

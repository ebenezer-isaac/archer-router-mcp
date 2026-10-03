# Master Plan — three standalone, browser-free MCP servers for the owner's TP-Link devices

**Decision (owner, 2026-10-03): three standalone repos, not one consolidated server.** Each is a complete MCP server; the device-agnostic `core/` directory is written once in `vigi-nvr-mcp` and **copied verbatim** into the other two (a shared package is extracted later only if it stays identical). Rationale: the three protocols share nothing, standalone repos let agents work with zero collisions, and public users install only the device they own.

| Repo / package / script | Hardware (owner's) | Protocol | Env prefix | Tool prefix | Spec |
|---|---|---|---|---|---|
| `vigi-nvr-mcp` / `vigi_nvr_mcp` / `vigi-nvr-mcp` | VIGI NVR1016H(UN), fw 1.1.3 Build 260727 | JSON-RPC `POST /stok=<t>/ds`, RSA-PKCS1v15(md5) login | `VIGI_NVR_*` | `nvr_` | `01-NVR-SPEC.md` |
| `tplink-easysmart-mcp` / `tplink_easysmart_mcp` / `tplink-easysmart-mcp` | TL-SG1016PE Easy Smart PoE | HTML pages + `*.cgi` form posts, cleartext login | `EASYSMART_*` | `switch_` | `02-SWITCH-SPEC.md` |
| `archer-router-mcp` / `archer_router_mcp` / `archer-router-mcp` | Archer AX53 v1 (AX3000), UI 1.11.0 | `/cgi-bin/luci/;stok=<t>/admin/<mod>?form=<f>`, SG hardened profile | `ARCHER_ROUTER_*` | `router_` | `03-ROUTER-SPEC.md` |

Optional fourth backend, **parked**: a bridge-mode gateway/ONT (out of scope). Low value while it only relays; revisit after the three above. Hygiene item for the owner now: [redacted] — disable telnet in its admin UI if the firmware allows.

The three protocols share **nothing** below the MCP layer. The copied `core/` is scaffolding only: config, envelope, redaction, write-gating, lockout breaker, serialised request queue, transport base, CLI helpers, test harness. **Never** build a "shared stok protocol" abstraction — it is false.

Repos live under `E:/projects-working-dir/`, each MIT, **public**, each with its own `scripts/gate.py`, `scripts/check_no_secrets.py`, `.env.example`, `deploy/<name>.service.example`. Python 3.11+, `mcp` (FastMCP), `httpx`, `cryptography`, `pydantic` v2, `python-dotenv`; dev: `pytest`, `pytest-cov`, `respx`, `ruff`.

## 1. Non-negotiables (apply to every phase of every spec)

1. **Public repo = zero secrets, zero real network data.** No private IPs except RFC 5737 `192.0.2.x` placeholders, no MACs, serials, hostnames, site/camera/person names, no captured responses. `scripts/check_no_secrets.py` is a test and a pre-commit gate.
2. **No browser at runtime.** `tools/capture-login/` (headless Chrome one-shot) is an isolated dev utility with its own `package.json`; never imported, never required.
3. **Lockout safety.** Every backend: never auto-retry a failed login; one explicit login per call path; a persistent **breaker** (file under `<PREFIX>_STATE_DIR`, default `~/.local/state/<repo-name>/`) that blocks further logins after a failure until a human clears it (`<script> breaker --clear`); surface the device's attempt counters in the error; env `<PREFIX>_LOGIN_DISABLED=true` freezes auth.
4. **Writes are gated twice.** `<PREFIX>_ALLOW_WRITES=true` in env **and** `confirm_write=True` on the tool call. Otherwise a mutating tool returns `{success:false, error:{code:"WRITE_NOT_ALLOWED"}}` and performs **no network call**.
5. **Envelope.** Every tool returns `{"success": bool, "data": ..., "error": {"code","message","details"} | null}`. Never raise out of a tool.
6. **Redaction.** Any field named like `ciphertext`, `password*`, `passwd*`, `key`, `stok`, `token`, `nonce`, `cookie` is stripped from tool output recursively (pure function, returns new objects).
7. **Serialised I/O per device.** One in-flight request per backend (asyncio lock). Required for the router's rolling hash, and harmless elsewhere.
8. **Style.** Files 200–400 lines (hard max 800). Immutability (new objects, never mutate inputs). Explicit errors, never swallowed. Pydantic at every boundary (tool inputs, device responses we rely on). Logging never includes request bodies of login calls.
9. **Tests are fault-finding.** Per module: happy path (minimal), edge cases (primary), adversarial (bad/oversized input, injection in strings, unexpected device responses, login page returned instead of data), state machine (expired token mid-batch, breaker tripped, writes disabled), and no `any`-style escapes. Coverage ≥ 80% per backend, ≥ 90% for `core/`.

## 2. The leash — phase contract for agents

Every phase in the three specs is sized to fit one agent context. An agent assigned a phase MUST:

- **Build everything listed under "Deliverables". Nothing may be deferred.** The following are forbidden anywhere under the package directory at the end of a phase: `NotImplementedError`, `TODO`, `FIXME`, `XXX`, `pass  # stub`, bare `...` function bodies, `return None  # later`, tools registered without an implementation, tests marked `skip`/`xfail` without a spec citation. `scripts/gate.py` greps for these and fails.
- **Stop and report instead of stubbing** if the phase cannot be finished (context, missing input, blocked question). The report must say exactly what is missing. A truncated-but-honest phase is acceptable; a "complete" phase with stubs is a failed phase and will be re-run.
- **Touch ≤ 14 files and add ≤ 1,500 LOC per phase.** If the work is bigger, stop and propose the split.
- **Run the gate before every commit**: `python scripts/gate.py` = ruff + pytest (with coverage thresholds) + `check_no_secrets` + stub-grep + `<script> --list-tools` (must succeed and list every tool the spec names for the phases completed so far). Commit only on PASS. Conventional commits (`feat:`/`fix:`/`test:`/`docs:`/`refactor:`/`chore:`), each ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- **Never push, never create a remote.** The orchestrator reviews and publishes.
- **Never contact a real device** unless the phase explicitly says "LIVE" and gives the exact command; live phases are run by the orchestrator with the owner present.
- **End with the Phase Report** (verbatim headings): `## Deliverables built` (file list), `## Tools registered` (paste `--list-tools` output), `## Gate output` (tail of `gate.py`), `## Tests` (count, coverage %), `## Deviations` (with reasons), `## Open questions`, `## Commits`.

The orchestrator re-runs `scripts/gate.py` independently after every phase and spot-reads 2–3 files. A phase that fails the gate or has stubs is sent back with the gate output.

## 3. Template core (`<package>/core/`) — built once in NVR phase N1, copied verbatim by S1 and R1

| File | Contents |
|---|---|
| `config.py` | `GlobalSettings` (transport/host/port/state_dir/log level) and `DeviceSettings` base (host, port, username, password, verify_tls, tls_fingerprint_sha256, allow_writes, login_disabled, timeout_s). Loaded from env with prefix. Validation: host non-empty & no whitespace, 1 ≤ port ≤ 65535, timeout finite & > 0. Fails fast at startup with a clear message. |
| `envelope.py` | `ok(data)`, `fail(code, message, details=None)`; `Envelope` pydantic model. |
| `errors.py` | `DeviceError` hierarchy: `AuthFailed(attempts, max_attempts)`, `TokenExpired`, `LockedOut`, `WriteNotAllowed`, `BreakerOpen`, `ProtocolError`, `TransportError`, `ConfigError`. `to_envelope(exc)`. |
| `redact.py` | `redact(obj) -> obj'` recursive; configurable key patterns; tested for nesting, lists, no-mutation. |
| `write_gate.py` | `require_write(settings, confirm_write: bool, action: str)` → raises `WriteNotAllowed` with which gate failed. |
| `breaker.py` | `LoginBreaker(state_dir, device)`: `check()`, `record_failure(details)`, `clear()`; JSON state file; tested for persistence across instances. |
| `serial.py` | `SerialExecutor`: per-device asyncio lock + optional min-interval; `async with executor:`. |
| `transport.py` | `HttpTransport` wrapper over `httpx.AsyncClient`: timeouts, `verify_tls` or SHA-256 fingerprint pinning (custom SSL context), retries **only** for connection errors on idempotent reads (max 2), never for auth. |
| `server.py` (per repo, not in core) | FastMCP app factory; registers `<prefix>status`; stdio or streamable-HTTP bound to `<PREFIX>_MCP_HOST` (default `127.0.0.1`). |
| `cli.py` (per repo) | `serve`, `--list-tools`, `--check-auth [--login]`, `breaker --show|--clear`. |

Tool naming: `nvr_*`, `switch_*`, `router_*`; each server exposes `<prefix>status` as its healthcheck. Every tool: pydantic input model, docstring that an LLM can act on (what it does, whether it mutates, what it refuses), returns `Envelope`.

## 4. Sequencing and dependency graph

```
N1 core+auth ─► N2 catalog gateway ─► N3 typed read tools ─► N4 channels (needs channel-management.md) ─► N5 LIVE verify + ghost cleanup + re-home ─► N6 docs/deploy
                                   └──────────────────────────────────────────────┐
S0 LIVE fixture capture (owner creds) ─► S1 parsers ─► S2 client ─► S3 tools ─► S4 LIVE poe_cycle test
R0 LIVE envelope capture (owner creds) ─► R1 crypto ─► R2 auth+session ─► R3 read tools ─► R4 write tools ─► R5 LIVE reservation test
```
- N1 is done (core exists). S1 and R1 may start immediately by copying `vigi-nvr-mcp/vigi_nvr_mcp/core/`; N2/N3/N4 run in parallel on `vigi-nvr-mcp` in separate git worktrees. Different repos never collide.
- `S0` and `R0` are orchestrator-run live captures that need the owner's switch and router passwords and a window when the owner is logged out of those web UIs. Until then S1/R1 can proceed from the already-downloaded JS/pages only where the spec says so.
- Each phase = one agent run. Maximise parallelism: one agent per phase wherever the graph allows; same-repo phases use `git worktree` branches that the orchestrator merges.

## 5. Verification the orchestrator runs

- After each phase: `python scripts/gate.py`; spot-read; diff review for secrets and for "defensive" `except Exception: pass`.
- Before any LIVE phase: read the exact request bodies the tool will send (dry-run mode `<PREFIX>_DRY_RUN=true` logs the body and does not send — every write tool must support it).
- Before publishing: `git log -p | python scripts/check_no_secrets.py --stdin` over full history; if anything leaks, the repo is re-initialised, not force-pushed.

## 6. Deployment target (private, not in repo)

Three non-root systemd services on the owner's Ubuntu server, each with its own `EnvironmentFile=/etc/<repo-name>.env` (0600), streamable-HTTP on `127.0.0.1` on three ports, reachable only via Tailscale/SSH; three entries in the MCP client config. The switch backend must run there (cleartext login, wired LAN only). Real hostnames/IPs/ports live only in that env file and the owner's private notes.

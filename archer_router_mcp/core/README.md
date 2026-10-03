# core/ — reusable template

This directory is **self-contained and device-agnostic**. It imports nothing
from the rest of `archer_router_mcp` (a test enforces this), so it is copied
**verbatim** from the `vigi-nvr-mcp` template that first wrote it. Keep it that
way: device-specific code (protocols, error tables, tool names, env prefixes)
belongs outside `core/`.

| Module | Purpose |
|---|---|
| `config.py` | `DeviceSettings` / `GlobalSettings` from `<PREFIX>*` env vars; fail-fast validation that never echoes values |
| `envelope.py` | `{success, data, error}` response envelope |
| `errors.py` | Exception hierarchy with stable `kind` codes and `details()` |
| `redact.py` | Pure recursive redaction of credential-bearing fields |
| `write_gate.py` | Two-key write gate: `<PREFIX>ALLOW_WRITES=true` + per-call `confirm_write=true` |
| `breaker.py` | Login circuit breaker: per-process failure budget, `LOGIN_DISABLED`, remaining-attempts guard |
| `serial.py` | `SerialLock` serialising read-check-write operations |
| `transport.py` | httpx JSON transport: TLS flag, timeouts, size caps, token masking in logs |
| `tooling.py` | `run_tool`: wraps a tool body in an envelope, redacts, never leaks internals |
| `cli.py` | Logging setup (stderr) and envelope printing |

Dependencies: `httpx`, `pydantic` v2. Python 3.11+.

When copying: keep the tests that cover these modules, and change nothing here
that would require knowing which device is on the other end.

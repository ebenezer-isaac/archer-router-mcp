# core/ — reusable template

This directory is **self-contained and device-agnostic**. It imports nothing
from the rest of `archer_router_mcp` (a test enforces this), so sibling projects,
such as MCP servers for other local devices, copy it **verbatim** as their
starting point. Keep it that way: device-specific code (protocols, error
tables, tool names, env prefixes) belongs outside `core/`.

| Module | Purpose |
|---|---|
| `config.py` | `DeviceSettings` / `GlobalSettings` from `<PREFIX>*` env vars; fail-fast validation that never echoes values |
| `types.py` | Shared strict tool-input types. `ConfirmWrite`: the annotated `bool` every mutating tool uses for `confirm_write`, so the MCP boundary cannot coerce a truthy string/number past the write gate |
| `envelope.py` | `{success, data, error}` response envelope |
| `errors.py` | Exception hierarchy with stable `kind` codes and `details()` |
| `redact.py` | Pure recursive redaction of credential-bearing fields |
| `write_gate.py` | Two-key write gate: `<PREFIX>ALLOW_WRITES=true` + per-call `confirm_write=true`. The gate requires the boolean `True`; pair it with `types.ConfirmWrite` on the tool parameter so a truthy string/number is collapsed to `False` at the boundary (one `WRITE_REFUSED` envelope, no I/O, no schema error) rather than coerced through |
| `state.py` | `ReservationStore` — the one reservation primitive over strict, atomically-written JSON (`read_state`/`write_state`, 0600, tmp+replace): named slots (`reservations: id -> {reserved_at, meta}`), a per-key cross-process lock whose creation proves writability, a monotonic epoch high-water mark (`<key>.epoch`), atomic `reserve`/`release`/`clear`, lock-free reads, and policy-driven staleness reclaim |
| `breaker.py` | Login circuit breaker: a thin policy (admit + release-mutate) over `ReservationStore` — sticky trip, cooldown, canonical device key; no second reservation mechanism |
| `slot.py` | Generic policies over the same primitive: `SingleSlot` (one in flight per key, crash-visible, stale reclaim — the export lock / cycle guard) and `MinInterval` (reserve-before-act min-interval rate limiter — the reboot limiter) |
| `serial.py` | `SerialLock` / `GuardedWriter` serialising read-check-write operations and central dry-run |
| `transport.py` | httpx JSON transport: TLS pinning on httpx's own connection (custom httpcore backend), timeouts, size caps, token masking in logs |
| `tooling.py` | `run_tool`: wraps a tool body in an envelope, redacts, never leaks internals |
| `cli.py` | Logging setup (stderr) and envelope printing |

Dependencies: `httpx`, `pydantic` v2. Python 3.11+.

When copying: keep the tests that cover these modules, and change nothing here
that would require knowing which device is on the other end.

## Conformance suite

`tests/conformance/test_breaker_contract.py` is copied verbatim into every repo and
hashed by `core/VERSION`, so it must not name any one package. Each repo's
`tests/conftest.py` provides a one-line fixture returning its core package:

```python
@pytest.fixture
def core_pkg():
    import archer_router_mcp.core as core  # this repo's core package

    return core
```

The suite resolves `breaker` / `errors` / `state` from `core_pkg`, and its spawned
multiprocess workers import the same package by the path passed through their args
(`core_pkg.__name__`), never a global.

## Changelog

- **1.3.0** — collapsed the two reservation paths into **one** primitive. `ReservationStore`
  now owns named slots for every policy (`reserve(key, admit, mutate, *, meta, stale_after_s)`
  inserts a uniquely-identified slot under the lock; `Reservation.release` removes only its own
  id and is a logged stale no-op when its id/epoch is no longer current); the dead
  `_resolver: return False` / anonymous-`reserved=0` path is deleted (x1c r2 F1). `clear()` is a
  single locked section and the epoch is a monotonic high-water mark persisted in `<key>.epoch`
  (never regresses on corrupt recovery) (x1c r2 F2/F3). `load()`/`status()` read without the
  lock, so a `--show`/healthcheck never blocks or misreports during a concurrent login
  (x1c r2 F4). New `slot.py` (`SingleSlot`/`MinInterval`) and a `SingleSlot`-based `export_lock`
  are pure policy over the primitive; the conformance suite is parametrised over the breaker,
  single-slot and min-interval policies, so the export lock's guarantees are conformed here
  (x1c r2 F5). Slot values are `{reserved_at, meta}`; a leftover v1.2.0 ledger fails closed
  (operator `--clear`), as any schema-mismatched state file does.
- **1.2.0** — breaker reservations are named slots (`reservations: id -> reserved_at`,
  reserved count derived) with a `clear()`-bumped `epoch`, so a release in flight across
  a `breaker --clear` is a logged stale no-op and can never over-admit (x1c F1); state
  float fields reject non-finite values and the cooldown clamp is total, so a hand-edited
  `Infinity`/`NaN` cooldown self-heals instead of sticking (x1c F2); conformance suite made
  package-agnostic via the `core_pkg` fixture, with the two POSIX lock/fork cases added.

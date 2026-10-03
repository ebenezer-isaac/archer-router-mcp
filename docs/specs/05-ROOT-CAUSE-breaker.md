# ROOT-CAUSE — the lockout breaker (two rounds, not converged)

Model: claude-opus-4-8
Scope: `core/breaker.py` across `vigi-nvr-mcp`, `archer-router-mcp`, `tplink-easysmart-mcp` (+ the switch's `LoginCooldown`).
Trigger: per `04-BREAKER-PROTOCOL.md` §1, vigi-nvr-mcp auth-persist reached round 2 with an open Major (R2-F1) and did not converge; archer-router-mcp auth-session round 2 also sits open (RA-F1). Two rounds without convergence ⇒ this is a **design finding**. Deliverable below: the structural cause, one greenfield refactor spec, blast radius, and the generalisation.
Findings this must make impossible by construction: **AL-F1**, **R2 auth-persist F1 / F2 / F3**, **router RA-F1**.
No code, no tests, no fixes were written. No repo was touched.

---

## 1. The shape of the cause

### 1.1 One fact, many places, reconciled by checks

The breaker exists to hold **one fact**: *"how much of the device's login budget is already spent, and may this process spend one more login attempt right now."* Every finding across both rounds is the same fact being **kept in more than one place and reconciled by a check**, exactly the shape the protocol names (§1: "usually one fact kept in more than one place and reconciled by checks").

The fact is currently split across four axes, and each repair *at the reported level* added a fifth place that then had to agree with the other four:

**(a) The decision and the record are two separate steps on a non-serialised store.**
`check()` is a **pure read** of the ledger ("are there already ≥ budget failures?"); `record_failure()` is a **later read-modify-write** ("load, +1, save"). Nothing serialises the two. So the authoritative count lives in two places at two times — the value the admit decision read, and the value the record write later computed — and they are reconciled only by hope that nothing ran in between.

- This is **R2 auth-persist F1** (vigi): two processes both `check()` an empty ledger (both admit), both POST a real login, and the lost-update on `record_failure` leaves `failed=1` after two failures. Budget of 1, two attempts to the device.
- It is also **RA-F1** (router) and the switch's write path: "unwritable" is only ever *discovered during the write*, while the admit decision was a pure read that already said yes. The decision passed before the record could fail, so an unwritable store reads as "no failures = allow" instead of "state unknown = deny." Fail open.

**(b) The identity under which the fact is filed is a raw string.**
The ledger is keyed by `settings.host` run through a per-file ad-hoc regex. The same device under two spellings is two files, each holding its own independent copy of the fact, each with its own full budget.

- This is **R2 auth-persist F3** (vigi): `fe80::1` and `fe80:0:0:0:0:0:0:1` (and `NVR.local` vs `nvr.local` on the case-sensitive deploy FS) produce `breaker-fe80__1.json` and `breaker-fe80_0_0_0_0_0_0_1.json` — two budgets for one device, and a `--clear` typed one way never clears the breaker opened the other way.

**(c) The type of the fact is trusted at load, not proven.**
`_load()` validates that JSON parses and the top level is a dict, then **trusts the field types** and lets `int(...)` do the real type-checking *outside* the fail-closed guard.

- This is **R2 auth-persist F2** (vigi): `{"failed":"oops"}` → uncaught `ValueError`; `{"failed":[1]}` → uncaught `TypeError` (`--show` crashes with a traceback); and the dangerous one, `{"failed":false}` → `int(False)==0` → the breaker reads **zero failures and fails open**. `false` and `"1"` silently coerce where they must refuse.

**(d) The contract itself is kept in three divergent copies.**
`core/` is "written once and copied verbatim" (MASTER-PLAN §3), but the three `breaker.py` files have drifted into three different designs of the same contract. The fact's own *rules* now live in three places that disagree — so a fix proven in one repo is not a fix in the others, and a breaker round on one cannot clear the other two. See the table in §1.3.

### 1.2 Why every repair at the reported level adds another place to agree

Each round's fix kept the fact split and added a reconciliation site instead of removing the split:

- **R1-F1 → R1 fix:** "the breaker is in-memory." The fix persisted it to a file. That *added a second home* for the count (the in-memory admit decision **plus** the on-disk record) with nothing serialising them — which is precisely what **R2-F1** then broke. Persisting closed the *sequential-restart* hole and opened the *concurrent* one.
- **Fixing F2 at its level** means adding type guards to `_load` in each file — another branch every copy must carry identically, and the router/switch already carry *different* versions of that branch (router returns a `corrupt` ledger → `LockoutGuard`; vigi raises `BreakerOpen`; the switch returns `open+corrupt` → `LockoutGuard`). Three spellings of "handle a bad type," none shared.
- **Fixing F3 at its level** means adding a key-normalisation step that the store, the CLI and the tests must all compute the same way — a fourth site to keep in sync, in three repos.
- **Fixing RA-F1 at its level** (the triage's own note) means making `record_failure`'s write fail closed *and* teaching `check()` to prove writability by writing a sentinel — i.e. giving the pure-read decision a *second* I/O step that must agree with the write step. Two steps again.

Every one of these keeps "decide" and "record" as two steps and keeps three copies, so every one needs a new agreement (a lock, a re-read, a type guard, a normaliser) re-made three times. That is the signature of a structural cause: the level the findings are reported at cannot hold the invariant, because the invariant is "these must be one step, in one place, filed under one identity, in one implementation," and none of those is true.

### 1.3 Three divergent copies of one contract

All three were meant to be byte-identical. They are not. Behavioural differences:

| Axis | `vigi-nvr-mcp` | `archer-router-mcp` | `tplink-easysmart-mcp` |
|---|---|---|---|
| **State model** | counter budget: `failed`/`successful`/`last_failure` | counter budget: `failed`/`successful`/`last_failure`/`corrupt` | **boolean** `open` flag (trip on first failure); no counter |
| **Unwritable dir** | `_save` → `BreakerOpen` (write fails closed) **but** `check` is pure read ⇒ concurrent fail-open (F1) | `save_ledger` re-raises **raw `OSError`** ⇒ fail OPEN, `INTERNAL_ERROR` (RA-F1) | `_atomic_write` re-raises **raw exception** ⇒ fail OPEN (same shape as router) |
| **Corrupt file** | raises **`BreakerOpen`** on load | returns `LoginLedger(corrupt=True)` → **`LockoutGuard`** | returns `BreakerState(open=True,corrupt=True)` → **`LockoutGuard`** |
| **Wrong types** | **not handled**: `int()` escapes as `ValueError`/`TypeError`; `false`→`0` fail-open (F2) | strict `isinstance(int)`, reject `bool`, reject `<0` → `corrupt` (handled) | validates `open` is `bool` → `corrupt` (handled); other fields trusted |
| **Concurrency** | no cross-process lock → lost update (F1) | no lock | no lock |
| **Success semantics** | `record_success` bumps `successful`, does **not** clear `failed` | same (bumps `successful`, keeps `failed`) | n/a (boolean); success not recorded; **cooldown** cleared on confirm |
| **Cooldown** | none | none | **separate `LoginCooldown` class** in `switch/auth.py` (not core): `cooldown-<slug>.json`, wall-clock `last_failure_at`, corrupt/unreadable ⇒ "failure just happened" (fail closed), injectable `now` |
| **Key normalisation** | raw `settings.host`, `.strip()` only; regex `[^A-Za-z0-9._-]` (**no `+`**, per-char sub) → `breaker-<host>.json` | **no device key at all**: single `login-breaker.json` (one router assumed) | `_slug`: regex `[^A-Za-z0-9._-]+` (**with `+`**), truncate 64, **no lowercase / no `ipaddress`** → `breaker-<slug>.json` |
| **`check` signature** | `check(*, explicit: bool)` (handles `login_disabled` + budget) | `check(*, explicit: bool)` (handles `corrupt` + `login_disabled` + budget) | `check()` **no args**; `login_disabled` handled in auth `_gate`, not breaker |
| **`check_remaining_attempts`** | carries `max_attempts` + `lock_seconds_left` (R1-F2 fix) | **older signature**, no counter fields | not present (boolean model) |
| **File mode** | `mkdir(0o700)` + `os.open(...,0o600)` | `mkdir` (no mode) + `chmod(0o600)` suppressed | `mkdir` (no mode) + `chmod(0o600)` **not** suppressed (can raise on Windows) |
| **CLI exit codes** | `core/cli.py` maps `BREAKER_OPEN→3`, `0/1/2/3/4` | `core/cli.py` returns **`0/1` only** | `core/cli.py` returns **`0/1` only** |
| **Constructor** | `LoginBreaker(state_dir, device, settings)` | `LoginBreaker(state_dir, settings)` (no device) | `LoginBreaker(state_dir, device, *, clear_hint)` (no settings) |

Three constructors, three state models, three corrupt-handling strategies, two of three fail **open** on an unwritable dir, three different filename regexes, and only one of three differentiates CLI exit codes. This is not one contract copied verbatim; it is three contracts.

---

## 2. Refactor spec — ONE canonical `core/breaker.py`

**Principle:** collapse the four splits of §1.1 into one. There is exactly one authoritative place for the fact (a single locked, schema-validated, atomically-written ledger file per device), the admit decision and the budget increment are **the same write**, the identity is derived once, the implementation is one file hashed and copied verbatim, and the failing state of *any* store operation is **refuse** (fail closed) — never a raw exception, never a coercion, never a pure-read "allow."

Device-agnostic: no device vocabulary in this file. Copied verbatim into all three packages' `core/`.

### (a) admit-and-reserve is one atomic step

```
reserve_attempt() -> Reservation          # increments the attempt count under the
                                          # cross-process lock BEFORE any network I/O
reservation.release(outcome, *, cooldown_s=None, failure=None)
```

- `reserve_attempt()` takes the per-device cross-process lock (see (b)), loads and validates the ledger (see (d)), applies policy (login-disabled, tripped flag, cooldown, budget), and — **in the same locked, atomic write** — increments `reserved` and persists before returning. The increment **is** the admission: there is no separate "decide" read. Two processes cannot both pass because the second one loads a ledger whose `reserved` already reflects the first's increment, and `reserved + failures >= max_failures` refuses it.
- The `Reservation` is a handle to that committed increment. `release(SUCCESS)` decrements `reserved` and bumps `successes`; `release(FAILURE, failure=...)` decrements `reserved`, bumps `failures`, sets `tripped` if `failures >= max_failures`, and optionally sets `cooldown_until`. Both are a single locked atomic write.
- **Crash leaves a reserved-but-unresolved attempt that counts against the budget until `--clear` (fail closed).** A holder that dies (SIGKILL, power loss) never runs `release`; its `+1` on `reserved` stays on disk, so `reserved + failures` still counts it and the budget is spent conservatively. `Reservation` is also a context manager: an unresolved `__exit__` (normal or exceptional) records a **failure** (fail closed), so only an explicit `release(SUCCESS)` ever counts as a success. Recovery is a human `--clear`, by design — a crashed login is treated as a possibly-landed attempt.
- No pure-read admit path exists anywhere. (The credential-free challenge/`device_config`/`GET /` probes stay *outside* the breaker, as all three already do — they spend no attempt.)

### (b) cross-process lock

- Portable advisory lock on a **dedicated `<key>.lock` file** next to the ledger: POSIX `fcntl.flock(fd, LOCK_EX)`; Windows fallback `msvcrt.locking(fd, LK_LOCK, 1)`. Selected once at import by platform; both wrapped in one `with _device_lock(path):` context manager.
- **Scope:** the entire load → validate → policy → increment → write sequence for one device key (and likewise the whole of `release`). The lock is held for the file ops only — **never across network I/O**; the network login happens after `reserve_attempt()` has returned and released the lock, holding only the `Reservation`.
- **Timeout:** bounded blocking acquire (default 5 s, `max_failures`-independent). If the lock cannot be acquired within the timeout → `BreakerOpen` ("breaker busy; refusing to risk a concurrent attempt"). Refuse, never proceed unlocked.
- **Lock cannot be taken (open/create fails)** → `BreakerOpen` (this is also the writability proof, (c)).

### (c) writability proven before admitting

- Acquiring the lock **requires creating/opening `<key>.lock` for writing** (`O_CREAT|O_WRONLY`, and `mkdir(state_dir, 0o700, exist_ok=True)` first). If the directory is read-only, missing-and-uncreatable, or points at a non-directory, that open fails → `BreakerOpen` with a clear message, **before any ledger read and before any admission**.
- Because admission cannot happen without first writing (the lock file) and incrementing (the ledger), an unwritable store **cannot** fail open on any platform. This kills RA-F1 and the switch's write-path fail-open at the root: "unwritable" is discovered at admit time, not at record time, and admit-time failure is refusal.

### (d) schema-validated ledger

- A pydantic v2 model, `model_config = ConfigDict(strict=True, extra="forbid")`, with a `version: int` field:

  ```
  class BreakerLedger(BaseModel):   # strict=True, extra="forbid"
      version: int
      key: str
      reserved: int                 # >= 0
      failures: int                 # >= 0
      successes: int                # >= 0
      tripped: bool
      cooldown_until: float | None
      last_failure: dict[str, Any] | None
      last_update: float
  ```
- Load = `json.loads` then `BreakerLedger.model_validate`. **Any** failure — `OSError`, `JSONDecodeError`, `ValidationError`, non-dict, unknown `version` — ⇒ `BreakerOpen` (fail closed), with a message naming the file and `breaker --clear`. Strict mode means `false` never becomes `0`, `"1"` never becomes `1`, `[1]` never slips through: `{"failed":false}` is a `ValidationError` ⇒ refuse, not allow. This kills F2's crash *and* its fail-open in one rule, and makes it identical in all three repos.
- The writer emits only this schema, with `version` current; forward-compat is an explicit version bump + migration, never a silent "unknown keys ignored."

### (e) canonical device key

- One function, the single source of the identity:

  ```
  def canonical_device_key(host: str) -> str:
      h = host.strip().lower()
      try:
          return ipaddress.ip_address(h).compressed      # fe80::1 == fe80:0:0:0:0:0:0:1
      except ValueError:
          return h                                        # lowercased hostname
  ```
- The filename is `breaker-<_safe(canonical_device_key(host))>.json` / `.lock`, where `_safe` is the **one** shared sanitiser (fixing the `+`/no-`+` regex drift). `LoginBreaker` takes `device_key` **already canonicalised**, and the **store, the CLI, and the tests all call `canonical_device_key`** — so `--show`/`--clear` and the running server cannot land on different files. This kills F3 and removes the router's "no key at all" special case (the router passes its one host through the same function).

### (f) budget semantics

- Default `max_failures = 1` (env `<PREFIX>_MAX_LOGIN_FAILURES`, lenient numeric parse, strict key).
- **A raised `MAX_LOGIN_FAILURES` does not silently reopen a tripped breaker.** `tripped` is a sticky boolean set the moment `failures >= max_failures` at any `release`/`reserve`; once set, `reserve_attempt()` refuses regardless of the current env budget. Only `clear()` (`breaker --clear`) resets it. So lowering risk tomorrow by raising the budget cannot silently un-trip yesterday's lockout.
- **A success does not clear failures.** `release(SUCCESS)` bumps `successes` and decrements `reserved` only; `failures` is untouched. *Justification:* the breaker's job is to protect the **device-side** lockout counter, which on the VIGI and Archer firmwares is not guaranteed to reset on a single successful login within the lock window; a breaker that forgave failures on success could oscillate (fail, succeed, fail, …) and still walk the account into the hard device lock while reporting itself healthy. Conservative = fail closed = failures are sticky until a human has seen them and cleared. (`release(SUCCESS)` **does** clear `cooldown_until`, since a success proves the soft-busy condition has passed — see (g).)

### (g) cooldown as a first-class state

- `cooldown_until: float | None` in the ledger — a **wall-clock epoch** (survives restart; monotonic cannot). Remaining is computed `max(0, cooldown_until - clock())` and **clamped at 0** (monotonic-safe against a wall clock that jumps backward: never report a negative or absurd remaining; a clock that leaps forward only ends the cooldown early, the safe direction).
- `reserve_attempt()` refuses with `BreakerOpen`/`Cooldown` (CLI exit 3) while `clock() < cooldown_until`.
- Set by `release(FAILURE, cooldown_s=...)`: the switch's `errType` 3/4/5 pass a short `cooldown_s` (session-busy/timeout, **not** a credential failure — see the blast-radius note that 3/4/5 must *not* increment `failures` toward `tripped`; they set a cooldown and decrement `reserved` only); the router's `EXCEEDED_MAX_ATTEMPTS` passes `cooldown_s = seconds_left` (~2 h). One mechanism serves both the switch cooldown and the router's 2-hour lock. This folds the switch's separate `LoginCooldown` file into the one ledger.

### (h) store layout and public API

- **Layout:** one `<state_dir>/breaker-<key>.json` + one `<state_dir>/breaker-<key>.lock` per device. `state_dir` created `0o700`; ledger file `0o600` (via `os.open(...,0o600)`; on Windows the mode is a no-op and the file inherits the dir ACL — deploy target is Ubuntu, MASTER-PLAN §6). Writes are tmp-file + `os.replace` (atomic), tmp unlinked on any error. The intermediate parents of `state_dir` are created with an explicit `0o700` walk (closing the vigi "only the leaf is 0700" minor).
- **Public API** (device-agnostic):

  ```
  class LoginBreaker:
      def __init__(self, state_dir: Path, device_key: str, *,
                   max_failures: int = 1, clock: Callable[[], float] = time.time) -> None: ...
      def reserve_attempt(self) -> Reservation         # raises BreakerOpen / LoginDisabled / Cooldown
      def status(self) -> dict[str, Any]               # non-secret snapshot for --show / healthcheck
      def clear(self) -> None                          # breaker --clear
      @property
      def cooldown_until(self) -> float | None

  class Reservation:
      def release(self, outcome: Outcome, *, cooldown_s: float | None = None,
                  failure: dict[str, Any] | None = None) -> None
      def __enter__(self) -> "Reservation"; def __exit__(self, *exc) -> None   # unresolved ⇒ FAILURE
  ```

  `device_key` is pre-canonicalised by the caller via `canonical_device_key`. `login_disabled` is **owned by the breaker again** (`reserve_attempt` raises before any I/O) so the switch's out-of-band `_gate` check is removed and all three behave identically. `status()` returns `{state: closed|open|cooldown|disabled, reserved, failures, successes, tripped, cooldown_remaining_s, max_failures, last_failure, path}` — no secret, no raw body.
- **CLI (`breaker --show|--clear`)**, identical in `core/cli.py` of all three:
  - `breaker --show` → print `status()` as sorted JSON, **exit 0** (reading the breaker is not itself a failure).
  - `breaker --clear` → `clear()`, print confirmation, **exit 0**.
  - Exit-code map promoted into the shared `core/cli.py` (router and switch currently only do 0/1): `0` success · `1` auth failed · `2` config error · `3` `BREAKER_OPEN`/`LOGIN_REFUSED`/`COOLDOWN`/login-disabled · `4` transport/`TLS_PIN_MISMATCH`. A `--show` on a *corrupt* file still exits 0 and prints `{state:"open", reason:"unreadable/invalid"}` — it must never crash (killing F2's `--show` traceback).

### (i) conformance test suite

One device-agnostic file, `tests/conformance/test_breaker_contract.py`, **copied verbatim** into all three repos (hashed like `core/`, see (j)) and run by each repo's gate. It constructs a real `LoginBreaker` against a real `tmp_path` state dir (matching how all three repos already fake the store — vigi's `conftest` monkeypatches `default_state_dir` to a temp dir, router's `build_components` takes `state_dir=tmp`, switch's `make_settings` sets `state_dir=tmp`; none use a fake store object, so real FS + real processes are the right fixture). Cases, each citing the finding it closes:

1. **Persistence across instances (AL-F1):** instance A reserves+fails; a fresh `LoginBreaker` on the same dir/key refuses — budget survives "restart."
2. **Corrupt / truncated / non-dict (R2-F2, router/switch corrupt axes):** each ⇒ `BreakerOpen`, no raw exception.
3. **Wrong types (R2-F2):** `{"failed":"oops"}`, `{"failed":[1]}`, and crucially **`{"failed":false}` / `{"reserved":false}`** ⇒ `BreakerOpen` (never coerced to 0, never fail-open).
4. **Unwritable store (RA-F1, R2 unwritable, switch write path):** state dir unwritable / parent is a regular file / read-only FS ⇒ `reserve_attempt()` raises `BreakerOpen` **before any admission**; assert no attempt is admitted and nothing is `INTERNAL_ERROR`. Also: an unwritable dir on the *resolve* path does not turn a would-be success into an error.
5. **Real multi-process concurrency (R2-F1):** spawn N (≥ 8) real `multiprocessing.Process` workers that each call `reserve_attempt()` on one key with `max_failures=1`; assert **exactly one** reservation succeeds and the rest raise `BreakerOpen`. Repeat with the processes all failing to prove the flock serialises the read-modify-write (no lost update: final `failures + reserved` equals the number admitted). This is the test the single-process barrier test in R2 could only approximate.
6. **Key normalisation (R2-F3):** `fe80::1` vs `fe80:0:0:0:0:0:0:1`, and `NVR.local` vs `nvr.local`, share one ledger and one budget; `--clear` under either spelling clears the other.
7. **Budget semantics (f):** raising `max_failures` after a trip does **not** reopen (tripped sticky until `clear`); a `release(SUCCESS)` does **not** clear `failures`.
8. **Crash fail-closed (a):** a reservation that is never released (simulated by dropping the handle / killing a child between reserve and release) leaves `reserved` elevated and the next `reserve_attempt()` refuses until `clear`.
9. **Cooldown (g):** `release(FAILURE, cooldown_s=T)` makes `reserve_attempt()` refuse until `clock()` passes `cooldown_until`; a backward clock jump never yields negative remaining; `release(SUCCESS)` clears the cooldown.
10. **Secrets (claim):** no password/token/nonce/ciphertext ever appears in the ledger file or any breaker error/`status()` string.
11. **Mode bits (POSIX-only, skip on Windows):** dir `0o700`, file `0o600`.

### (j) core identity mechanism (so the three copies cannot drift again)

- Add `core/VERSION` carrying a semver **and** a manifest of `sha256` for every file under `core/` (and for `tests/conformance/test_breaker_contract.py`), with one documented exception: the single `core/README.md` line that names the package.
- Each repo ships `tests/test_core_identity.py` that recomputes the sha256 of every `core/` file and the conformance test, and asserts they equal `core/VERSION`'s manifest. Any drift fails the gate — the three copies cannot diverge silently again (this is the test that would have caught the three-way split in §1.3).
- **Sync procedure:** edit the canonical files **only** in `vigi-nvr-mcp/vigi_nvr_mcp/core/`; bump `core/VERSION` and regenerate the manifest; copy the files **verbatim** into `archer_router_mcp/core/` and `tplink_easysmart_mcp/core/` (and the conformance test into each `tests/conformance/`); run the conformance suite **and** the identity test in all three repos; commit the three together. This is MASTER-PLAN X1, now with teeth.

---

## 3. Blast radius

Every call site that must change (file : function), and the constraints on the fixer.

**`vigi-nvr-mcp`**
- `vigi_nvr_mcp/auth.py : Authenticator.__init__` — build `LoginBreaker(state_dir, canonical_device_key(settings.host), max_failures=settings.max_login_failures)`; drop passing `settings`.
- `vigi_nvr_mcp/auth.py : Authenticator._login_locked` — replace `self._breaker.check(explicit=...)` + later `record_success`/`record_failure` with: `with self._breaker.reserve_attempt() as res:` around `_attempt`, then `res.release(SUCCESS)` on a good token / `res.release(FAILURE, failure=...)` on `AuthFailed`. `-40410 NonceInvalid` must `release(FAILURE)` **without** counting toward `failures` only if LIVE proves the nonce-POST is uncounted — default conservative: it is a spent attempt (release FAILURE). The reserve wraps `_attempt`'s single login POST; the credential-free `get_challenge` stays outside.
- `vigi_nvr_mcp/auth.py : Authenticator._record_failure / token / login / status` — `_record_failure` returns the `AuthFailed` but the ledger write moves into `res.release`; `status()` → `self._breaker.status()`.
- `vigi_nvr_mcp/cli.py : _breaker_for, run_breaker, _parse_breaker` — construct via `canonical_device_key`; `run_breaker` uses `status()`; exit codes via the shared map.
- `vigi_nvr_mcp/core/cli.py` — already has the 0/1/2/3/4 map; keep as the canonical one.

**`archer-router-mcp`**
- `archer_router_mcp/server.py : Components.from_env` — construct `LoginBreaker(state_dir, canonical_device_key(host), max_failures=...)` (it currently builds a keyless single-file breaker).
- `archer_router_mcp/auth.py : RouterAuthenticator.login` — `reserve_attempt()` immediately **before `_post_login`** (pre-login `fetch_keys`/`fetch_auth` are credential-free, stay outside); wrap the POST + optional authorised `confirm=true` takeover in **one** reservation (the takeover is part of the same explicit call, not a second attempt).
- `archer_router_mcp/auth.py : RouterAuthenticator._raise_login_error` — `LOGIN_FAILED` → `res.release(FAILURE, failure=...)`; `EXCEEDED_MAX_ATTEMPTS` → `res.release(FAILURE, cooldown_s=seconds_left, failure=...)`; others → `res.release(FAILURE)`.
- `archer_router_mcp/auth.py : RouterAuthenticator._handle_conflict / login success path` — `record_success` → `res.release(SUCCESS)`.
- `archer_router_mcp/cli.py : _run_breaker` + `core/cli.py` — adopt the shared `status()`, `--show|--clear`, and the **0/1/2/3/4 exit map** (currently 0/1 only).

**`tplink-easysmart-mcp`**
- `tplink_easysmart_mcp/switch/auth.py` — **delete the local `LoginCooldown` class**; its state folds into the one ledger's `cooldown_until`.
- `tplink_easysmart_mcp/switch/auth.py : SwitchAuthenticator.__init__` — take one `LoginBreaker` (drop the separate `cooldown` param).
- `switch/auth.py : SwitchAuthenticator._gate` — replace `self._breaker.check()` + `self._cooldown.check()` + the local `login_disabled` branch with `res = self._breaker.reserve_attempt()` (which now owns login-disabled, budget and cooldown); hold `res` through the POST.
- `switch/auth.py : _map_err_type` — `errType` 1/2/6/unknown → `res.release(FAILURE)` (trips); `errType` 3/4/5 → `res.release(FAILURE, cooldown_s=...)` as a **cooldown, not a budget failure** (must not push `failures` toward `tripped`); `errType` 0 confirmed → `res.release(SUCCESS)` (clears cooldown).
- `switch/auth.py : _fail_closed` (restored-account / unsupported-variant) and `_confirm` (login-silently-ignored) → `res.release(FAILURE, ...)` / `res.release(SUCCESS)` accordingly.
- Construction site of the breaker/cooldown (switch backend/components factory) — build the one `LoginBreaker(state_dir, canonical_device_key(host), ...)`.
- `tplink_easysmart_mcp/cli.py : _breaker` + `core/cli.py` — shared `status()`, `--show|--clear`, **0/1/2/3/4 exit map** (currently 0/1).

**The fixer must NOT:**
- Produce any per-repo variant of `core/breaker.py` or the conformance test — they are byte-identical and the identity test (2j) enforces it. Device specifics live in the device `auth.py`, never in `core/`.
- Re-introduce a pure-read `check()` or any admit path that does not go through `reserve_attempt()`'s locked write.
- Catch `BreakerOpen`/`LoginDisabled`/`Cooldown` (or any store exception) to "keep going," retry, or downgrade to `INTERNAL_ERROR` — they must surface as the mapped envelope and exit code. No `except Exception: pass`, no swallowing on the write path.
- Keep the switch's separate `LoginCooldown` file, the router's keyless single file, or the three different filename regexes — one `canonical_device_key` + one `_safe`.
- Weaken, skip, or fork any conformance case to make a repo pass (protocol §4 / §3).

---

## 4. The same pattern elsewhere — a generic primitive

The structural pattern — **decide-then-record on a shared state file with no lock, no schema, and no writability proof** — is not confined to the breaker. The switch's `cycle_in_progress` marker (S3: read "is a cycle running?", decide, then write the marker — two overlapping `switch_poe_cycle` calls can both read "no" and both start), the router's reboot rate-limit timestamp (R4: read last-reboot time, decide, write new time — the triage already flags that RA-F1's `save_ledger`-raises shape recurs here, and the lost-update shape recurs too), the router's presence store (read-append log), and the NVR export serial lock are all the same shape: a single fact (in-progress? last-time? next-serial?) read and written as two unserialised steps on a file whose type and writability are trusted. Each will grow its own F1/F2/RA-F1 the moment it is breakered. The refactor should therefore **not** stop at the breaker: extract the lock + strict-schema + writability-proof + atomic read-modify-write into a generic `core/state.py` primitive — `AtomicStateFile` / `ReservationStore` — and build `LoginBreaker` as a thin policy layer over it (reserve/release = a reservation; cooldown/tripped = policy fields). The PoE cycle marker becomes a `Reservation` (one in-flight per port), the reboot rate-limit and export serial become atomic read-modify-writes through the same store, and the presence log an atomic append — each inheriting fail-closed-on-unwritable and schema-validated-or-refuse **for free**, hashed and copied verbatim under the same X1 identity test. That turns "make these four findings impossible" into "make this class of finding impossible," which is the point of a root-cause pass rather than a third breaker battery.

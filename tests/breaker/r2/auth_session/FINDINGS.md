# Breaker round 2 — vector auth-session — archer-router-mcp @ 7c1d54c

Model: claude-opus-4-8
Branch: breaker/r2-auth-session (from 7c1d54c)

Claim attacked (R2 auth + session), verbatim excerpt:

> "In `archer-router-mcp` (R2), `RouterAuthenticator.login()` sends exactly one login
> POST per explicit call and never auto-retries a failed login; the file-backed breaker
> persists across process instances, is written atomically with mode 0600, and a corrupt,
> truncated or unwritable state file makes it fail CLOSED (no login possible, clear error);
> `LOGIN_DISABLED` prevents every login POST while still allowing the credential-free
> `device_config` probe; `user conflict` never evicts the owner's session unless BOTH
> `ARCHER_ROUTER_FORCE_SESSION_TAKEOVER=true` AND the call passed `force_takeover=True`,
> and then resends `confirm:true` exactly once; `RouterSession` is single-flight, keeps the
> rolling hash correct across many requests under both envelopes, re-logs-in and replays
> exactly once on `timeout` and never on `login failed`/`exceeded max attempts`, and logs
> out on context exit even after an exception; the TLS fingerprint pin fails closed before
> any request body is sent, and `nvr`-style unknown `ARCHER_ROUTER_*` env keys fail loudly;
> no password, AES key/IV, `stok`, `sysauth` cookie or signature appears in any log, repr,
> exception or envelope; `is_support()`/`should_skip_encrypt()` reproduce the bundle for all
> five certification sets."

Method: read `auth.py`, `session.py`, `transport.py`, `errors.py`, `server.py`, `cli.py`,
`core/breaker.py`, `core/config.py`, `core/transport.py`, `core/redact.py`, `core/tooling.py`,
`crypto.py`, `tests/fakes.py` and the existing R2 suite (353 tests, all green at this SHA).
Attacked each clause with fakes only (no network), using the existing `FakeRouter`, plus one
empirical probe. The R1 breaker vectors
(`tests/breaker/r1/crypto/fixtures/breaker_vectors.json`) were reused to confirm the
`is_support` clause.

## Axes with no finding (verified, or not reachable)

- **One login POST / no auto-retry** (`login()`): a single `_post_login`; `login failed`,
  `exceeded max attempts`, `multiple login`, `timeout` each raise with no retry. The only
  second POST is the authorised takeover (`confirm=true`), sent at most once. Matches the claim.
- **Breaker persists / corrupt / truncated -> fail closed**: `load_ledger` returns
  `corrupt=True` for unparseable, non-dict, negative/`"x"`/empty content, and for an
  unreadable-but-present file (`OSError`); `check` then raises `LockoutGuard`. A **state file
  that is itself a directory** also fails closed (read raises `IsADirectoryError` -> corrupt).
  Confirmed. **The "unwritable" member of that same list does NOT fail closed — see F1.**
- **`LOGIN_DISABLED`**: `login()` calls `breaker.check` (-> `LockoutGuard`) before any
  `fetch_keys`/`fetch_auth`/login POST; the pre-login reads go through `_read_prelogin`, which
  never consults the breaker, so the credential-free `device_config` probe still answers.
  `router_check_auth --login` and `router_login` both route through the same gated
  `session.login`. Honoured.
- **user conflict / takeover**: `_handle_conflict` requires `settings.force_session_takeover and
  force_takeover`; one `confirm=true` resend, and a second `user conflict` raises `SessionConflict`
  (no third POST). The implicit/lazy and timeout-replay logins pass `force_takeover=False`, so they
  never evict. (Observation, not a finding: the `router_login` and `router_check_auth --login` tools
  hard-code `force_takeover=True`, so at the tool surface the *only* remaining takeover gate is the
  env var — the per-call gate guards only the implicit paths. This does not contradict the literal
  claim and matches the R2 spec, which gates takeover on the env var alone.)
- **Single-flight / rolling hash / timeout replay / logout on exit**: every `login`/`request`/
  `logout` runs under one non-reentrant `SerialLock`; the lazy-login check sits inside the locked
  `action`, so concurrent `request`s cannot double-login. The rolling hash is recomputed per
  request from that request's own `data_b64` (`crypto.rolling_hash`), so order/concurrency cannot
  desync it under either envelope. `request` re-logs-in + replays exactly once on `TokenExpired`
  (a second `timeout` propagates — no third login); `login failed`/`exceeded max attempts` surface
  as non-`TokenExpired` errors and are never replayed. `__aexit__` always calls `logout`, which
  swallows only `DeviceError` and still clears local state; the lock is free by `__aexit__` time
  (each `request` releases it on return/raise), so no deadlock. As claimed.
- **TLS pin fails closed before the body**: `ArcherTransport.post` awaits `_enforce_pin()` (->
  `verify_fingerprint_pin`, which treats a missing observation as a mismatch) before building the
  URL or calling `client.post`. Leaf cert on both sides; colon/space/case normalised on both sides.
  (Minor latent weakness, not a finding: the probe is cached for the client's life, so a mid-session
  certificate swap is not re-checked — likelihood 1.)
- **Unknown env keys fail loudly**: `_reject_unknown_keys` raises `ConfigError` for any
  `ARCHER_ROUTER_*` (and `ARCHER_MCP_*`) suffix not in the whitelist (e.g. `..._ALLOW_WRITE`).
  Confirmed by the existing suite.
- **Secrets never leak**: `AesKey.key/iv` and `Session.stok` are `field(repr=False)`; `password`
  is a pydantic `SecretStr`; `transport` masks `;stok=...` in every log line (incl. httpx's own via
  a logging filter) and never logs a body; `run_tool` redacts tool output and converts unexpected
  exceptions to a generic `INTERNAL_ERROR`. No password/AES key/IV/`stok`/`sysauth`/signature was
  found in any repr, log, exception message or envelope on the auth/session paths.
- **`is_support()` / `should_skip_encrypt()` across five cert sets**: `crypto.is_support` matches
  the bundle's authoritative `isSupport_by_cert` output for SG, US-only, empty, RG and CE_RED (all
  non-SG sets -> every flag off, SG -> the six SG flags on), because the vectors were generated with
  cert strings that only the SG value matches; `should_skip_encrypt(True)=True` and `base_url` is
  always `https`, reproducing the bundle's HTTPS-plain default. Matches.
- **Encoding edges**: `build_login_body`/`build_request_body` percent-encode via
  `quote(..., safe="")`, so `&`/`=`/`%`/unicode in a password or param cannot break the body;
  `errorCode` normalises int/str/nested; a valid-AES-but-not-JSON or undecryptable response becomes
  `TokenExpired`/`ProtocolError`, never a crash; a non-canonical/too-small modulus from a crafted
  LAN response raises `ValueError` in `crypto`, surfaced as a clean `INVALID_INPUT` envelope (no
  unhandled exception, no secret). No finding.

## F1  "Unwritable breaker state file" fails OPEN, not closed — the lockout-safety net silently vanishes — Impact 3 (the breaker's one job is to stop repeated failed logins from tripping the router's ~2-hour admin lockout; with it defeated the admin account is driven to that lock and the router admin is unreachable until it expires — the "locks the admin account" reading of the rubric is Impact 4) x Likelihood 2 (operator misconfiguration: a read-only state FS, a mis-permissioned systemd `StateDirectory`, or `ARCHER_ROUTER_STATE_DIR` pointed at a non-directory — on record for state-dir hardening; needs wrong/stale creds to actually lock out; adversary-reading? no — a LAN host cannot choose this state) = 6 Major

Test: tests/breaker/r2/auth_session/test_breaker_unwritable_fails_open.py::test_unwritable_state_dir_should_fail_closed_no_login_no_internal_error
Test: tests/breaker/r2/auth_session/test_breaker_unwritable_fails_open.py::test_unwritable_state_dir_breaker_never_trips_fails_open
(control, passes: ::test_control_writable_state_dir_does_trip_after_one_failure)

What happens: with `ARCHER_ROUTER_STATE_DIR` pointed at a path that cannot be written (the test
uses a dir whose parent is a regular file; a read-only FS behaves identically), the first login is
NOT refused — `LoginBreaker.check` only reads, and `load_ledger` sees no file and returns an empty
*allowing* ledger, so a login POST leaves the process (empirically `login_posts == 1`; the claim
says an unwritable breaker means "no login possible"). On a failed login, `_raise_login_error` calls
`breaker.record_failure` -> `save_ledger`, whose `path.parent.mkdir(...)` raises a raw `OSError`
(`FileExistsError`/`NotADirectoryError`) that pre-empts the `AuthFailed`; `run_tool` reports it as a
generic `INTERNAL_ERROR` ("Unexpected server error; see server logs"), not the "clear error" the
claim promises. Crucially the failure is never persisted, so the next attempt reads the same empty
ledger and is allowed again: the budget-of-1 breaker never trips and attempt after attempt reaches
the device (empirically `login_posts == 2` on the second call, `snapshot().failed == 0` throughout).
The corrupt and truncated siblings in the very same claim clause DO fail closed; only "unwritable"
is handled on the write path and inverts to fail-open. (Same write path also means a *successful*
login under an unwritable state dir raises in `record_success` after the router authenticated,
turning a good login into `INTERNAL_ERROR` and leaving a dangling router session — secondary.)

Why (root cause hypothesis): the breaker's admit/deny decision is a pure READ of the ledger while
"unwritable" is only ever discovered during a WRITE; `check` never verifies that the state store is
usable, so an unwritable store reads as "no failures recorded = allow" instead of "state unknown =
deny". The same `save_ledger`-raises-on-unwritable shape will recur in R4's `router_reboot`
rate-limit timestamp, which also lives under `STATE_DIR`. Do not fix here.

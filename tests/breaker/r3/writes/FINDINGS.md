# Breaker round r3 - vector writes - archer-router-mcp @ 9c06445

Model: claude-opus-4-8
Branch: breaker/r3-writes  (worktree E:/projects-working-dir/.wt/archer-router-mcp/breaker-r3-writes)

Claim attacked (verbatim):
> "In `archer-router-mcp` @ `9c06445` (R4), no write operation leaves the process
> unless `ARCHER_ROUTER_ALLOW_WRITES=true` AND `confirm_write=True`; startup refuses
> when writes are on and `ARCHER_ROUTER_PROTECTED_MACS` is empty; any
> block/unblock/limit/isolate/reservation-remove/WoL targeting a protected MAC is
> refused (`PROTECTED_TARGET`) regardless of MAC spelling ...; `router_set_access_mode(whitelist)`
> is refused unless every protected MAC is already on the white list ...; `router_add_dhcp_reservation`
> refuses a MAC already reserved, an IP used by another reservation, or an IP outside
> the LAN subnet; `router_remove_dhcp_reservation` removes exactly the row whose MAC
> matches ...; `router_reboot` is rate-limited via a persisted timestamp that survives
> process restart and cannot be bypassed by a backward clock; dry-run sends nothing;
> every write batch logs out; `force_takeover` defaults False ...; writes never trigger
> a session takeover; no secret ... appears in any envelope or log; writes marked
> INFERRED (`write_spf`, speed-limit fields, schedule shape, isolate, wol) are gated
> behind `R0_UNCONFIRMED` so they cannot be sent before the live capture confirms them."

**Verdict: DISPROVEN.** The final clause is false for four of the five INFERRED
tools (F1, Critical). The reboot rate limit is a decide-then-record gate that fails
open on an unwritable store and offers no atomic reserve (F2, Major). The
protected-target enumeration is false for unblock / un-isolate / WoL (F3, Minor).
A token-expiry replay double-applies a non-idempotent insert (F6, Major, caveated).
Two low-harm/cosmetic gaps (F5, F7).

Axes that produced nothing (verified, no finding):
- **Double gating** (`ALLOW_WRITES` env + `confirm_write=True`): every tool refuses
  `WRITE_REFUSED` with no network call when either gate is off.
- **`confirm_write` string coercion at the `mcp.call_tool` boundary**: FastMCP's
  pydantic validates the `bool` annotation, so "true"/"1"/"yes" coerce to True - but
  these are affirmative values that match the confirming intent, and the direct
  (non-MCP) path's `check_write_gate` uses `confirm_write is not True` so a string is
  rejected there. No path lets a non-affirmative value through, and the operator gate
  (`ALLOW_WRITES`) is unaffected. No bypass.
- **dry-run sends nothing**: `guarded` routes to `dry_fn` before the gate and never
  opens a session; `fake.write_posts == 0` / `login_posts == 0` in dry-run.
- **every write batch logs out**: `async with components.session` calls `logout()` in
  `__aexit__` even when the batch raises mid-sequence.
- **force_takeover default + "writes never take over"**: the write path calls
  `_authenticate(explicit=False)` -> `login(force_takeover=False)`; `_handle_conflict`
  requires BOTH `settings.force_session_takeover` and the `force_takeover` arg, so a
  `user conflict` during a write surfaces `SESSION_CONFLICT`, never an eviction, even
  with the env var set.
- **secrets in envelopes/logs across a write batch**: `run_tool` redacts by key;
  `router_set_wifi` strips `is_sensitive_key` fields from the echoed body while
  preserving them on the wire; `transport.post` logs only the token-masked URL, never
  the body; `error.details()` on every refusal carries only mac/ip/reason/counts.
  (The `AesKey.__repr__` leak is real but is an R1/auth concern already filed, not a
  write-path leak.)
- **startup refuses writes-on + empty PROTECTED_MACS**: `_require_protected_macs`
  raises `ConfigError` in `Components.from_env`.
- **whitelist mode vs protected spelling / TOCTOU**: `router_set_access_mode(whitelist)`
  re-reads the white list, canonicalises both sides via `normalize_mac`, and refuses
  `protected_not_whitelisted` if any protected MAC is absent (fail-closed if the row
  key is unexpected). Holds for colon/dash/case/no-separator spellings.
- **protected MAC via robust spellings** (spaces, case, dashes, no separators): both
  sides canonicalise, so `reject_protected` fires (`PROTECTED_TARGET`). See the
  passing delimiter `test_robust_spellings_are_PROTECTED_TARGET`.
- **speed-limit(0,0) "unlimited" on a protected MAC**: `reject_protected` runs in
  `prep()` before any rate logic, so it is still refused.
- **block/limit/isolate by name**: no write tool accepts a device name as the target
  selector; all take `mac` through `valid_mac`.
- **backward / future / corrupt reboot timestamp**: a `last` in the past or future
  only makes `next_allowed` earlier/later and never admits an extra reboot inside the
  window (passing delimiter `test_backward_clock_does_not_bypass`). A corrupt file is
  treated as "no previous event" (allows) - the same fail-open family as F2.
- **IP `192.0.2.256` / bad IPv4**: rejected by `valid_ipv4` (`INVALID_INPUT`).
- **name injection (& = % unicode, 64 chars, control, NUL)**: `valid_name` rejects
  control/NUL and >32 chars; `build_request_body` percent-encodes the rest (existing
  suite covers the exact body). No body-break found.
- **remove resolves key+index from a fresh load**: confirmed; `find_by_mac` over the
  freshly loaded `before` rows.

---

## F1  INFERRED writes (speed-limit, schedule, isolate, WoL) are NOT gated behind R0_UNCONFIRMED - Impact 3 (a guessed-field body reaches the live router - the exact event R0_UNCONFIRMED exists to prevent; recoverable) x Likelihood 4 (every live call of these four tools while writes are enabled and the verified doc is absent - the repo's current state; adversary-reading? yes - the call and args are LLM-supplied) = 12 Critical
Test: tests/breaker/r3/writes/test_r0_unconfirmed_inferred_writes.py::{test_speed_limit_live_refused_until_r0, test_isolate_live_refused_until_r0, test_schedule_live_refused_until_r0, test_wol_live_refused_until_r0}
What happens: The claim names five INFERRED writes as "gated behind `R0_UNCONFIRMED`
so they cannot be sent before the live capture confirms them." Only `router_set_wifi`
(`write_spf`) actually calls `wifi_write_confirmed()` and refuses `R0_UNCONFIRMED`
while `docs/protocol/archer-ax53-verified.md` is missing (it is missing in this tree).
`router_set_client_speed_limit`, `router_set_wifi_schedule`, `router_isolate_device`
and `router_wol` carry no R0 gate: with `ALLOW_WRITES=true` and `confirm_write=True`,
each sends its guessed-field body straight to the device (`fake.write_posts` /
`fake.wakeups` > 0). The tests assert the claimed refusal and fail, with the live
write going out instead.
Why (root cause hypothesis): the R0 gate was wired into `writes.py::router_set_wifi`
only; the four INFERRED tools in `writes_access.py` (and `router_wol` in `writes.py`)
were never given an equivalent `R0Unconfirmed` guard, though their own docstrings
admit the field names are "INFERRED ... confirmed at R5."

## F2  Reboot rate limit is decide-then-record and fails open - Impact 3 (an unintended router reboot drops the whole LAN; under an unwritable store the limiter can never bound it, so reboots repeat) x Likelihood 2 (unwritable `STATE_DIR` is an operational misconfig that has happened; the concurrency race needs two reboot calls in flight; adversary-reading? no - coincidence/misconfig, not a goal) = 6 Major
Test: tests/breaker/r3/writes/test_reboot_decide_then_record.py::{test_decide_and_record_are_not_atomic, test_unwritable_state_dir_fails_open_to_unbounded_reboots} (the "two processes" axis reduces to the same lock-free file store and is covered deterministically by the first test; a live multiprocessing repro was omitted as nondeterministic under this sandbox)
What happens: `router_reboot.live` reads `limiter.status(now)` (a pure read), sends
the reboot via `session.request`, and only THEN calls `limiter.record(now)` - the
three steps share no lock. (a) Two callers that both read `status` before either
records are both admitted (`test_decide_and_record_are_not_atomic`: both `status`
calls return allowed with no file yet). (b) If the store is unwritable, `record`
raises AFTER the reboot has already been sent; nothing is persisted, so the next call
is allowed again - `test_unwritable_state_dir_fails_open_to_unbounded_reboots` sends
two reboots 60 s apart (well inside the 900 s window) and the tool returns
`INTERNAL_ERROR` while the device reboots regardless. This is exactly the RA-F1 /
"save_ledger re-raises" shape the root-cause triage (section 4) predicted would recur.
Why (root cause hypothesis): the limiter is a decide-then-record pair on an
unserialised, writability-unproven file (no reserve-before-act, no fail-closed on an
unwritable store), identical to the login breaker's structural cause.

## F6  A token-expiry replay double-applies a non-idempotent insert - Impact 3 (a duplicate DHCP reservation / black-list row; the real device likely rejects the replayed duplicate, so the tool reports failure though the first write landed) x Likelihood 2 (token expiry mid-batch is a known coincidence, but this sub-case - expiry on the reply AFTER the write commits - is rarer and its only witness is this crafted fake; scored down per the rubric; adversary-reading? no) = 6 Major (borderline Minor under a strict "own-test-only => 1" reading)
Test: tests/breaker/r3/writes/test_token_expiry_double_write.py::test_insert_is_not_double_applied_on_timeout_replay
What happens: `RouterSession.request` replays a request once after a `timeout`
re-login, unconditionally - it cannot tell "the write never landed" from "the write
landed but the reply was lost/undecryptable." A fake whose `insert` commits the row
and then reports `timeout` once makes the client re-login and re-send the same insert;
`insert` is not idempotent (a new keyed row each time), so the reservation table ends
with two rows for one MAC while the envelope reports success. The spec's own
state-machine guarantee ("failure mid-sequence leaves no partial reservation";
"replayed ... once") is violated for a write that lands before its reply is lost.
Why (root cause hypothesis): the single-replay re-login path treats every request as
idempotent; a non-idempotent insert/remove/write has no de-dup token
(client-supplied idempotency key / read-back-before-replay).

## F3  The PROTECTED_TARGET guard does not cover unblock / un-isolate / WoL - Impact 1 (waking or restoring access to a protected device is benign and reversible) x Likelihood 4 (LLM-supplied MAC; every such call; adversary-reading? yes) = 4 Minor
Test: tests/breaker/r3/writes/test_protected_coverage_gaps.py::{test_wol_to_protected_mac_is_refused, test_unblock_of_protected_mac_is_refused}
What happens: the claim says "any block/unblock/limit/isolate/reservation-remove/WoL
targeting a protected MAC is refused (`PROTECTED_TARGET`)." The code refuses only
block / limit / isolate(True) / reservation-remove. `router_wol` and
`router_unblock_device` (and `router_isolate_device(isolate=False)`) never call
`reject_protected`, so a magic packet / unblock write targeting a protected MAC leaves
the process. The tests assert the claimed refusal and fail. Harm is low (and the
omission is a defensible design choice for restorative ops), but the claim's
enumeration is literally false.
Why (root cause hypothesis): `reject_protected` is applied per-tool by hand; the
restorative/benign tools were intentionally exempted, which contradicts the claim's
blanket wording rather than a safety bug.

## F5  A trailing-NUL protected MAC is refused with INVALID_INPUT, not PROTECTED_TARGET - Impact 1 (the write is still refused; nothing leaves the process - only the error code differs) x Likelihood 2 (a NUL-suffixed MAC is a crafted input, no harm either way) = 2 Won't-fix
Test: tests/breaker/r3/writes/test_protected_mac_spelling.py::test_trailing_nul_protected_mac_gives_protected_target
What happens: `str.strip()` does not remove the NUL byte and the NUL is outside the
MAC separator class, so "00:00:5E:00:53:AA\x00" fails `valid_mac` (-> `INVALID_INPUT`)
before reaching `reject_protected`. The claim's "`PROTECTED_TARGET` regardless of MAC
spelling, including a trailing NUL" is false in letter only - the write is safely
blocked, just with a different code.
Why (root cause hypothesis): validation ordering (`valid_mac` before
`reject_protected`) means any spelling `valid_mac` rejects can never produce
`PROTECTED_TARGET`; no safety consequence because both outcomes refuse.

## F7  The LAN-subnet check is skipped when the mask is absent - Impact 2 (an out-of-subnet reservation is written) x Likelihood 1 (the mask comes from the router's `lan_ipv4` read, not the caller; needs an unusual response shape; adversary-reading? no) = 2 Won't-fix
Test: tests/breaker/r3/writes/test_subnet_check_gap.py::test_out_of_subnet_ip_refused_even_without_mask
What happens: `_check_in_lan_subnet` returns early ("subnet unknown -> allow")
whenever the LAN read lacks a string `mask`. A `lan_ipv4` response with `ipaddr` but
no `mask` lets an out-of-subnet reservation through - the claim ("refuses ... an IP
outside the LAN subnet") is unconditional, the code is "when known."
Why (root cause hypothesis): the subnet check fails open on an unknown subnet instead
of refusing (or refusing only the out-of-subnet case it cannot rule in).

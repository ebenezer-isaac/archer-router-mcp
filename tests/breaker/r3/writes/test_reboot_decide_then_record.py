"""BREAKER r3 / writes — F2: the reboot rate limit is decide-then-record and fails open.

Claim under attack: "``router_reboot`` is rate-limited via a persisted timestamp
that survives process restart and cannot be bypassed by a backward clock".

The root-cause triage (ROOT-CAUSE-breaker.md §4) predicts the reboot limiter grows
the same ``RA-F1`` shape: *decide* (``limiter.status(now)``) and *record*
(``limiter.record(now)``) are two unserialised steps on a shared file, with the
destructive ``session.request`` **between** them, and record is only attempted
*after* the reboot has already been sent. Two ways to bypass:

* **Concurrency** — two ``router_reboot`` calls both read ``status`` (both see
  "allowed", no file yet), both pass the check, then serialise only through the
  session lock and both send the reboot. Nothing serialises decide+record.

* **Unwritable STATE_DIR** — the reboot is sent, then ``record`` raises (the dir is
  read-only / the save fails). The reboot already left the process, nothing is
  persisted, so the *next* call is allowed again → unbounded reboots. The limiter's
  own docstring assumes "worst case ... one extra reboot"; the real worst case is
  every call.

Both tests assert the claimed invariant (one reboot reaches the device inside the
window) and FAIL against the code.

Backward-clock bypass was also attacked and produced nothing: a ``last`` in the
past only makes ``next_allowed`` earlier, never admits an extra reboot inside the
window — that half of the claim holds (see ``test_backward_clock_does_not_bypass``,
which passes and is therefore not itself a finding, included only to delimit the
attack surface).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from archer_router_mcp import server
from archer_router_mcp.core.ratelimit import RateLimiter
from tests.fakes import FakeRouter, build_components

# RW-F2 — orchestrator decision: the reboot limiter's decide-then-record / fail-open
# shape is the same structural cause as the login breaker (RA-F1) and is DEFERRED to
# X1b's `ReservationStore` (reserve-before-act, writability-proven, fail-closed). These
# two tests are therefore expected to fail here until that refactor lands; they are
# marked strict xfail so the day X1b fixes the cause they flip to a visible failure and
# this marker is removed. See tests/breaker/r3/writes/FINDINGS.md (F2).
_DEFERRED_RW_F2 = pytest.mark.xfail(
    strict=True, reason="deferred to X1b ReservationStore; FINDINGS RW-F2"
)

PROTECTED = "00:00:5E:00:53:AA"

# The "two processes" axis reduces to the same unlocked file store: there is no
# cross-process lock anywhere in RateLimiter, so N processes behave exactly like the
# N in-process callers modelled deterministically in
# ``test_decide_and_record_are_not_atomic`` below. A live multiprocessing reproduction
# was prototyped but omitted: under this sandbox spawn/Manager startup is
# nondeterministic (skip-vs-run), which would make the test flaky, violating the
# "deterministic, isolated" rule. The deterministic model is the faithful witness.


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class UnwritableLimiter(RateLimiter):
    """Models an unwritable STATE_DIR: the save is only discovered to fail at
    record time (``save_ledger``/``mkstemp`` raising OSError), exactly RA-F1's shape."""

    def record(self, now: float) -> None:
        raise OSError("state directory is read-only")


def _components(tmp_path: Path, clock: FakeClock):
    fake = FakeRouter(envelope="https-plain", stateful=True)
    extra = {
        "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED,
        "ARCHER_ROUTER_ALLOW_WRITES": "true",
    }
    comps = build_components(
        fake, envelope="https-plain", state_dir=tmp_path, extra_env=extra, clock=clock
    )
    return fake, comps


@_DEFERRED_RW_F2
def test_decide_and_record_are_not_atomic(tmp_path) -> None:
    """Deterministic model of the async gap: two callers each decide before either
    records (caller A is awaiting its reboot POST when caller B reads status). The
    limiter offers no reserve, so both are admitted.
    """
    limiter = RateLimiter(tmp_path, "rl.json", 900.0)
    now = 1000.0
    a_allowed = limiter.status(now)["allowed"]  # caller A decides
    b_allowed = limiter.status(now)["allowed"]  # caller B decides (A has not recorded yet)
    limiter.record(now)  # A records after its reboot POST returns
    limiter.record(now)  # B records after its reboot POST returns
    # Claim: the window admits at most one reboot.
    assert [a_allowed, b_allowed].count(True) == 1, (
        "both concurrent callers were admitted: status() is a pure read with no "
        "check-and-reserve, so decide-then-record cannot bound reboots to one per window"
    )


@_DEFERRED_RW_F2
async def test_unwritable_state_dir_fails_open_to_unbounded_reboots(tmp_path) -> None:
    clock = FakeClock(1000.0)
    fake, c = _components(tmp_path, clock)
    # Swap in a limiter whose record() fails, as an unwritable STATE_DIR would.
    c.reboot_rate_limiter = UnwritableLimiter(tmp_path, "reboot-ratelimit.json", 900.0)
    try:
        await server.router_reboot(c, confirm_write=True)
        # The first reboot was sent even though persistence failed.
        assert fake.reboots == 1
        # A second call one minute later — well inside the 900s window.
        clock.t = 1060.0
        second = await server.router_reboot(c, confirm_write=True)
        # Claim: a call inside the window sends nothing.
        assert fake.reboots == 1, (
            f"rate limit failed open: {fake.reboots} reboots in the window because the "
            "limiter never persisted (unwritable store), and the reboot is sent before record"
        )
        assert second["success"] is False
        assert second["error"]["code"] == "RATE_LIMITED"
    finally:
        await c.aclose()


def test_backward_clock_does_not_bypass(tmp_path) -> None:
    """Delimiter (passes): the backward-clock half of the claim holds."""
    limiter = RateLimiter(tmp_path, "rl.json", 900.0)
    limiter.record(10_000.0)
    # Clock jumps far backward; still refused, retry window only grows.
    status = limiter.status(5_000.0)
    assert status["allowed"] is False
    assert status["retry_after_s"] >= 900.0

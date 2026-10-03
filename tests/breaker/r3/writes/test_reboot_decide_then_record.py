"""BREAKER r3 / writes — F2 (RW-F2) RESOLVED by X1b's ``ReservationStore``.

RW-F2 was: the reboot rate limit was a *decide-then-record* pair on an unlocked,
writability-unproven file — two callers could both read "allowed" before either
recorded, and an unwritable ``STATE_DIR`` was discovered only *after* the reboot had
been sent, so the limiter failed open to unbounded reboots. It was deferred to X1b's
``ReservationStore`` (reserve-before-act, writability-proven, fail-closed).

That refactor has landed (``archer_router_mcp.ratelimit.RebootLimiter`` over
``core.state.ReservationStore``), so these tests now assert the invariant HOLDS and
pass (the ``xfail(strict=True)`` markers are removed). Each is the positive form of
the finding it closes:

* reserve-before-act is atomic — a second reserve inside the window (or while one is
  in flight) is refused, so decide-then-record can no longer admit two reboots;
* an unwritable store is discovered at *reserve* time and refuses before any reboot
  leaves the process (fail closed), not fail-open after the fact;
* the backward-clock delimiter still holds (it never did bypass).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from archer_router_mcp import server
from archer_router_mcp.core.breaker import canonical_device_key
from archer_router_mcp.core.state import Outcome
from archer_router_mcp.errors import RateLimited
from archer_router_mcp.ratelimit import RebootLimiter
from tests.fakes import FakeRouter, build_components

PROTECTED = "00:00:5E:00:53:AA"


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


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


def test_reserve_before_act_is_atomic(tmp_path) -> None:
    """The reserve IS the admission (one locked write), so a second caller inside the
    window is refused — decide-then-record can no longer admit two reboots per window.
    """
    clock = FakeClock(1000.0)
    limiter = RebootLimiter(tmp_path, "dev", min_interval_s=900.0, clock=clock)
    first = limiter.reserve()  # caller A reserves (the admission commits under the lock)
    # Caller B, same device/window, is refused before it can act — no lost-update gap.
    with pytest.raises(RateLimited):
        RebootLimiter(tmp_path, "dev", min_interval_s=900.0, clock=clock).reserve()
    first.release(Outcome.SUCCESS)
    # Still inside the window after A released: one reboot per window holds.
    clock.t = 1060.0
    with pytest.raises(RateLimited):
        limiter.reserve()


async def test_unwritable_state_dir_refuses_before_any_reboot(tmp_path) -> None:
    # A regular file where the state directory must be: the store can never be created,
    # so the reservation (and thus the reboot) is refused before anything is sent.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    clock = FakeClock(1000.0)
    fake, c = _components(tmp_path, clock)
    c.reboot_rate_limiter = RebootLimiter(
        blocker / "state", canonical_device_key("192.0.2.1"), min_interval_s=900.0, clock=clock
    )
    try:
        first = await server.router_reboot(c, confirm_write=True)
        # Fail closed: nothing was sent, mapped to RATE_LIMITED, never INTERNAL_ERROR.
        assert first["success"] is False
        assert first["error"]["code"] == "RATE_LIMITED"
        assert fake.reboots == 0
        # A second call one minute later is likewise refused (still unwritable).
        clock.t = 1060.0
        second = await server.router_reboot(c, confirm_write=True)
        assert second["success"] is False
        assert second["error"]["code"] == "RATE_LIMITED"
        assert fake.reboots == 0
    finally:
        await c.aclose()


def test_backward_clock_does_not_bypass(tmp_path) -> None:
    """Delimiter (still passes): a clock that jumps backward only grows the window."""
    limiter = RebootLimiter(tmp_path, "dev", min_interval_s=900.0, clock=FakeClock(10_000.0))
    limiter.reserve().release(Outcome.SUCCESS)  # acceptance recorded at t=10000
    status = limiter.status(5_000.0)  # clock jumps far backward
    assert status["allowed"] is False
    assert status["retry_after_s"] >= 900.0

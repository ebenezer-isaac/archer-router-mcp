"""Breaker round 2 — vector: breaker durability / fail-closed semantics.

Claim under attack (excerpt):

    "...the file-backed breaker ... a corrupt, truncated or unwritable state file
     makes it fail CLOSED (no login possible, clear error)..."

The corrupt and truncated cases *are* handled on the READ path (``load_ledger`` ->
``corrupt=True`` -> ``check`` raises ``LockoutGuard``); the existing suite proves
that. This file attacks the third member of that list — **unwritable** — which is
handled on the WRITE path, and which fails OPEN instead of closed:

* ``LoginBreaker.check`` only READS the ledger. When the state directory cannot be
  written, no file exists, so ``load_ledger`` returns an empty *allowing* ledger
  and ``check`` lets the login through -> a login POST reaches the device (so it is
  NOT "no login possible").
* The failure is recorded only in ``record_failure`` -> ``save_ledger``, which
  raises a raw ``OSError``. The failure is therefore NEVER persisted, so the
  breaker's failure budget is never consumed and every subsequent attempt is
  allowed through again. The account's whole lockout-safety guarantee is defeated
  precisely when the operator most needs it (read-only FS, a mis-permissioned
  systemd ``StateDirectory``, ``state_dir`` pointed at a non-directory, ...).

These tests encode the CLAIMED behaviour (fail closed) and therefore fail against
the current code, which fails open. Mocks/fakes only; no network.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from archer_router_mcp.core.errors import LockoutGuard
from archer_router_mcp.errors import DeviceError
from archer_router_mcp.server import router_login
from tests.fakes import FakeRouter, build_components

_LOGIN_FAILED = {"failureCount": 1, "attemptsAllowed": 4}


def _unwritable_state_dir(tmp_path: Path) -> Path:
    """A state dir that can never be created: its parent is a regular file.

    ``save_ledger`` does ``path.parent.mkdir(parents=True, exist_ok=True)``; with a
    file where a directory is expected that raises ``OSError`` on every platform
    (``FileExistsError``/``NotADirectoryError``). ``check`` -> ``load_ledger`` sees
    no file under it and returns an *allowing* ledger.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    return blocker / "sub"  # parent is a file -> uncreatable


async def test_unwritable_state_dir_should_fail_closed_no_login_no_internal_error(
    tmp_path: Path,
) -> None:
    """Claim: an unwritable breaker file => no login POST, and a *clear* error.

    Reality: a login POST is sent (login IS possible) and the operator sees a
    generic ``INTERNAL_ERROR`` (a raw ``OSError`` surfaced by ``run_tool``), not a
    clear login-refused message. Both assertions below fail against current code.
    """
    fake = FakeRouter(
        envelope="http-encrypted",
        login_error="login failed",
        login_failure_data=_LOGIN_FAILED,
    )
    comps = build_components(
        fake,
        envelope="http-encrypted",
        state_dir=str(_unwritable_state_dir(tmp_path)),
        rng=random.Random(1),
    )
    try:
        result = await router_login(comps)
    finally:
        await comps.aclose()

    # The claim is "no login possible" when the breaker file is unwritable.
    assert fake.login_posts == 0, (
        "claim: an unwritable breaker fails CLOSED (no login POST); "
        f"the code sent {fake.login_posts} login POST(s)"
    )
    # ... with a *clear* error, not a leaked-internals INTERNAL_ERROR.
    assert result["success"] is False
    assert result["error"]["code"] == LockoutGuard.kind, (
        "claim: a clear login-refused error; got "
        f"{result['error']['code']!r} ({result['error']['message']!r})"
    )


async def test_unwritable_state_dir_breaker_never_trips_fails_open(tmp_path: Path) -> None:
    """The breaker budget is 1, yet an unwritable state dir lets attempt after
    attempt reach the device because the failure is never persisted.

    Two consecutive failed logins are issued. With a working breaker the second is
    refused locally (budget spent) and no second POST is sent. Here both reach the
    device: the breaker has silently failed OPEN, marching the admin account toward
    its multi-hour lockout — the exact outcome the breaker exists to prevent.
    """
    fake = FakeRouter(
        envelope="http-encrypted",
        login_error="login failed",
        login_failure_data=_LOGIN_FAILED,
    )
    comps = build_components(
        fake,
        envelope="http-encrypted",
        state_dir=str(_unwritable_state_dir(tmp_path)),
        rng=random.Random(2),
    )
    assert comps.settings.max_login_failures == 1  # one failure should open the breaker
    try:
        for _ in range(2):
            with pytest.raises((DeviceError, OSError)):
                await comps.session.login(explicit=True, force_takeover=True)
        # The failure was never persisted, so the breaker is still "closed".
        assert comps.breaker.snapshot().failed == 0
    finally:
        await comps.aclose()

    assert fake.login_posts <= 1, (
        "breaker must stop the second login once the budget (1) is spent; "
        f"an unwritable state dir let {fake.login_posts} POSTs through (fail-open)"
    )


async def test_control_writable_state_dir_does_trip_after_one_failure(tmp_path: Path) -> None:
    """Control (not a finding): with a WRITABLE state dir the breaker behaves as

    claimed — the first failure is persisted and the second login is refused
    locally with a clear ``LOGIN_REFUSED`` and no second POST. This isolates the
    defect to the unwritable path.
    """
    fake = FakeRouter(
        envelope="http-encrypted",
        login_error="login failed",
        login_failure_data=_LOGIN_FAILED,
    )
    comps = build_components(
        fake,
        envelope="http-encrypted",
        state_dir=str(tmp_path / "state"),
        rng=random.Random(3),
    )
    try:
        from archer_router_mcp.errors import AuthFailed

        with pytest.raises(AuthFailed):
            await comps.session.login(explicit=True, force_takeover=True)
        assert comps.breaker.snapshot().failed == 1
        with pytest.raises(LockoutGuard):
            await comps.session.login(explicit=True, force_takeover=True)
    finally:
        await comps.aclose()

    assert fake.login_posts == 1  # the second login never left the process

"""Canonical breaker conformance suite (device-agnostic).

Copied verbatim into every repo's ``tests/conformance/`` and hashed by
``core/VERSION`` (the identity test), so the contract cannot drift. Each case cites
the breaker finding it makes impossible by construction. It builds a real
``LoginBreaker`` against a real ``tmp_path`` state directory and, for concurrency,
real ``multiprocessing`` workers - no fakes, matching how the store is used in
production.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from vigi_nvr_mcp.core.breaker import LoginBreaker, canonical_device_key
from vigi_nvr_mcp.core.errors import BreakerOpen, Cooldown, LoginDisabled
from vigi_nvr_mcp.core.state import Outcome

KEY = "device-under-test"


def _breaker(state_dir: Path, *, key: str = KEY, max_failures: int = 1, **kwargs) -> LoginBreaker:
    return LoginBreaker(state_dir, key, max_failures=max_failures, **kwargs)


# ---- 1. Persistence across instances (AL-F1) --------------------------------


def test_budget_survives_a_restart(tmp_path: Path) -> None:
    a = _breaker(tmp_path)
    a.reserve_attempt().release(Outcome.FAILURE)
    # A brand-new instance (the next process) on the same dir/key is still refused.
    fresh = _breaker(tmp_path)
    with pytest.raises(BreakerOpen):
        fresh.reserve_attempt()


# ---- 2. Corrupt / truncated / non-dict (R2-F2) ------------------------------


@pytest.mark.parametrize("blob", ["{ not json", "[]", '"a string"', "42", "null"])
def test_corrupt_or_nondict_fails_closed(tmp_path: Path, blob: str) -> None:
    b = _breaker(tmp_path)
    b.path.write_text(blob, encoding="utf-8")
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()
    # --show must never crash on a corrupt file.
    assert b.status()["state"] == "open"


# ---- 3. Wrong types never coerce to a permissive value (R2-F2) ---------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"reserved": False},  # bool must NOT coerce to 0 (the dangerous fail-open)
        {"failures": False},
        {"failures": "oops"},
        {"reserved": [1]},
        {"tripped": "yes"},
        {"version": 2},  # unknown version
        {"cooldown_until": "soon"},
    ],
)
def test_wrong_types_fail_closed(tmp_path: Path, overrides: dict) -> None:
    b = _breaker(tmp_path)
    ledger = {
        "version": 1,
        "key": KEY,
        "reserved": 0,
        "failures": 0,
        "successes": 0,
        "tripped": False,
        "cooldown_until": None,
        "last_failure": None,
        "last_update": 1.0,
        **overrides,
    }
    b.path.write_text(json.dumps(ledger), encoding="utf-8")
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()


# ---- 4. Unwritable store: refuse before any admission (RA-F1) ----------------


def test_unwritable_store_refuses_before_admitting(tmp_path: Path) -> None:
    # A regular file where a directory must be: the store can never be created, so
    # admission is impossible on every platform.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    b = _breaker(blocker / "state")
    with pytest.raises(BreakerOpen):  # mapped, never INTERNAL_ERROR, never fail-open
        b.reserve_attempt()
    assert not (blocker / "state").exists()


# ---- 5. Real multi-process concurrency (R2-F1) ------------------------------


def _reserve_worker(args: tuple[str, str, int, bool]) -> str:
    state_dir, key, max_failures, do_fail = args
    worker = LoginBreaker(Path(state_dir), key, max_failures=max_failures)
    try:
        res = worker.reserve_attempt()
    except BreakerOpen:
        return "refused"
    if do_fail:
        res.release(Outcome.FAILURE)
    return "admitted"


def test_only_one_process_is_admitted_under_budget_one(tmp_path: Path) -> None:
    state = str(tmp_path)
    jobs = [(state, KEY, 1, False)] * 8
    with ProcessPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_reserve_worker, jobs))
    assert results.count("admitted") == 1, results
    assert results.count("refused") == 7, results


def test_no_lost_update_across_processes(tmp_path: Path) -> None:
    # Budget == worker count: every worker reserves and fails; the flock serialises
    # the read-modify-write, so the final failure count equals the number admitted.
    state = str(tmp_path)
    n = 8
    jobs = [(state, "lost-update", n, True)] * n
    with ProcessPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_reserve_worker, jobs))
    assert results.count("admitted") == n, results
    snap = LoginBreaker(tmp_path, "lost-update", max_failures=n).status()
    assert snap["failures"] == n and snap["reserved"] == 0, snap


# ---- 6. Key normalisation (R2-F3) -------------------------------------------


@pytest.mark.parametrize(
    ("spelling_a", "spelling_b"),
    [("fe80::1", "fe80:0:0:0:0:0:0:1"), ("NVR.local", "nvr.local")],
)
def test_equivalent_hosts_share_one_budget(tmp_path: Path, spelling_a, spelling_b) -> None:
    assert canonical_device_key(spelling_a) == canonical_device_key(spelling_b)
    first = _breaker(tmp_path, key=canonical_device_key(spelling_a))
    second = _breaker(tmp_path, key=canonical_device_key(spelling_b))
    assert first.path == second.path
    first.reserve_attempt().release(Outcome.FAILURE)
    with pytest.raises(BreakerOpen):
        second.reserve_attempt()
    # --clear under either spelling clears the other.
    second.clear()
    first.reserve_attempt().release(Outcome.SUCCESS)


# ---- 7. Budget semantics (f) ------------------------------------------------


def test_raising_budget_does_not_reopen_a_trip(tmp_path: Path) -> None:
    _breaker(tmp_path, max_failures=1).reserve_attempt().release(Outcome.FAILURE)
    # A bigger budget tomorrow must not silently un-trip yesterday's lockout.
    with pytest.raises(BreakerOpen):
        _breaker(tmp_path, max_failures=5).reserve_attempt()


def test_success_does_not_clear_failures(tmp_path: Path) -> None:
    b = _breaker(tmp_path, max_failures=3)
    b.reserve_attempt().release(Outcome.FAILURE)
    b.reserve_attempt().release(Outcome.SUCCESS)
    snap = b.status()
    assert snap["failures"] == 1 and snap["successes"] == 1


# ---- 8. Crash fail-closed (a) -----------------------------------------------


def test_unresolved_reservation_counts_against_budget(tmp_path: Path) -> None:
    b = _breaker(tmp_path, max_failures=1)
    b.reserve_attempt()  # handle dropped, never released (crash between reserve/release)
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()


def test_context_manager_unresolved_exit_is_a_failure(tmp_path: Path) -> None:
    b = _breaker(tmp_path, max_failures=2)
    with b.reserve_attempt():
        pass  # no explicit release -> recorded as a failure
    assert b.status()["failures"] == 1


# ---- 9. Cooldown (g) --------------------------------------------------------


def test_cooldown_refuses_until_it_expires_and_is_monotonic_safe(tmp_path: Path) -> None:
    now = [1000.0]
    b = _breaker(tmp_path, max_failures=5, clock=lambda: now[0])
    b.reserve_attempt().release(Outcome.FAILURE, cooldown_s=100)
    with pytest.raises(Cooldown):
        b.reserve_attempt()
    # A clock that jumps backward never yields a negative remaining.
    now[0] = 0.0
    assert b.status()["cooldown_remaining_s"] >= 0
    with pytest.raises(Cooldown):
        b.reserve_attempt()
    # Past the cooldown, a reservation is admitted again.
    now[0] = 2000.0
    b.reserve_attempt().release(Outcome.SUCCESS)
    assert b.status()["cooldown_remaining_s"] == 0


def test_success_clears_cooldown(tmp_path: Path) -> None:
    now = [1000.0]
    b = _breaker(tmp_path, max_failures=5, clock=lambda: now[0])
    b.reserve_attempt().release(Outcome.BUSY, cooldown_s=100)
    assert b.status()["state"] == "cooldown"
    now[0] = 2000.0
    b.reserve_attempt().release(Outcome.SUCCESS)
    assert b.cooldown_until is None


# ---- 10. No secrets in the ledger or status (claim) -------------------------


def test_no_secret_reaches_the_ledger_or_status(tmp_path: Path) -> None:
    b = _breaker(tmp_path, max_failures=5)
    b.reserve_attempt().release(
        Outcome.FAILURE, failure={"device_error_code": -40401, "attempts_left": 2}
    )
    raw = b.path.read_text(encoding="utf-8")
    snap = b.status()
    snap.pop("path", None)  # the filesystem path is not a secret-bearing value
    snapshot = json.dumps(snap)
    for marker in ("password", "secret", "token", "nonce", "ciphertext", "stok"):
        assert marker not in raw.lower()
        assert marker not in snapshot.lower()


# ---- login_disabled is owned by the breaker ---------------------------------


def test_login_disabled_refuses_without_touching_the_store(tmp_path: Path) -> None:
    b = _breaker(tmp_path, login_disabled=True)
    with pytest.raises(LoginDisabled):
        b.reserve_attempt()
    assert not b.path.exists()  # no store I/O at all


# ---- 11. Mode bits (POSIX only) ---------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits only")
def test_mode_bits(tmp_path: Path) -> None:
    state = tmp_path / "state"
    b = _breaker(state, max_failures=5)
    b.reserve_attempt().release(Outcome.FAILURE)
    assert (os.stat(state).st_mode & 0o777) == 0o700
    assert (os.stat(b.path).st_mode & 0o777) == 0o600

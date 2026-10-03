"""Canonical breaker conformance suite (device- AND package-agnostic).

Copied verbatim into every repo's ``tests/conformance/`` and hashed by
``core/VERSION`` (the identity test), so the contract cannot drift. The core package
is NOT imported by name here: each repo's ``tests/conftest.py`` provides a one-line
``core_pkg`` fixture returning that repo's core package (for this repo,
``vigi_nvr_mcp.core``); every case resolves ``breaker``/``errors``/``state`` from it,
and the spawned multiprocess workers import the right package by the module path
passed through their arguments (never a global). Each case cites the breaker finding
it makes impossible by construction. It builds a real ``LoginBreaker`` against a real
``tmp_path`` state directory and, for concurrency, real ``multiprocessing`` workers -
no fakes, matching how the store is used in production.
"""

from __future__ import annotations

import importlib
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

KEY = "device-under-test"


# ---- package-agnostic access to the core under test -------------------------


@pytest.fixture
def bk(core_pkg):
    return importlib.import_module(f"{core_pkg.__name__}.breaker")


@pytest.fixture
def errs(core_pkg):
    return importlib.import_module(f"{core_pkg.__name__}.errors")


@pytest.fixture
def st(core_pkg):
    return importlib.import_module(f"{core_pkg.__name__}.state")


@pytest.fixture
def sl(core_pkg):
    return importlib.import_module(f"{core_pkg.__name__}.slot")


@pytest.fixture
def pkg_path(core_pkg) -> str:
    """The core package's import path, handed to spawned workers so they import the
    same package rather than relying on any global."""
    return core_pkg.__name__


def _make(bk, state_dir: Path, *, key: str = KEY, max_failures: int = 1, **kwargs):
    return bk.LoginBreaker(state_dir, key, max_failures=max_failures, **kwargs)


def _ledger(**overrides) -> dict:
    base = {
        "version": 1,
        "key": KEY,
        "epoch": 0,
        "reservations": {},
        "failures": 0,
        "successes": 0,
        "tripped": False,
        "cooldown_until": None,
        "last_failure": None,
        "last_update": 1.0,
    }
    base.update(overrides)
    return base


# ---- 1. Persistence across instances (AL-F1) --------------------------------


def test_budget_survives_a_restart(tmp_path: Path, bk, errs, st) -> None:
    a = _make(bk, tmp_path)
    a.reserve_attempt().release(st.Outcome.FAILURE)
    # A brand-new instance (the next process) on the same dir/key is still refused.
    fresh = _make(bk, tmp_path)
    with pytest.raises(errs.BreakerOpen):
        fresh.reserve_attempt()


# ---- 2. Corrupt / truncated / non-dict (R2-F2) ------------------------------


@pytest.mark.parametrize("blob", ["{ not json", "[]", '"a string"', "42", "null"])
def test_corrupt_or_nondict_fails_closed(tmp_path: Path, bk, errs, blob: str) -> None:
    b = _make(bk, tmp_path)
    b.path.write_text(blob, encoding="utf-8")
    with pytest.raises(errs.BreakerOpen):
        b.reserve_attempt()
    # --show must never crash on a corrupt file.
    assert b.status()["state"] == "open"


# ---- 3. Wrong types never coerce to a permissive value (R2-F2) ---------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"reservations": False},  # bool must NOT coerce (the dangerous fail-open)
        {"failures": False},
        {"failures": "oops"},
        {"reservations": [1]},
        {"reservations": {"id": "soon"}},  # a reservation timestamp must be a float
        {"epoch": False},
        {"tripped": "yes"},
        {"version": 2},  # unknown version
        {"cooldown_until": "soon"},
    ],
)
def test_wrong_types_fail_closed(tmp_path: Path, bk, errs, overrides: dict) -> None:
    b = _make(bk, tmp_path)
    b.path.write_text(json.dumps(_ledger(**overrides)), encoding="utf-8")
    with pytest.raises(errs.BreakerOpen):
        b.reserve_attempt()


# ---- 4. Unwritable store: refuse before any admission (RA-F1) ----------------


def test_unwritable_store_refuses_before_admitting(tmp_path: Path, bk, errs) -> None:
    # A regular file where a directory must be: the store can never be created, so
    # admission is impossible on every platform.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    b = _make(bk, blocker / "state")
    with pytest.raises(errs.BreakerOpen):  # mapped, never INTERNAL_ERROR, never fail-open
        b.reserve_attempt()
    assert not (blocker / "state").exists()


# ---- 5. Real multi-process concurrency (R2-F1) ------------------------------


def _reserve_worker(args: tuple[str, str, str, int, bool]) -> str:
    pkg, state_dir, key, max_failures, do_fail = args
    breaker = importlib.import_module(f"{pkg}.breaker")
    errors = importlib.import_module(f"{pkg}.errors")
    state = importlib.import_module(f"{pkg}.state")
    worker = breaker.LoginBreaker(Path(state_dir), key, max_failures=max_failures)
    try:
        res = worker.reserve_attempt()
    except errors.BreakerOpen:
        return "refused"
    if do_fail:
        res.release(state.Outcome.FAILURE)
    return "admitted"


def test_only_one_process_is_admitted_under_budget_one(tmp_path: Path, pkg_path: str) -> None:
    jobs = [(pkg_path, str(tmp_path), KEY, 1, False)] * 8
    with ProcessPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_reserve_worker, jobs))
    assert results.count("admitted") == 1, results
    assert results.count("refused") == 7, results


def test_no_lost_update_across_processes(tmp_path: Path, bk, pkg_path: str) -> None:
    # Budget == worker count: every worker reserves and fails; the flock serialises
    # the read-modify-write, so the final failure count equals the number admitted.
    n = 8
    jobs = [(pkg_path, str(tmp_path), "lost-update", n, True)] * n
    with ProcessPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_reserve_worker, jobs))
    assert results.count("admitted") == n, results
    snap = _make(bk, tmp_path, key="lost-update", max_failures=n).status()
    assert snap["failures"] == n and snap["reserved"] == 0, snap


# ---- 6. Key normalisation (R2-F3) -------------------------------------------


@pytest.mark.parametrize(
    ("spelling_a", "spelling_b"),
    [("fe80::1", "fe80:0:0:0:0:0:0:1"), ("NVR.local", "nvr.local")],
)
def test_equivalent_hosts_share_one_budget(
    tmp_path: Path, bk, errs, st, spelling_a, spelling_b
) -> None:
    canon = bk.canonical_device_key
    assert canon(spelling_a) == canon(spelling_b)
    first = _make(bk, tmp_path, key=canon(spelling_a))
    second = _make(bk, tmp_path, key=canon(spelling_b))
    assert first.path == second.path
    first.reserve_attempt().release(st.Outcome.FAILURE)
    with pytest.raises(errs.BreakerOpen):
        second.reserve_attempt()
    # --clear under either spelling clears the other.
    second.clear()
    first.reserve_attempt().release(st.Outcome.SUCCESS)


# ---- 7. Budget semantics (f) ------------------------------------------------


def test_raising_budget_does_not_reopen_a_trip(tmp_path: Path, bk, errs, st) -> None:
    _make(bk, tmp_path, max_failures=1).reserve_attempt().release(st.Outcome.FAILURE)
    # A bigger budget tomorrow must not silently un-trip yesterday's lockout.
    with pytest.raises(errs.BreakerOpen):
        _make(bk, tmp_path, max_failures=5).reserve_attempt()


def test_success_does_not_clear_failures(tmp_path: Path, bk, st) -> None:
    b = _make(bk, tmp_path, max_failures=3)
    b.reserve_attempt().release(st.Outcome.FAILURE)
    b.reserve_attempt().release(st.Outcome.SUCCESS)
    snap = b.status()
    assert snap["failures"] == 1 and snap["successes"] == 1


# ---- 8. Crash fail-closed (a) -----------------------------------------------


def test_unresolved_reservation_counts_against_budget(tmp_path: Path, bk, errs) -> None:
    b = _make(bk, tmp_path, max_failures=1)
    b.reserve_attempt()  # handle dropped, never released (crash between reserve/release)
    with pytest.raises(errs.BreakerOpen):
        b.reserve_attempt()


def test_context_manager_unresolved_exit_is_a_failure(tmp_path: Path, bk) -> None:
    b = _make(bk, tmp_path, max_failures=2)
    with b.reserve_attempt():
        pass  # no explicit release -> recorded as a failure
    assert b.status()["failures"] == 1


# ---- 9. Cooldown (g) --------------------------------------------------------


def test_cooldown_refuses_until_it_expires_and_is_monotonic_safe(
    tmp_path: Path, bk, errs, st
) -> None:
    now = [1000.0]
    b = _make(bk, tmp_path, max_failures=5, clock=lambda: now[0])
    b.reserve_attempt().release(st.Outcome.FAILURE, cooldown_s=100)
    with pytest.raises(errs.Cooldown):
        b.reserve_attempt()
    # A clock that jumps backward never yields a negative remaining.
    now[0] = 0.0
    assert b.status()["cooldown_remaining_s"] >= 0
    with pytest.raises(errs.Cooldown):
        b.reserve_attempt()
    # Past the cooldown, a reservation is admitted again.
    now[0] = 2000.0
    b.reserve_attempt().release(st.Outcome.SUCCESS)
    assert b.status()["cooldown_remaining_s"] == 0


def test_success_clears_cooldown(tmp_path: Path, bk, st) -> None:
    now = [1000.0]
    b = _make(bk, tmp_path, max_failures=5, clock=lambda: now[0])
    b.reserve_attempt().release(st.Outcome.BUSY, cooldown_s=100)
    assert b.status()["state"] == "cooldown"
    now[0] = 2000.0
    b.reserve_attempt().release(st.Outcome.SUCCESS)
    assert b.cooldown_until is None


@pytest.mark.parametrize("token", ["Infinity", "-Infinity", "NaN"])
def test_nonfinite_cooldown_is_treated_as_expired(tmp_path: Path, bk, token: str) -> None:
    # F2 (x1c): a hand-edited non-finite cooldown_until must never make the breaker
    # refuse logins forever. The strict schema the writer emits can never produce one;
    # a foreign/hand edit is self-healed to "no cooldown" (clamp is total, remaining 0).
    now = [1000.0]
    b = _make(bk, tmp_path, max_failures=5, clock=lambda: now[0])
    blob = (
        '{"version": 1, "key": "' + KEY + '", "epoch": 0, "reservations": {}, '
        '"failures": 0, "successes": 0, "tripped": false, "last_failure": null, '
        '"last_update": 1.0, "cooldown_until": ' + token + "}"
    )
    b.path.parent.mkdir(parents=True, exist_ok=True)
    b.path.write_text(blob, encoding="utf-8")
    now[0] = 1000.0 + 10**9
    assert b.status()["cooldown_remaining_s"] == 0
    b.reserve_attempt()  # admitted, not stuck


# ---- 10. No secrets in the ledger or status (claim) -------------------------


def test_no_secret_reaches_the_ledger_or_status(tmp_path: Path, bk, st) -> None:
    b = _make(bk, tmp_path, max_failures=5)
    b.reserve_attempt().release(
        st.Outcome.FAILURE, failure={"device_error_code": -40401, "attempts_left": 2}
    )
    raw = b.path.read_text(encoding="utf-8")
    snap = b.status()
    snap.pop("path", None)  # the filesystem path is not a secret-bearing value
    snapshot = json.dumps(snap)
    for marker in ("password", "secret", "token", "nonce", "ciphertext", "stok"):
        assert marker not in raw.lower()
        assert marker not in snapshot.lower()


# ---- 11. clear() invalidates outstanding reservations (F1, x1c) --------------


def test_clear_then_stale_release_cannot_overadmit(tmp_path: Path, bk, errs, st) -> None:
    # A reservation held across a `breaker --clear` (a separate process) must not, when
    # it finally releases, free a slot that a post-clear holder is still using - that
    # would admit a second attempt over a budget of one.
    b = _make(bk, tmp_path, max_failures=1)
    res_a = b.reserve_attempt()
    assert b.status()["reserved"] == 1
    b.clear()
    assert b.status()["reserved"] == 0
    res_b = b.reserve_attempt()  # the one legitimate post-clear holder
    assert b.status()["reserved"] == 1
    assert res_a.release(st.Outcome.SUCCESS) is True  # stale: the slot it owned is gone
    with pytest.raises(errs.BreakerOpen):
        b.reserve_attempt()  # res_b still holds the single slot; a third is refused
    assert res_b is not None


# ---- POSIX-only hazards (skip on Windows; Ubuntu CI runs them everywhere) ----


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock inode semantics; deploy target is Ubuntu")
def test_posix_lockfile_deletion_breaks_mutual_exclusion(tmp_path: Path, bk, st) -> None:
    """DELETING the lock file mid-hold lets a second acquirer lock a new inode.

    Ported from the x1c breaker battery (as written): proves the store relies on the
    lock file's inode being stable. The store never unlinks its own lock file, so this
    needs an external deleter; it fails (two holders) on Linux if anything deletes the
    ``.lock`` file while it is held."""
    import fcntl

    b = _make(bk, tmp_path, max_failures=1)
    b.reserve_attempt().release(st.Outcome.SUCCESS)  # materialise the store + lock file
    lock_path = b.path.with_name(b.path.stem + ".lock")
    assert lock_path.exists()

    fd_a = os.open(lock_path, os.O_RDWR)
    fcntl.flock(fd_a, fcntl.LOCK_EX | fcntl.LOCK_NB)  # holder A
    try:
        os.unlink(lock_path)  # external deleter removes the name; A keeps the inode
        fd_b = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)  # NEW inode
        try:
            took_second = True
            try:
                fcntl.flock(fd_b, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                took_second = False
            assert not took_second, (
                "a second acquirer locked a NEW inode while holder A still holds the "
                "old one: deleting the .lock file defeats cross-process mutual exclusion."
            )
        finally:
            os.close(fd_b)
    finally:
        os.close(fd_a)


@pytest.mark.skipif(os.name == "nt", reason="requires os.fork + flock; deploy target is Ubuntu")
def test_posix_killed_holder_releases_lock_and_reservation_still_counts(
    tmp_path: Path, bk, errs
) -> None:
    """A process killed while HOLDING the store lock has the lock freed by the OS, and
    its reserved slot (written before it died) still counts against the budget (fail
    closed). Ported from the x1c crash/durability battery (control, as written)."""
    import time

    b = _make(bk, tmp_path, max_failures=1)

    pid = os.fork()
    if pid == 0:  # child: reserve (writes a slot), then die WITHOUT releasing
        try:
            child = _make(bk, tmp_path, max_failures=1)
            child.reserve_attempt()
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    time.sleep(0.05)

    assert b.status()["reserved"] == 1
    with pytest.raises(errs.BreakerOpen):
        b.reserve_attempt()


# ============================================================================
# One primitive, every policy. The reservation primitive (ReservationStore named
# slots + epoch + lock + writability proof) is proven identically for each policy
# built on it: the login breaker, the generic single-slot (the EXPORT lock, and the
# switch cycle guard) and the generic min-interval rate limiter (the router reboot
# limiter). This closes x1c round-2 F1/F5: the export lock's guarantees are the
# primitive's, now conformed here rather than left to a separate, un-fixed path.
# ============================================================================

_POLICIES = ["breaker", "single", "interval"]


class _Pol:
    """A uniform handle over a policy so one case can run against all three."""

    def __init__(self, obj, reserve, clear, status, path) -> None:
        self.obj = obj
        self.reserve = reserve
        self.clear = clear
        self.status = status
        self.path = path


def _policy(
    kind, bk, sl, state_dir, *, key="pol", clock=None, stale_after_s=3600.0, min_interval_s=0.0
):
    clk = clock or time.time
    if kind == "breaker":
        o = bk.LoginBreaker(state_dir, key, max_failures=1, clock=clk)
        return _Pol(o, o.reserve_attempt, o.clear, o.status, o.path)
    if kind == "single":
        store = sl.single_slot_store(state_dir, clock=clk)
        o = sl.SingleSlot(store, key, stale_after_s=stale_after_s, clock=clk)
        return _Pol(o, o.reserve, o.clear, o.status, o.path)
    store = sl.min_interval_store(state_dir, clock=clk)
    o = sl.MinInterval(store, key, min_interval_s=min_interval_s, clock=clk)
    return _Pol(o, o.reserve, o.clear, o.status, o.path)


@pytest.mark.parametrize("kind", _POLICIES)
def test_policy_admits_one_then_refuses_a_second_in_flight(tmp_path, bk, sl, errs, st, kind):
    p = _policy(kind, bk, sl, tmp_path)
    first = p.reserve()
    with pytest.raises(errs.DeviceError):  # BreakerOpen / PreconditionFailed
        p.reserve()
    first.release(st.Outcome.SUCCESS)


@pytest.mark.parametrize("kind", _POLICIES)
def test_policy_unresolved_reservation_is_crash_visible(tmp_path, bk, sl, errs, kind):
    _policy(kind, bk, sl, tmp_path).reserve()  # handle dropped (crash between reserve/release)
    # A fresh instance (the next process) on the same dir/key still sees it and refuses.
    with pytest.raises(errs.DeviceError):
        _policy(kind, bk, sl, tmp_path).reserve()


@pytest.mark.parametrize("kind", _POLICIES)
def test_policy_clear_then_stale_release_cannot_overadmit(tmp_path, bk, sl, errs, st, kind):
    p = _policy(kind, bk, sl, tmp_path)
    res_a = p.reserve()
    p.clear()
    res_b = p.reserve()  # the one legitimate post-clear holder
    assert res_a.release(st.Outcome.SUCCESS) is True  # stale: the slot it owned is gone
    with pytest.raises(errs.DeviceError):
        p.reserve()  # res_b still holds the single slot
    assert res_b is not None


@pytest.mark.parametrize("kind", _POLICIES)
def test_policy_unwritable_store_fails_closed_before_admit(tmp_path, bk, sl, errs, kind):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    p = _policy(kind, bk, sl, blocker / "state")
    with pytest.raises(errs.DeviceError):  # BreakerOpen / StateUnavailable, never fail-open
        p.reserve()
    assert not (blocker / "state").exists()


@pytest.mark.parametrize("kind", _POLICIES)
def test_policy_status_never_blocks_under_lock_contention(tmp_path, bk, sl, st, kind):
    # x1c round-2 F4: status() reads the atomic file WITHOUT the lock, so a --show /
    # healthcheck during any concurrent reserve/release neither blocks nor misreports.
    p = _policy(kind, bk, sl, tmp_path)
    p.reserve().release(st.Outcome.SUCCESS)  # materialise the store + lock file
    lock_path = p.path.with_name(p.path.stem + ".lock")
    fd = _lock_exclusive(lock_path)
    try:
        start = time.monotonic()
        p.status()  # must not raise
        assert time.monotonic() - start < 0.2
    finally:
        _unlock_and_close(fd)


def _lock_exclusive(lock_path: Path) -> int:
    fd = os.open(lock_path, os.O_RDWR)
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _unlock_and_close(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


# ---- F1 (x1c r2): the EXPORT lock's over-admit, closed by named-slot reclaim --


def test_single_slot_old_holder_release_cannot_free_the_current_holder(tmp_path, bk, sl, st):
    now = [1000.0]
    s = sl.SingleSlot(
        sl.single_slot_store(tmp_path, clock=lambda: now[0]),
        "export-dev",
        stale_after_s=60.0,
        clock=lambda: now[0],
    )
    res_a = s.reserve()
    assert s.status()["in_flight"] is True
    now[0] = 2000.0  # A now looks stale (older than 60s)
    res_b = s.reserve()  # B reclaims the slot; B is the CURRENT, fresh, legitimate holder
    assert s.status()["in_flight"] is True
    # A's release owns a slot that was reclaimed away: it MUST be a stale no-op, never a
    # decrement of B's live slot (round-1 F1 / x1c r2 F1).
    assert res_a.release(st.Outcome.SUCCESS) is True
    assert s.status()["in_flight"] is True  # B still holds the single slot
    assert res_b is not None


# ---- F3 (x1c r2): the epoch is a monotonic high-water mark --------------------


def test_epoch_is_monotonic_across_a_corrupt_recovery(tmp_path, bk):
    b = bk.LoginBreaker(tmp_path, "dev", max_failures=1)
    b.clear()
    b.clear()
    b.clear()
    advanced = b.status()["epoch"]
    assert advanced == 3
    b.path.write_text("{ not valid json", encoding="utf-8")  # out-of-band corruption
    b.clear()  # operator recovery
    assert b.status()["epoch"] > advanced  # never repeats a previously-issued value


# ---- F2 (x1c r2): clear() is one locked section; no lost epoch update ---------


def _clear_worker(args: tuple[str, str, str]) -> int:
    pkg, state_dir, key = args
    breaker = importlib.import_module(f"{pkg}.breaker")
    b = breaker.LoginBreaker(Path(state_dir), key, max_failures=1)
    b.clear()
    return b.status()["epoch"]


def test_concurrent_clears_bump_the_epoch_monotonically(tmp_path, bk, pkg_path):
    # Each clear is one locked load->bump->write over a persisted high-water mark, so N
    # concurrent clears advance the epoch by exactly N - no two collapse to one bump
    # (the x1c r2 F2 lost-update the old two-lock clear suffered).
    bk.LoginBreaker(tmp_path, KEY, max_failures=1).clear()  # baseline epoch 1
    n = 8
    jobs = [(pkg_path, str(tmp_path), KEY)] * n
    with ProcessPoolExecutor(max_workers=n) as pool:
        list(pool.map(_clear_worker, jobs))
    assert bk.LoginBreaker(tmp_path, KEY, max_failures=1).status()["epoch"] == 1 + n


# ---- MinInterval: the reserve-before-act rate-limit window --------------------


def test_min_interval_enforces_the_window_and_only_success_consumes_it(tmp_path, bk, sl, errs, st):
    now = [1000.0]
    m = sl.MinInterval(
        sl.min_interval_store(tmp_path, clock=lambda: now[0]),
        "reboot-dev",
        min_interval_s=100.0,
        clock=lambda: now[0],
    )
    m.reserve().release(st.Outcome.SUCCESS)  # completes at t=1000, window starts
    with pytest.raises(errs.PreconditionFailed):
        m.reserve()  # within the 100s window
    # An aborted attempt (not carried out) does NOT consume the window.
    now[0] = 1200.0
    m.reserve().release(st.Outcome.ABORT)
    now[0] = 1250.0  # last COMPLETED action was t=1000, so > 100s has elapsed
    m.reserve().release(st.Outcome.SUCCESS)  # allowed

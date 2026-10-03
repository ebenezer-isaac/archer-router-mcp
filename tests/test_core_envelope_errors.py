from __future__ import annotations

import pytest

from archer_router_mcp.config import load_device_settings
from archer_router_mcp.core import envelope
from archer_router_mcp.core.breaker import LoginBreaker, canonical_device_key
from archer_router_mcp.core.errors import (
    ApiError,
    AuthFailed,
    BreakerOpen,
    InvalidInput,
    LockoutGuard,
    LoginDisabled,
    PreconditionFailed,
    TokenExpired,
)
from archer_router_mcp.core.state import Outcome
from archer_router_mcp.core.tooling import run_tool
from archer_router_mcp.core.write_gate import check_write_gate
from tests.helpers import ROUTER_PREFIX, router_env


def test_ok_shape() -> None:
    assert envelope.ok({"a": 1}) == {"success": True, "data": {"a": 1}, "error": None}
    assert envelope.ok([]) == {"success": True, "data": [], "error": None}


def test_fail_shape_and_details_copied() -> None:
    details = {"k": 1}
    result = envelope.fail("X", "m", details)
    details["k"] = 2
    assert result == {
        "success": False,
        "data": None,
        "error": {"code": "X", "message": "m", "details": {"k": 1}},
    }
    assert envelope.fail("X", "m")["error"]["details"] == {}


def test_auth_failed_surfaces_attempts_left_and_max() -> None:
    result = envelope.from_error(
        AuthFailed("bad", code=-40401, symbol="EUNAUTH", attempts_left=3, max_attempts=10)
    )
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"] == {
        "device_error_code": -40401,
        "symbol": "EUNAUTH",
        "attempts_left": 3,
        "max_attempts": 10,
        "lock_seconds_left": None,
        "locked": False,
    }


@pytest.mark.parametrize(
    ("kwargs", "locked"),
    [
        ({"locked": True}, True),
        ({"attempts_left": 0}, True),
        ({"lock_seconds_left": 60}, True),
        ({"attempts_left": 1}, False),
        ({}, False),
    ],
)
def test_auth_failed_locked_flag(kwargs: dict, locked: bool) -> None:
    assert AuthFailed("x", **kwargs).locked is locked


def test_api_error_includes_symbol_and_meaning() -> None:
    err = ApiError(-40209, symbol="EINVARG", meaning="Invalid argument")
    assert "EINVARG" in str(err)
    details = envelope.from_error(err)["error"]["details"]
    assert details == {
        "device_error_code": -40209,
        "symbol": "EINVARG",
        "meaning": "Invalid argument",
    }


def test_precondition_failed_details() -> None:
    err = PreconditionFailed("m", reason="MAC_EXISTS", context={"mac": "AA"})
    assert envelope.from_error(err)["error"]["details"] == {
        "reason": "MAC_EXISTS",
        "mac": "AA",
    }


def test_error_kinds_are_distinct() -> None:
    kinds = {AuthFailed.kind, TokenExpired.kind, LockoutGuard.kind, ApiError.kind}
    assert len(kinds) == 4


# ---- write gate ---------------------------------------------------------------


def _settings(**overrides: str):
    return load_device_settings(ROUTER_PREFIX, router_env(**overrides))


def test_write_gate_read_passes() -> None:
    assert check_write_gate(_settings(), "get", False) is None


@pytest.mark.parametrize("confirm", [False, True, "true", 1])
def test_write_gate_refuses_when_disallowed(confirm: object) -> None:
    refusal = check_write_gate(_settings(), "set", confirm)
    assert refusal is not None
    assert "ARCHER_ROUTER_ALLOW_WRITES" in refusal["error"]["message"]


@pytest.mark.parametrize("confirm", [False, "true", "yes", 1, None])
def test_write_gate_requires_literal_true(confirm: object) -> None:
    refusal = check_write_gate(_settings(ALLOW_WRITES="true"), "do", confirm)
    assert refusal is not None and "confirm_write" in refusal["error"]["message"]


def test_write_gate_passes_with_both_keys() -> None:
    assert check_write_gate(_settings(ALLOW_WRITES="true"), "delete", True) is None


# ---- login breaker (reserve/release API; full contract in tests/conformance) -------


def test_breaker_reserve_release_spends_budget(tmp_path) -> None:
    b = LoginBreaker(tmp_path, canonical_device_key("192.0.2.1"), max_failures=1)
    b.reserve_attempt().release(Outcome.FAILURE, failure={"x": 1})
    assert b.status()["failures"] == 1
    # Budget of 1 is spent: the next reservation is refused (fail closed).
    with pytest.raises(BreakerOpen):
        b.reserve_attempt()


def test_breaker_login_disabled_is_owned_by_the_breaker(tmp_path) -> None:
    b = LoginBreaker(
        tmp_path, "dev", login_disabled=True, disabled_hint="ARCHER_ROUTER_LOGIN_DISABLED=true"
    )
    with pytest.raises(LoginDisabled, match="frozen"):
        b.reserve_attempt()
    assert not b.path.exists()  # no store I/O at all when frozen


def test_breaker_success_does_not_clear_failures(tmp_path) -> None:
    b = LoginBreaker(tmp_path, "dev", max_failures=3)
    b.reserve_attempt().release(Outcome.FAILURE)
    b.reserve_attempt().release(Outcome.SUCCESS)
    snap = b.status()
    assert snap["failures"] == 1 and snap["successes"] == 1


# ---- run_tool -----------------------------------------------------------------


async def test_run_tool_maps_errors_and_redacts() -> None:
    async def leaky():
        return {"stok": "s", "ok": 1}

    async def bad_input():
        # Only InvalidInput is treated as client input; a plain ValueError is internal.
        raise InvalidInput("nope")

    async def boom():
        raise RuntimeError("internal detail")

    assert (await run_tool("t", leaky))["data"] == {"stok": "<redacted>", "ok": 1}
    assert (await run_tool("t", bad_input))["error"]["code"] == "INVALID_INPUT"
    internal = await run_tool("t", boom)
    assert internal["error"]["code"] == "INTERNAL_ERROR"
    assert "internal detail" not in internal["error"]["message"]


async def test_run_tool_maps_device_error_to_its_kind() -> None:
    async def fails():
        raise AuthFailed("bad credentials", attempts_left=2)

    result = await run_tool("login", fails)
    assert result["success"] is False
    assert result["error"]["code"] == "AUTH_FAILED"
    assert result["error"]["details"]["attempts_left"] == 2


def test_base_device_error_details_are_empty() -> None:
    assert envelope.from_error(TokenExpired("gone"))["error"]["details"] == {}


# ---- serial lock / transport masks / cli helpers ----------------------------------


async def test_serial_lock_serialises() -> None:
    import asyncio

    from archer_router_mcp.core.serial import SerialLock

    lock, order = SerialLock(), []

    async def job(name: str) -> str:
        order.append(f"{name}-start")
        await asyncio.sleep(0)
        order.append(f"{name}-end")
        return name

    results = await asyncio.gather(lock.run(lambda: job("a")), lock.run(lambda: job("b")))
    assert results == ["a", "b"]
    assert order == ["a-start", "a-end", "b-start", "b-end"]
    assert lock.busy is False


def test_token_masks_are_registered_once_and_applied() -> None:
    from archer_router_mcp.core import transport

    transport.register_token_mask(r"sid=\w+", "sid=<x>")
    transport.register_token_mask(r"sid=\w+", "sid=<x>")
    assert sum(p.pattern == r"sid=\w+" for p, _ in transport._MASKS) == 1
    assert transport.mask_tokens("/a?sid=abc123") == "/a?sid=<x>"


def test_cli_helpers(capsys) -> None:
    from archer_router_mcp.core.cli import configure_logging, emit_envelope, emit_lines

    configure_logging("NOPE_LEVEL", {"NOPE_LEVEL": "bogus"})
    assert emit_envelope(envelope.ok({"a": 1})) == 0
    assert emit_envelope(envelope.fail("X", "m")) == 1
    assert emit_lines(["one", "two"]) == 0
    out = capsys.readouterr().out
    assert '"success": true' in out and out.rstrip().endswith("two")

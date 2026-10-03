from __future__ import annotations

import pytest

from archer_router_mcp.core import breaker, envelope
from archer_router_mcp.core.config import load_device_settings
from archer_router_mcp.core.errors import (
    ApiError,
    AuthFailed,
    LockoutGuard,
    PreconditionFailed,
    TokenExpired,
)
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


# ---- lockout helpers ------------------------------------------------------------


def test_ledger_is_immutable_and_rebuilt() -> None:
    ledger = breaker.LoginLedger()
    after = breaker.record_failure(ledger, {"x": 1})
    assert (ledger.failed, after.failed) == (0, 1)
    assert breaker.record_success(after).successful == 1


def test_login_disabled_guard_names_variable() -> None:
    with pytest.raises(LockoutGuard, match="ARCHER_ROUTER_LOGIN_DISABLED"):
        breaker.check_login_allowed(
            breaker.LoginLedger(), _settings(LOGIN_DISABLED="true"), explicit=True
        )


def test_check_login_allowed_budget_and_implicit_rules() -> None:
    one_failure = breaker.record_failure(breaker.LoginLedger(), {"x": 1})
    # Under a higher budget, an implicit login after any failure is still refused,
    while_under_budget = _settings(MAX_LOGIN_FAILURES="3")
    with pytest.raises(LockoutGuard, match="previous login failed"):
        breaker.check_login_allowed(one_failure, while_under_budget, explicit=False)
    # but an explicit login is allowed while the budget has room.
    breaker.check_login_allowed(one_failure, while_under_budget, explicit=True)
    # With the default budget of 1, one failure exhausts it even for explicit logins.
    with pytest.raises(LockoutGuard, match="failed login"):
        breaker.check_login_allowed(one_failure, _settings(), explicit=True)


@pytest.mark.parametrize(
    ("remaining", "explicit", "refused"),
    [
        (None, False, False),
        (0, True, True),
        (-1, True, True),
        (1, True, False),
        (1, False, True),
        (2, False, True),
        (3, False, False),
    ],
)
def test_remaining_attempt_guard(remaining, explicit, refused) -> None:
    if refused:
        with pytest.raises(LockoutGuard):
            breaker.check_remaining_attempts(remaining, explicit=explicit)
    else:
        breaker.check_remaining_attempts(remaining, explicit=explicit)


# ---- run_tool -----------------------------------------------------------------


async def test_run_tool_maps_errors_and_redacts() -> None:
    async def leaky():
        return {"stok": "s", "ok": 1}

    async def bad_input():
        raise ValueError("nope")

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

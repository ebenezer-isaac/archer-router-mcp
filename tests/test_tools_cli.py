"""The router_* tools, their envelopes/redaction, and the CLI surface."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from archer_router_mcp import cli, server
from tests.fakes import FAKE_STOK, FAKE_SYSAUTH, FakeRouter, build_components


def _close(components: server.Components) -> None:
    asyncio.run(components.aclose())


# ------------------------------------------------------------------- tools


async def test_router_status_reports_without_login(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_status(c)
        assert env["success"] is True
        data = env["data"]
        assert data["feature_flags"]["5_gdpr"] is True
        assert data["model"] == "Archer AX53"
        assert data["tls_fingerprint_sha256"] == "aa" * 32
        assert data["breaker"]["state"] == "closed"
        assert fake.login_posts == 0
    finally:
        await c.aclose()


async def test_router_check_auth_capabilities_only(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_check_auth(c, do_login=False)
        assert env["success"] is True
        assert env["data"]["login_attempted"] is False
        assert env["data"]["authenticated"] is False
        assert fake.login_posts == 0
    finally:
        await c.aclose()


async def test_router_check_auth_with_login(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_check_auth(c, do_login=True)
        assert env["data"]["authenticated"] is True
        assert env["data"]["mode"] == "router"
        assert fake.login_posts == 1
    finally:
        await c.aclose()


async def test_router_login_returns_no_token_or_cookie(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_login(c)
        blob = json.dumps(env)
        assert env["data"]["authenticated"] is True
        assert env["data"]["mode"] == "router"
        assert FAKE_STOK not in blob and FAKE_SYSAUTH not in blob
        assert "stok" not in blob and "sysauth" not in blob
    finally:
        await c.aclose()


async def test_router_login_failure_becomes_envelope_not_exception(tmp_path: Path) -> None:
    fake = FakeRouter(
        login_error="login failed", login_failure_data={"failureCount": 1, "attemptsAllowed": 4}
    )
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_login(c)
        assert env["success"] is False
        assert env["error"]["code"] == "AUTH_FAILED"
    finally:
        await c.aclose()


async def test_router_logout_tool(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        await server.router_login(c)
        env = await server.router_logout(c)
        assert env["success"] is True
        assert env["data"] == {"logged_out": True, "was_authenticated": True}
    finally:
        await c.aclose()


# ------------------------------------------------------------------- CLI


async def test_create_app_registers_every_tool(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        app = server.create_app(c)
        registered = {tool.name for tool in await app.list_tools()}
        assert registered == set(server.TOOL_NAMES)
    finally:
        await c.aclose()


def test_cli_list_tools(capsys) -> None:
    rc = cli.main(["--list-tools"])
    assert rc == 0
    out = capsys.readouterr().out.split()
    assert out == list(server.TOOL_NAMES)
    assert "router_status" in out


def test_cli_check_auth(tmp_path: Path, capsys) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        rc = cli.main(["--check-auth"], components=c)
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["success"] is True
        assert payload["data"]["authenticated"] is False
        assert fake.login_posts == 0
    finally:
        _close(c)


def test_cli_check_auth_with_login(tmp_path: Path, capsys) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        rc = cli.main(["--check-auth", "--login"], components=c)
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["data"]["authenticated"] is True
        assert fake.login_posts == 1
    finally:
        _close(c)


def test_cli_breaker_show_and_clear(tmp_path: Path, capsys) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        c.breaker.record_failure({"error": "login failed", "failure_count": 1})
        rc = cli.main(["breaker", "--show"], components=c)
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0  # show always emits an ok envelope
        assert payload["success"] is True
        assert payload["data"]["failed"] == 1
        assert payload["data"]["state"] == "open"

        rc2 = cli.main(["breaker", "--clear"], components=c)
        cleared = json.loads(capsys.readouterr().out)
        assert rc2 == 0
        assert cleared["data"]["cleared"] is True
        assert c.breaker.snapshot().failed == 0
    finally:
        _close(c)


def test_cli_check_auth_config_error_is_envelope(monkeypatch, capsys) -> None:
    # No host/password in the environment -> a clean CONFIG_ERROR envelope, not a crash.
    for key in list(__import__("os").environ):
        if key.startswith(("ARCHER_ROUTER_", "ARCHER_MCP_")):
            monkeypatch.delenv(key, raising=False)
    rc = cli.main(["--check-auth"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["success"] is False
    assert payload["error"]["code"] == "CONFIG_ERROR"


def test_cli_no_args_prints_help(capsys) -> None:
    rc = cli.main([])
    captured = capsys.readouterr()
    assert rc == 0
    assert "archer-router-mcp" in captured.err


def test_cli_unknown_flag_rejected() -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--bogus"])
    assert info.value.code == 2

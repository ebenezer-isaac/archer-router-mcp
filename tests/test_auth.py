"""Transport and authenticator behaviour against the fake Archer router."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from archer_router_mcp.core.errors import LockoutGuard, TransportError
from archer_router_mcp.errors import AuthFailed, LockedOut, ProtocolError, SessionConflict
from archer_router_mcp.transport import ArcherTransport, build_url
from tests.fakes import FAKE_SYSAUTH, FakeRouter, build_components

# ------------------------------------------------------------------- transport


def test_build_url_shapes() -> None:
    prefix = "/cgi-bin/luci/;stok="  # token slot is empty before login
    assert build_url("", "/login?form=keys") == prefix + "/login?form=keys"
    assert build_url("ABC", "/admin/x?form=y") == prefix + "ABC/admin/x?form=y"


async def _transport(handler, **kw) -> ArcherTransport:
    return ArcherTransport(
        host="192.0.2.1",
        port=443,
        base_url="https://192.0.2.1:443",
        verify_tls=False,
        timeout_seconds=5.0,
        http_transport=httpx.MockTransport(handler),
        **kw,
    )


async def test_cookie_round_trips() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("cookie"))
        return httpx.Response(200, headers={"Set-Cookie": "sysauth=XYZ; Path=/"}, content="{}")

    t = await _transport(handler)
    try:
        await t.post(token="", path="/login?form=login", body="operation=login")
        assert t.sysauth == "XYZ"
        await t.post(token="XYZ", path="/admin/x?form=y", body="operation=read")
        assert seen[1] is not None and "sysauth=XYZ" in seen[1]
        t.clear_session_cookie()
        assert t.sysauth is None
    finally:
        await t.aclose()


async def test_http_error_maps_to_transport_error() -> None:
    t = await _transport(lambda r: httpx.Response(500))
    try:
        with pytest.raises(TransportError, match="HTTP 500"):
            await t.post(token="", path="/login?form=keys", body="operation=read")
    finally:
        await t.aclose()


async def test_oversize_response_rejected(monkeypatch) -> None:
    import archer_router_mcp.transport as tmod

    monkeypatch.setattr(tmod, "MAX_RESPONSE_BYTES", 4)
    t = await _transport(lambda r: httpx.Response(200, content=b"xxxxxxxx"))
    try:
        with pytest.raises(TransportError, match="size limit"):
            await t.post(token="", path="/p", body="operation=read")
    finally:
        await t.aclose()


async def test_fingerprint_pin_match_allows_request() -> None:
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, content="{}")

    t = await _transport(
        handler,
        tls_fingerprint_sha256="ab" * 32,
        fingerprint_probe=_probe_returning("AB" * 32),
    )
    try:
        await t.post(token="", path="/p", body="operation=read")
        assert called["n"] == 1
        assert await t.observed_fingerprint() == "ab" * 32
    finally:
        await t.aclose()


async def test_fingerprint_mismatch_sends_no_request() -> None:
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, content="{}")

    t = await _transport(
        handler,
        tls_fingerprint_sha256="aa" * 32,
        fingerprint_probe=_probe_returning("bb" * 32),
    )
    try:
        with pytest.raises(TransportError, match="does not match"):
            await t.post(token="", path="/p", body="operation=read")
        assert called["n"] == 0  # fail closed: the request body never left
    finally:
        await t.aclose()


def _probe_returning(value: str):
    async def _probe() -> str:
        return value

    return _probe


# ----------------------------------------------------------- device_config / reads


async def test_read_device_config_derives_sg_flags(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        caps = await c.authenticator.read_device_config()
        assert caps.certification == ["US FCC", "SG CLS L1 STAGE2"]
        assert caps.flags["5_gdpr"] is True and caps.flags["13_rsa_pad_with_pkcs1_oaep"] is True
        assert caps.model == "Archer AX53"
        assert fake.login_posts == 0  # capability read never logs in
    finally:
        await c.aclose()


async def test_unexpected_ui_version_warns_not_fails(tmp_path: Path, caplog) -> None:
    fake = FakeRouter(ui_version="AX53v1_2.0.0_2027-01-01")
    c = build_components(fake, state_dir=tmp_path)
    try:
        with caplog.at_level("WARNING"):
            caps = await c.authenticator.read_device_config()
        assert caps.ui_version == "AX53v1_2.0.0_2027-01-01"
        assert any("does not match" in r.message for r in caplog.records)
    finally:
        await c.aclose()


async def test_html_instead_of_json_is_protocol_error(tmp_path: Path) -> None:
    fake = FakeRouter(device_config_html=True)
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(ProtocolError):
            await c.authenticator.read_device_config()
    finally:
        await c.aclose()


# ------------------------------------------------------------------- login paths


@pytest.mark.parametrize("envelope", ["http-encrypted", "https-plain"])
async def test_login_succeeds_both_envelopes(tmp_path: Path, envelope: str) -> None:
    fake = FakeRouter(envelope=envelope)
    c = build_components(fake, envelope=envelope, state_dir=tmp_path)
    try:
        session = await c.authenticator.login(explicit=True)
        assert session.mode == "router"
        assert c.transport.sysauth == FAKE_SYSAUTH
        assert fake.login_posts == 1
        assert fake.confirm_values == [False]  # confirm defaults to False
        assert c.breaker.snapshot().successful == 1
    finally:
        await c.aclose()


async def test_login_failed_raises_without_retry_and_writes_breaker(tmp_path: Path) -> None:
    fake = FakeRouter(
        login_error="login failed", login_failure_data={"failureCount": 2, "attemptsAllowed": 3}
    )
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(AuthFailed) as info:
            await c.authenticator.login(explicit=True)
        assert info.value.attempts_left == 3
        assert info.value.max_attempts == 5
        assert fake.login_posts == 1  # never retried
        assert c.breaker.snapshot().failed == 1
    finally:
        await c.aclose()


async def test_exceeded_max_attempts_is_locked_out(tmp_path: Path) -> None:
    fake = FakeRouter(login_error="exceeded max attempts")
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(LockedOut) as info:
            await c.authenticator.login(explicit=True)
        assert info.value.seconds_left == 7200
        assert c.breaker.snapshot().failed == 1
    finally:
        await c.aclose()


async def test_multiple_login_is_locked_out(tmp_path: Path) -> None:
    fake = FakeRouter(login_error="multiple login")
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(LockedOut):
            await c.authenticator.login(explicit=True)
    finally:
        await c.aclose()


async def test_user_conflict_without_force_raises(tmp_path: Path) -> None:
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(SessionConflict):
            await c.authenticator.login(explicit=True, force_takeover=True)  # env gate still off
        assert fake.login_posts == 1  # no takeover attempt without the env flag
    finally:
        await c.aclose()


async def test_user_conflict_with_force_takes_over_once(tmp_path: Path) -> None:
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(
        fake, state_dir=tmp_path, extra_env={"ARCHER_ROUTER_FORCE_SESSION_TAKEOVER": "true"}
    )
    try:
        session = await c.authenticator.login(explicit=True, force_takeover=True)
        assert session.mode == "router"
        assert fake.login_posts == 2
        assert fake.confirm_values == [False, True]  # exactly one confirm=true resend
    finally:
        await c.aclose()


async def test_force_env_without_argument_does_not_take_over(tmp_path: Path) -> None:
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(
        fake, state_dir=tmp_path, extra_env={"ARCHER_ROUTER_FORCE_SESSION_TAKEOVER": "true"}
    )
    try:
        with pytest.raises(SessionConflict):
            await c.authenticator.login(explicit=True, force_takeover=False)
        assert fake.login_posts == 1
    finally:
        await c.aclose()


async def test_login_html_is_protocol_error(tmp_path: Path) -> None:
    fake = FakeRouter(login_html=True)
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(ProtocolError):
            await c.authenticator.login(explicit=True)
    finally:
        await c.aclose()


async def test_login_disabled_makes_no_network_call(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(
        fake, state_dir=tmp_path, extra_env={"ARCHER_ROUTER_LOGIN_DISABLED": "true"}
    )
    try:
        # The credential-free probe still works.
        await c.authenticator.read_device_config()
        probe_paths = len(fake.paths)
        with pytest.raises(LockoutGuard, match="frozen"):
            await c.authenticator.login(explicit=True)
        assert fake.login_posts == 0
        assert len(fake.paths) == probe_paths  # not even keys/auth were fetched
    finally:
        await c.aclose()


async def test_breaker_open_blocks_login_with_no_network(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        c.breaker.record_failure({"error": "login failed"})  # budget of 1 now spent
        with pytest.raises(LockoutGuard):
            await c.authenticator.login(explicit=True)
        assert fake.login_posts == 0
    finally:
        await c.aclose()

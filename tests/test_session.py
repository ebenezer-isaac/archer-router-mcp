"""RouterSession: envelopes, rolling hash, re-login on timeout, logout, context."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from archer_router_mcp import crypto
from archer_router_mcp.core.errors import TokenExpired
from archer_router_mcp.errors import RouterError
from tests.fakes import FAKE_STOK, FAKE_SYSAUTH, FakeRouter, build_components


@pytest.mark.parametrize("envelope", ["http-encrypted", "https-plain"])
async def test_request_round_trips_both_envelopes(tmp_path: Path, envelope: str) -> None:
    fake = FakeRouter(envelope=envelope, authed_payload={"value": 7})
    c = build_components(fake, envelope=envelope, state_dir=tmp_path)
    try:
        await c.session.login(explicit=True)
        data = await c.session.request("admin/status", "all", "read")
        assert data == {"value": 7}
    finally:
        await c.aclose()


async def test_lazy_login_on_first_request(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        assert c.session.authenticated is False
        await c.session.request("admin/x", "y", "read")
        assert c.session.authenticated is True
        assert fake.login_posts == 1
    finally:
        await c.aclose()


async def test_rolling_hash_per_request_and_seq_constant(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        session = await c.session.login(explicit=True)
        for _ in range(3):
            await c.session.request("admin/x", "y", "read")
        assert len(fake.authed_requests) == 3
        # Each request's signature is HMAC over this request's OWN ciphertext hash,
        # and seq never increments.
        hashes_seen = set()
        for _form, data_b64, sign in fake.authed_requests:
            expected = crypto.sign_request(
                session.aes, crypto.rolling_hash(data_b64), session.seq, data_b64
            )
            assert sign == expected
            hashes_seen.add(crypto.rolling_hash(data_b64))
        assert len(hashes_seen) == 1  # identical read bodies -> identical self-contained hashes
    finally:
        await c.aclose()


async def test_timeout_triggers_exactly_one_relogin_then_succeeds(tmp_path: Path) -> None:
    fake = FakeRouter(authed_errors=["timeout", None])
    c = build_components(fake, state_dir=tmp_path)
    try:
        await c.session.login(explicit=True)
        data = await c.session.request("admin/x", "y", "read")
        assert data == {"ok": True}
        assert fake.login_posts == 2  # one initial + one re-login
    finally:
        await c.aclose()


async def test_timeout_twice_raises_without_third_login(tmp_path: Path) -> None:
    fake = FakeRouter(authed_errors=["timeout", "timeout"])
    c = build_components(fake, state_dir=tmp_path)
    try:
        await c.session.login(explicit=True)
        with pytest.raises(TokenExpired):
            await c.session.request("admin/x", "y", "read")
        assert fake.login_posts == 2  # never a third login
    finally:
        await c.aclose()


async def test_non_timeout_error_surfaces_as_router_error(tmp_path: Path) -> None:
    fake = FakeRouter(authed_errors=["permission denied"])
    c = build_components(fake, state_dir=tmp_path)
    try:
        await c.session.login(explicit=True)
        with pytest.raises(RouterError) as info:
            await c.session.request("admin/x", "y", "read")
        assert info.value.code == "permission denied"
        assert fake.login_posts == 1  # a non-timeout error is NOT re-logged-in
    finally:
        await c.aclose()


async def test_logout_sends_request_and_clears_state(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        await c.session.login(explicit=True)
        await c.session.logout()
        assert c.session.authenticated is False
        assert c.transport.sysauth is None
        logout_calls = [
            (path, form)
            for path, form in fake.paths
            if path.endswith("/admin/system") and form == "logout"
        ]
        assert len(logout_calls) == 1 and FAKE_STOK in logout_calls[0][0]
    finally:
        await c.aclose()


async def test_logout_without_session_is_noop(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        await c.session.logout()
        assert fake.login_posts == 0
        assert fake.paths == []
    finally:
        await c.aclose()


async def test_context_manager_logs_out_even_after_exception(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        with pytest.raises(RuntimeError):
            async with c.session as s:
                await s.login(explicit=True)
                raise RuntimeError("boom")
        assert c.session.authenticated is False
        assert any(form == "logout" for _p, form in fake.paths)
    finally:
        await c.aclose()


async def test_serial_lock_prevents_concurrent_logins(tmp_path: Path) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        # Two concurrent first-requests must not each trigger their own login.
        await asyncio.gather(
            c.session.request("admin/a", "x", "read"),
            c.session.request("admin/b", "x", "read"),
        )
        assert fake.login_posts == 1
    finally:
        await c.aclose()


async def test_no_secrets_in_logs(tmp_path: Path, caplog) -> None:
    fake = FakeRouter()
    c = build_components(fake, state_dir=tmp_path)
    try:
        with caplog.at_level("DEBUG"):
            await c.session.login(explicit=True)
            await c.session.request("admin/x", "y", "read")
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert "TestPass123" not in blob
        assert FAKE_SYSAUTH not in blob
        assert "FAKESTOK000000000000" not in blob  # token masked in logged URLs
    finally:
        await c.aclose()

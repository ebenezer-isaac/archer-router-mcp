"""Device-agnostic tests for core.transport (part of the copied core template)."""

from __future__ import annotations

import logging

import httpx
import pytest

from archer_router_mcp.core import transport as T
from archer_router_mcp.core.errors import TransportError


def _transport(handler) -> T.JsonHttpTransport:
    return T.JsonHttpTransport(
        "https://192.0.2.1",
        verify_tls=False,
        timeout_seconds=5.0,
        headers={"X-Test": "1"},
        http_transport=httpx.MockTransport(handler),
    )


async def test_post_json_success_returns_object() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/json"
        return httpx.Response(200, json={"ok": True})

    t = _transport(handler)
    try:
        assert await t.post_json("/path", {"method": "get"}) == {"ok": True}
    finally:
        await t.aclose()


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(500),
        lambda r: httpx.Response(200, content=b"not json"),
        lambda r: httpx.Response(200, json=[1, 2, 3]),
    ],
)
async def test_post_json_bad_responses_raise_transport_error(handler) -> None:
    t = _transport(handler)
    try:
        with pytest.raises(TransportError):
            await t.post_json("/p", {"method": "get"})
    finally:
        await t.aclose()


async def test_post_json_timeout_and_httperror_map_to_transport_error() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow", request=request)

    def neterr(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    for handler in (timeout, neterr):
        t = _transport(handler)
        try:
            with pytest.raises(TransportError):
                await t.post_json("/p", {"method": "get"})
        finally:
            await t.aclose()


async def test_post_json_oversize_response_rejected(monkeypatch) -> None:
    monkeypatch.setattr(T, "MAX_RESPONSE_BYTES", 4)
    t = _transport(lambda r: httpx.Response(200, json={"big": "xxxxxxxxxx"}))
    try:
        with pytest.raises(TransportError, match="size limit"):
            await t.post_json("/p", {"method": "get"})
    finally:
        await t.aclose()


async def test_get_bytes_streams_with_cap() -> None:
    t = _transport(lambda r: httpx.Response(200, content=b"abcdef"))
    try:
        assert await t.get_bytes("/f", max_bytes=100) == b"abcdef"
        with pytest.raises(TransportError, match="size limit"):
            await t.get_bytes("/f", max_bytes=3)
    finally:
        await t.aclose()


async def test_get_bytes_non_200_and_errors_raise() -> None:
    t = _transport(lambda r: httpx.Response(404))
    try:
        with pytest.raises(TransportError):
            await t.get_bytes("/f", max_bytes=100)
    finally:
        await t.aclose()

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    t2 = _transport(boom)
    try:
        with pytest.raises(TransportError):
            await t2.get_bytes("/f", max_bytes=100)
    finally:
        await t2.aclose()


def test_body_summary_lists_modules_without_values() -> None:
    summary = T.body_summary({"method": "set", "wireless": {"psk_key": "x"}, "nat": 1})
    assert "method=set" in summary
    assert "nat" in summary and "wireless" in summary
    assert "psk_key" not in summary and "x" not in summary


def test_mask_filter_scrubs_log_records(caplog) -> None:
    T.register_token_mask(r"tok=[0-9a-f]+", "tok=<redacted>")
    record = logging.LogRecord("n", logging.INFO, __file__, 1, "see tok=deadbeef here", None, None)
    assert T._MaskTokenFilter().filter(record) is True
    assert "deadbeef" not in record.getMessage()

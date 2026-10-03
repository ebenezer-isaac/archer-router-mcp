"""Coverage for the device-agnostic ``core/`` modules this repo ships verbatim.

The router uses a subset of ``core`` directly, but the whole template is shipped and
hashed (the identity test), so these exercise the shared pieces the router's own
suites do not otherwise reach: the core config loaders/validators, ``GuardedWriter``,
the ``read_state``/``write_state``/``ReservationStore`` primitives, the ``JsonHttpTransport``
pinning backend, and the error ``details()`` payloads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import httpcore
import httpx
import pytest
from pydantic import ConfigDict

from archer_router_mcp.core import config as core_config
from archer_router_mcp.core.errors import (
    ConfigError,
    Cooldown,
    LockoutGuard,
    StateUnavailable,
    TlsPinMismatch,
    TransportError,
    WriteNotEnabled,
)
from archer_router_mcp.core.serial import GuardedWriter
from archer_router_mcp.core.state import (
    Outcome,
    ReservationStore,
    SlotLedger,
    ensure_dir,
    read_state,
    write_state,
)
from archer_router_mcp.core.transport import (
    JsonHttpTransport,
    _der_from_ssl_object,
    _PinningBackend,
    fingerprint_sha256,
)
from tests.fakes import FakeNetworkStream, FakeSSLObject

# --------------------------------------------------------------- core config


def _core_settings(**overrides: str):
    env = {"ACME_HOST": "192.0.2.1", "ACME_PASSWORD": "pw", **overrides}
    return core_config.load_device_settings("ACME_", env)


def test_core_device_settings_media_fields_and_properties() -> None:
    s = _core_settings(
        ACME_RTSP_USERNAME="ru",
        ACME_RTSP_PASSWORD="rp",
        ACME_FFMPEG="/usr/bin/ffmpeg",
        ACME_EXPORT_DIR="exports",
    )
    assert s.rtsp_username == "ru"
    assert s.effective_rtsp_username == "ru"
    assert s.effective_rtsp_password == "rp"
    assert s.export_path == Path("exports").expanduser()
    assert s.host_for_url == "192.0.2.1"


def test_core_rtsp_defaults_to_login_credentials() -> None:
    s = _core_settings()
    assert s.effective_rtsp_username == "admin"
    assert s.effective_rtsp_password == "pw"


def test_core_host_for_url_brackets_ipv6() -> None:
    assert _core_settings(ACME_HOST="2001:db8::1").host_for_url == "[2001:db8::1]"


@pytest.mark.parametrize(
    "overrides",
    [
        {"ACME_RTSP_USERNAME": "bad user"},
        {"ACME_RTSP_PASSWORD": "bad\x00pw"},
        {"ACME_FFMPEG": "ff\x00mpeg"},
        {"ACME_EXPORT_DIR": "exp\x00ort"},
        {"ACME_STATE_DIR": "st\x00ate"},
    ],
)
def test_core_settings_reject_bad_values(overrides: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        _core_settings(**overrides)


def test_core_load_rejects_unknown_and_bad_prefix() -> None:
    with pytest.raises(ConfigError, match="BOGUS"):
        core_config.load_device_settings("ACME_", {"ACME_HOST": "192.0.2.1", "ACME_BOGUS": "1"})
    with pytest.raises(ConfigError):
        core_config.load_global_settings("bad", {})


def test_core_load_global_settings_ok() -> None:
    g = core_config.load_global_settings("ACME_MCP_", {"ACME_MCP_TRANSPORT": "streamable-http"})
    assert g.mcp_transport == "streamable-http"


def test_core_normalise_fingerprint_non_string() -> None:
    with pytest.raises(ValueError, match="hex"):
        core_config.normalise_fingerprint(123)


# --------------------------------------------------------------- GuardedWriter


async def _coro(value: Any) -> Any:
    return value


async def test_guarded_writer_dry_run_echoes_and_skips_io() -> None:
    gw = GuardedWriter(_core_settings(ACME_DRY_RUN="true"))
    assert await gw.run({"x": 1}, lambda: _coro("ran")) == {"dry_run": True, "request": {"x": 1}}


async def test_guarded_writer_live_runs_under_lock() -> None:
    gw = GuardedWriter(_core_settings(ACME_ALLOW_WRITES="true"))
    assert await gw.run({}, lambda: _coro(5)) == 5
    assert gw.busy is False


async def test_guarded_writer_refuses_a_gated_write_without_writes_enabled() -> None:
    gw = GuardedWriter(_core_settings())  # allow_writes defaults off
    with pytest.raises(WriteNotEnabled):
        await gw.run({}, lambda: _coro(1))


async def test_guarded_writer_ungated_operation_runs_with_writes_off() -> None:
    gw = GuardedWriter(_core_settings())
    assert await gw.run({}, lambda: _coro(2), require_gate=False) == 2


# --------------------------------------------------------------- state primitives


class _Ledger(SlotLedger):
    """A minimal v1.3.0 ledger: the shared epoch + named slots, plus a policy field."""

    model_config = ConfigDict(strict=True, extra="forbid")

    version: Literal[1] = 1
    key: str
    note: str = "x"


def _fresh(key: str, epoch: int) -> _Ledger:
    return _Ledger(key=key, epoch=epoch, reservations={}, last_update=0.0, note="x")


def test_ensure_dir_rejects_a_file_in_the_path(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(StateUnavailable):
        ensure_dir(f)  # exists but is not a directory
    with pytest.raises(StateUnavailable):
        ensure_dir(f / "sub")  # a parent is a regular file


def test_read_write_state_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "nested" / "s.json"
    assert read_state(p, _Ledger) is None  # absent -> None (creates nothing)
    write_state(p, _Ledger(key="k", epoch=1, reservations={}, last_update=1.0, note="n"))
    got = read_state(p, _Ledger)
    assert got is not None
    assert got.note == "n"
    assert got.epoch == 1


def test_read_state_failures(tmp_path: Path) -> None:
    as_dir = tmp_path / "dir.json"
    as_dir.mkdir()
    with pytest.raises(StateUnavailable):
        read_state(as_dir, _Ledger)  # reading a directory -> OSError
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"version": 1, "key": "k", "note": "n", "epoch": "x", '
        '"reservations": {}, "last_update": 1.0}',
        encoding="utf-8",
    )
    with pytest.raises(StateUnavailable):
        read_state(bad, _Ledger)  # wrong type, strict schema
    not_json = tmp_path / "nj.json"
    not_json.write_text("not json", encoding="utf-8")
    with pytest.raises(StateUnavailable):
        read_state(not_json, _Ledger)  # unparseable
    not_obj = tmp_path / "arr.json"
    not_obj.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(StateUnavailable):
        read_state(not_obj, _Ledger)  # a JSON array is not an object


def test_write_state_fails_on_unwritable(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("x", encoding="utf-8")  # a regular file where a parent dir must be
    with pytest.raises(StateUnavailable):
        write_state(f / "s.json", _Ledger(key="k", epoch=0, reservations={}, last_update=0.0))


def test_reservation_store_reserve_release_cycle(tmp_path: Path) -> None:
    store: ReservationStore[_Ledger] = ReservationStore(tmp_path, _Ledger, make_default=_fresh)

    def admit(ledger: _Ledger) -> None:
        # One slot at a time: refuse a second concurrent reservation.
        if ledger.reservations:
            raise StateUnavailable("already reserved")

    def mutate(ledger: _Ledger, outcome: Outcome, kwargs: dict[str, Any]) -> _Ledger:
        return ledger.model_copy(update={"note": outcome.value})

    res = store.reserve("t", admit, mutate, meta={"pid": 1})
    live = store.load("t")
    assert live is not None and live.reserved == 1  # the insert IS the admission
    assert res.resolved is False
    res.release(Outcome.SUCCESS)
    done = store.load("t")
    assert done is not None and done.reserved == 0  # the release frees only its own slot
    assert done.note == "success"  # mutate applied the outcome
    assert res.resolved is True
    assert res.release(Outcome.SUCCESS) is False  # double release is a no-op (not stale)


def test_reservation_store_clear_bumps_epoch_and_recovers(tmp_path: Path) -> None:
    store: ReservationStore[_Ledger] = ReservationStore(tmp_path, _Ledger, make_default=_fresh)
    store.reserve("t", lambda ledger: None)  # leave one slot in flight (never released)
    assert store.load("t").reserved == 1
    store.clear("t")  # one locked section: fresh ledger at a bumped epoch
    cleared = store.load("t")
    assert cleared is not None
    assert cleared.reserved == 0
    assert cleared.epoch >= 1  # monotonic high-water mark advanced


# --------------------------------------------------------------- transport pinning

_PIN_DER = b"genuine-leaf-certificate"
_PIN = fingerprint_sha256(_PIN_DER)


def _json_transport(handler, **kw) -> JsonHttpTransport:
    return JsonHttpTransport(
        "https://192.0.2.1",
        verify_tls=False,
        timeout_seconds=5.0,
        http_transport=httpx.MockTransport(handler),
        host="192.0.2.1",
        port=443,
        **kw,
    )


async def test_jsonhttp_pin_match_records_observed() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"ok": True}, extensions={"network_stream": FakeNetworkStream(_PIN_DER)}
        )

    t = _json_transport(handler, tls_fingerprint=_PIN)
    try:
        assert await t.post_json("/p", {"method": "get"}) == {"ok": True}
        assert t.observed_fingerprint == _PIN
    finally:
        await t.aclose()


async def test_jsonhttp_pin_mismatch_is_refused() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"ok": True}, extensions={"network_stream": FakeNetworkStream(b"impostor")}
        )

    t = _json_transport(handler, tls_fingerprint=_PIN)
    try:
        with pytest.raises(TlsPinMismatch):
            await t.post_json("/p", {"method": "get"})
    finally:
        await t.aclose()


async def test_jsonhttp_pin_without_network_stream_fails_closed() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})  # no network_stream to read the cert from

    t = _json_transport(handler, tls_fingerprint=_PIN)
    try:
        with pytest.raises(TransportError):
            await t.post_json("/p", {"method": "get"})
    finally:
        await t.aclose()


async def test_jsonhttp_get_bytes_verifies_pin() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"abc", extensions={"network_stream": FakeNetworkStream(_PIN_DER)}
        )

    t = _json_transport(handler, tls_fingerprint=_PIN)
    try:
        assert await t.get_bytes("/f", max_bytes=100) == b"abc"
    finally:
        await t.aclose()


async def test_jsonhttp_builds_real_pinning_backend_when_unmocked() -> None:
    # No http_transport + a pin -> the real pinning transport is constructed. We only
    # build and close it (a real request would need a device); this covers the wiring.
    t = JsonHttpTransport(
        "https://192.0.2.1",
        verify_tls=False,
        timeout_seconds=5.0,
        tls_fingerprint=_PIN,
        host="192.0.2.1",
        port=443,
    )
    await t.aclose()


def test_der_from_ssl_object_none_and_empty() -> None:
    assert _der_from_ssl_object(None) is None
    assert _der_from_ssl_object(FakeSSLObject(b"")) is None
    assert _der_from_ssl_object(FakeSSLObject(b"der")) == b"der"


# ---- the pinning network backend / stream (exercised with fakes) -------------


class _FakeTlsStream:
    def __init__(self, der: bytes) -> None:
        self._ssl = FakeSSLObject(der)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return b"r"

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def get_extra_info(self, name: str) -> Any:
        return self._ssl if name == "ssl_object" else None


class _FakeInnerStream:
    def __init__(self, der: bytes) -> None:
        self._der = der

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return _FakeTlsStream(self._der)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return b"inner"

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def get_extra_info(self, name: str) -> Any:
        return "info"


class _FakeBackend:
    def __init__(self, der: bytes) -> None:
        self._der = der

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        return _FakeInnerStream(self._der)


async def test_pinning_backend_verifies_leaf_at_handshake() -> None:
    seen: list[bytes | None] = []

    def verify(ssl_object: Any) -> None:
        seen.append(_der_from_ssl_object(ssl_object))

    backend: Any = _PinningBackend(_FakeBackend(b"leaf-cert"), verify)
    stream = await backend.connect_tcp("host", 443)
    tls = await stream.start_tls(None, server_hostname="host")
    assert seen == [b"leaf-cert"]  # verified immediately after the handshake
    assert await tls.read(10) == b"r"
    await tls.write(b"x")
    assert tls.get_extra_info("ssl_object") is not None
    await tls.aclose()
    # the pre-handshake stream also delegates
    assert await stream.read(10) == b"inner"
    await stream.write(b"y")
    assert stream.get_extra_info("anything") == "info"
    await stream.aclose()


# --------------------------------------------------------------- error details


def test_cooldown_and_lockout_details() -> None:
    assert Cooldown("m", cooldown_remaining_s=5.0).details() == {"cooldown_remaining_s": 5.0}
    lg = LockoutGuard("r", attempts_left=2, max_attempts=5, lock_seconds_left=10)
    assert lg.details() == {"attempts_left": 2, "max_attempts": 5, "lock_seconds_left": 10}


def test_httpcore_backend_is_available() -> None:
    # Sanity: the backend type the real pinning transport wraps exists in this env.
    assert hasattr(httpcore, "AnyIOBackend")

"""Generic JSON-over-HTTPS transport (httpx) with certificate pinning on httpx's
OWN connection.

Request and response bodies are never logged. Device packages register the shape of
any session token that appears in URLs with ``register_token_mask``; matches are
masked in every log line, including httpx's own request lines.

TLS pinning is enforced on the connection that actually carries the request, not on
a side-channel probe: a custom httpcore network backend wraps every new connection
and, immediately after the TLS handshake (``start_tls``), reads the leaf
certificate's DER, computes its SHA-256 and compares it to the pin **before
returning the stream**, so a mismatch raises :class:`TlsPinMismatch` before any
request bytes are sent. There is no "checked once" latch: every new connection is
verified. The observed fingerprint is taken from that real connection. As
defense-in-depth (and to serve ``tls_fingerprint_observed`` when the handshake is
mocked in tests), each request also re-reads the serving connection's certificate
from ``response.extensions["network_stream"]`` and re-compares it to the pin.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable
from typing import Any

import httpcore
import httpx

from .errors import TlsPinMismatch, TransportError

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MASKS: list[tuple[re.Pattern[str], str]] = []


def fingerprint_sha256(der: bytes) -> str:
    """Lower-case hex SHA-256 of a DER-encoded certificate."""
    return hashlib.sha256(der).hexdigest()


def verify_cert_fingerprint(der: bytes, pin: str) -> None:
    """Raise ``TlsPinMismatch`` unless ``der``'s SHA-256 equals ``pin`` (fail closed)."""
    if fingerprint_sha256(der) != pin:
        raise TlsPinMismatch("device TLS certificate fingerprint does not match the configured pin")


def register_token_mask(pattern: str, replacement: str) -> None:
    """Mask ``pattern`` as ``replacement`` in all logs and logged paths (idempotent)."""
    compiled = re.compile(pattern)
    if all(existing.pattern != compiled.pattern for existing, _ in _MASKS):
        _MASKS.append((compiled, replacement))


def mask_tokens(text: str) -> str:
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


class _MaskTokenFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if _MASKS:
            message = record.getMessage()
            masked = mask_tokens(message)
            if masked != message:
                record.msg = masked
                record.args = None
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(_MaskTokenFilter())


def body_summary(body: dict[str, Any]) -> str:
    modules = sorted(k for k in body if k != "method")
    return f"method={body.get('method')!s} modules={modules}"


def _der_from_ssl_object(ssl_object: Any) -> bytes | None:
    if ssl_object is None:
        return None
    der = ssl_object.getpeercert(binary_form=True)
    return der or None


class _PinnedStream(httpcore.AsyncNetworkStream):
    """Wraps an httpcore stream so the pin is checked at ``start_tls``."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, verify: Callable[[Any], None]) -> None:
        self._inner = inner
        self._verify = verify

    async def start_tls(
        self,
        ssl_context: Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        tls_stream = await self._inner.start_tls(
            ssl_context, server_hostname=server_hostname, timeout=timeout
        )
        # Read the leaf certificate of THIS connection and verify before returning,
        # so no request bytes can be sent over a stream that failed the pin.
        self._verify(tls_stream.get_extra_info("ssl_object"))
        return _PinnedStream(tls_stream, self._verify)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _PinningBackend(httpcore.AsyncNetworkBackend):
    """A network backend whose every new connection is pin-checked at handshake."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend, verify: Callable[[Any], None]) -> None:
        self._inner = inner
        self._verify = verify

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        return _PinnedStream(stream, self._verify)

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover - never used (HTTPS over TCP only)
        return await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:  # pragma: no cover - delegated
        await self._inner.sleep(seconds)


class JsonHttpTransport:
    def __init__(
        self,
        base_url: str,
        *,
        verify_tls: bool,
        timeout_seconds: float,
        headers: dict[str, str] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        tls_fingerprint: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self._pin = tls_fingerprint
        self._host = host
        self._port = port
        self._observed: str | None = None
        if http_transport is None and tls_fingerprint is not None:
            http_transport = self._pinning_transport(verify_tls)
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers or {},
            verify=verify_tls,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=http_transport,
        )

    def _pinning_transport(self, verify_tls: bool) -> httpx.AsyncBaseTransport:
        """A real httpx transport whose connections are pin-checked at the handshake."""
        transport = httpx.AsyncHTTPTransport(verify=verify_tls)
        transport._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify_tls),
            network_backend=_PinningBackend(httpcore.AnyIOBackend(), self._verify_ssl_object),
        )
        return transport

    def _verify_ssl_object(self, ssl_object: Any) -> None:
        """Record and verify the leaf certificate of a freshly-handshaked connection."""
        der = _der_from_ssl_object(ssl_object)
        if der is None:
            raise TlsPinMismatch("could not read the device certificate to verify the pin")
        self._observed = fingerprint_sha256(der)
        verify_cert_fingerprint(der, self._pin)  # type: ignore[arg-type]

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def observed_fingerprint(self) -> str | None:
        """The peer certificate's observed SHA-256, taken from the request connection."""
        return self._observed

    async def _peer_cert_der(self) -> bytes:
        """Fallback cert source when the response exposes no network stream.

        There is no side-channel probe: if the serving connection's certificate
        cannot be read, pinning cannot be proven, so this refuses (fail closed).
        """
        raise TransportError("could not read the request connection's certificate for pinning")

    async def _verify_pin(self, response: httpx.Response) -> None:
        """Re-verify the pin against the connection that served ``response`` (no latch)."""
        if self._pin is None:
            return
        stream = response.extensions.get("network_stream")
        der = _der_from_ssl_object(stream.get_extra_info("ssl_object")) if stream else None
        if der is None:
            der = await self._peer_cert_der()
        self._observed = fingerprint_sha256(der)
        verify_cert_fingerprint(der, self._pin)

    async def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST ``body`` as JSON; return the decoded JSON object or raise TransportError."""
        log.debug("POST %s %s", mask_tokens(path), body_summary(body))
        try:
            response = await self._client.post(path, json=body)
        except httpx.TimeoutException as exc:
            raise TransportError(f"Device request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Device request failed ({type(exc).__name__})") from None
        await self._verify_pin(response)
        if response.status_code != 200:
            raise TransportError(f"Device returned HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise TransportError("Device response exceeds size limit")
        try:
            payload = response.json()
        except ValueError:
            raise TransportError("Device returned a non-JSON response") from None
        if not isinstance(payload, dict):
            raise TransportError("Device returned JSON that is not an object")
        return payload

    async def get_bytes(self, path: str, *, max_bytes: int) -> bytes:
        """GET ``path`` and return the body, streaming with a hard size cap."""
        log.debug("GET %s", mask_tokens(path))
        try:
            async with self._client.stream("GET", path) as response:
                await self._verify_pin(response)
                if response.status_code != 200:
                    raise TransportError(f"Device returned HTTP {response.status_code}")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise TransportError("Device download exceeds size limit")
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise TransportError(f"Device request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Device request failed ({type(exc).__name__})") from None
        return b"".join(chunks)

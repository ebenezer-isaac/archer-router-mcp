"""Generic JSON-over-HTTPS transport (httpx).

Request and response bodies are never logged. Device packages register the
shape of any session token that appears in URLs with ``register_token_mask``;
matches are masked in every log line, including httpx's own request lines.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

import httpx

from .errors import TransportError

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MASKS: list[tuple[re.Pattern[str], str]] = []
_FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def normalize_fingerprint(value: str) -> str:
    """Normalise a SHA-256 certificate fingerprint to 64 lower-case hex chars.

    Accepts the common operator spellings (colon-separated, spaced, mixed case);
    rejects anything that is not exactly 32 bytes of hex so a truncated or
    mistyped pin can never silently disable pinning.
    """
    if not isinstance(value, str):
        raise ValueError("TLS fingerprint must be a string")
    cleaned = value.replace(":", "").replace(" ", "").strip().lower()
    if not _FINGERPRINT_RE.match(cleaned):
        raise ValueError("TLS fingerprint must be a SHA-256 hex digest (64 hex characters)")
    return cleaned


def fingerprint_sha256(cert_der: bytes) -> str:
    """SHA-256 of a DER-encoded certificate, as 64 lower-case hex characters."""
    return hashlib.sha256(cert_der).hexdigest()


def verify_fingerprint_pin(expected: str, observed: str | None) -> None:
    """Fail closed unless ``observed`` matches the pinned ``expected`` fingerprint.

    A missing observation (``None``) is treated as a mismatch: if a pin is
    configured the connection must be proven, never assumed.
    """
    if observed is None:
        raise TransportError(
            "TLS certificate fingerprint could not be observed; refusing to connect to a "
            "pinned host."
        )
    if normalize_fingerprint(observed) != normalize_fingerprint(expected):
        raise TransportError(
            "TLS certificate fingerprint does not match the pinned value; refusing to connect."
        )


async def observe_peer_fingerprint(  # pragma: no cover - live TLS handshake only
    host: str, port: int, *, timeout: float = 10.0
) -> str:
    """Open a TLS connection and return the peer certificate's SHA-256 fingerprint.

    Verification is disabled for this probe: its only job is to read the cert the
    server actually presents so an operator can pin it (or so a configured pin can
    be checked). Never used to decide trust on its own.
    """
    import asyncio
    import contextlib
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context), timeout)
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True)
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
    if not der:
        raise TransportError("The server presented no TLS certificate")
    return fingerprint_sha256(der)


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


class JsonHttpTransport:
    def __init__(
        self,
        base_url: str,
        *,
        verify_tls: bool,
        timeout_seconds: float,
        headers: dict[str, str] | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers or {},
            verify=verify_tls,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=http_transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST ``body`` as JSON; return the decoded JSON object or raise TransportError."""
        log_path = mask_tokens(path)
        log.debug("POST %s %s", log_path, body_summary(body))
        try:
            response = await self._client.post(path, json=body)
        except httpx.TimeoutException as exc:
            raise TransportError(f"Device request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Device request failed ({type(exc).__name__})") from None
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

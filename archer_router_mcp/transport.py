"""HTTP transport for the Archer AX53 web protocol.

Thin, dumb, and credential-free: it builds the ``/cgi-bin/luci/;stok=<token>...``
URL, posts a pre-built ``application/x-www-form-urlencoded`` body, keeps the
``sysauth`` cookie the router sets, and returns the raw response text. The
envelope (AES/sign vs plain) and any response decryption are the caller's job
(``auth``/``session``). TLS certificate pinning, when configured, is enforced here
before any request leaves the process, so a mismatched certificate never sees a
request body.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

import httpx

from .core import transport as core_transport
from .core.errors import TransportError

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# Mask the session token wherever a URL is logged (httpx's own lines included).
core_transport.register_token_mask(r";stok=[^/\s]+", ";stok=<redacted>")

FingerprintProbe = Callable[[], Awaitable[str | None]]


def build_url(token: str, path: str) -> str:
    """``/cgi-bin/luci/;stok=<token><path>`` — empty token before login."""
    if not path.startswith("/"):
        path = "/" + path
    return f"/cgi-bin/luci/;stok={token}{path}"


class ArcherTransport:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        base_url: str,
        verify_tls: bool,
        timeout_seconds: float,
        tls_fingerprint_sha256: str | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        fingerprint_probe: FingerprintProbe | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout_seconds
        self._pin = tls_fingerprint_sha256
        self._probe = fingerprint_probe
        self._observed_fingerprint: str | None = None
        self._fingerprint_probed = False
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
            },
            verify=verify_tls,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=http_transport,
        )

    @property
    def sysauth(self) -> str | None:
        """The current ``sysauth`` session cookie value, if the router set one."""
        return self._client.cookies.get("sysauth")

    def clear_session_cookie(self) -> None:
        self._client.cookies.clear()

    async def observed_fingerprint(self) -> str | None:
        """The peer certificate SHA-256 fingerprint, probed once and cached.

        Returns ``None`` if it cannot be observed (so an operator can see that),
        but note that :meth:`post` fails closed when a pin is configured.
        """
        if self._fingerprint_probed:
            return self._observed_fingerprint
        self._fingerprint_probed = True
        try:
            if self._probe is not None:
                raw = await self._probe()
            else:  # pragma: no cover - real TLS handshake, only against a device
                raw = await core_transport.observe_peer_fingerprint(
                    self._host, self._port, timeout=self._timeout
                )
            self._observed_fingerprint = core_transport.normalize_fingerprint(raw) if raw else None
        except (TransportError, OSError) as exc:  # pragma: no cover - live-only failure path
            log.warning("could not observe TLS fingerprint: %s", type(exc).__name__)
            self._observed_fingerprint = None
        return self._observed_fingerprint

    async def _enforce_pin(self) -> None:
        if self._pin is None:
            return
        observed = await self.observed_fingerprint()
        core_transport.verify_fingerprint_pin(self._pin, observed)

    async def post(self, *, token: str, path: str, body: str) -> str:
        """POST ``body`` (already a urlencoded string) and return the response text."""
        await self._enforce_pin()
        url = build_url(token, path)
        log.debug("POST %s", core_transport.mask_tokens(url))
        try:
            response = await self._client.post(url, content=body.encode("utf-8"))
        except httpx.TimeoutException as exc:
            raise TransportError(f"Router request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Router request failed ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise TransportError(f"Router returned HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise TransportError("Router response exceeds size limit")
        return response.text

    async def aclose(self) -> None:
        await self._client.aclose()

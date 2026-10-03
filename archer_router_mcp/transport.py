"""HTTP transport for the Archer AX53 web protocol.

Thin, dumb, and credential-free: it builds the ``/cgi-bin/luci/;stok=<token>...``
URL, posts a pre-built ``application/x-www-form-urlencoded`` body, keeps the
``sysauth`` cookie the router sets, and returns the raw response text. The
envelope (AES/sign vs plain) and any response decryption are the caller's job
(``auth``/``session``).

TLS certificate pinning, when configured, is enforced on the connection that
actually carries the request — not a side-channel probe. It adopts the canonical
``core.transport`` pinning backend: a custom httpcore network backend verifies the
leaf certificate's SHA-256 immediately after the TLS handshake (``start_tls``),
before any request bytes are sent, so a mismatched certificate never sees a request
body; there is no "checked once" latch. As defense-in-depth (and to serve
``tls_fingerprint_observed`` when the handshake is mocked in tests) each response is
re-checked against the certificate of the connection that served it, read from
``response.extensions["network_stream"]``. The observed fingerprint is always taken
from that real connection — even when no pin is configured — so ``router_status`` /
``--check-auth`` can report the certificate an operator may then pin.
"""

from __future__ import annotations

import logging

import httpcore
import httpx

from .core import transport as core_transport
from .core.errors import TlsPinMismatch, TransportError

log = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# Mask the session token wherever a URL is logged (httpx's own lines included).
core_transport.register_token_mask(r";stok=[^/\s]+", ";stok=<redacted>")


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
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout_seconds
        self._pin = tls_fingerprint_sha256
        self._observed_fingerprint: str | None = None
        if http_transport is None and tls_fingerprint_sha256 is not None:
            http_transport = self._pinning_transport(verify_tls)
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

    def _pinning_transport(self, verify_tls: bool) -> httpx.AsyncBaseTransport:
        """A real httpx transport whose connections are pin-checked at the handshake."""
        transport = httpx.AsyncHTTPTransport(verify=verify_tls)
        transport._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify_tls),
            network_backend=core_transport._PinningBackend(
                httpcore.AnyIOBackend(), self._verify_ssl_object
            ),
        )
        return transport

    def _verify_ssl_object(self, ssl_object: object) -> None:
        """Record and verify the leaf certificate of a freshly-handshaked connection."""
        der = core_transport._der_from_ssl_object(ssl_object)
        if der is None:
            raise TlsPinMismatch("could not read the device certificate to verify the pin")
        self._observed_fingerprint = core_transport.fingerprint_sha256(der)
        core_transport.verify_cert_fingerprint(der, self._pin)  # type: ignore[arg-type]

    @property
    def sysauth(self) -> str | None:
        """The current ``sysauth`` session cookie value, if the router set one."""
        return self._client.cookies.get("sysauth")

    def clear_session_cookie(self) -> None:
        self._client.cookies.clear()

    @property
    def observed_fingerprint(self) -> str | None:
        """The peer certificate's observed SHA-256, taken from the request connection.

        ``None`` until a request has been served (an operator can see that it could
        not be observed); :meth:`post` fails closed when a pin is configured.
        """
        return self._observed_fingerprint

    def _capture_and_verify(self, response: httpx.Response) -> None:
        """Record the serving connection's fingerprint and (if pinned) verify it.

        The fingerprint is recorded whenever the connection exposes a certificate,
        so ``router_status``/``--check-auth`` can report it even without a pin. When a
        pin is configured the certificate must be readable and must match, or the
        response is refused (fail closed) — never a side-channel, always the
        connection that served this request.
        """
        stream = response.extensions.get("network_stream")
        der = (
            core_transport._der_from_ssl_object(stream.get_extra_info("ssl_object"))
            if stream is not None
            else None
        )
        if der is not None:
            self._observed_fingerprint = core_transport.fingerprint_sha256(der)
        if self._pin is not None:
            if der is None:
                raise TransportError(
                    "could not read the request connection's certificate to verify the TLS pin"
                )
            core_transport.verify_cert_fingerprint(der, self._pin)

    async def post(self, *, token: str, path: str, body: str) -> str:
        """POST ``body`` (already a urlencoded string) and return the response text."""
        url = build_url(token, path)
        log.debug("POST %s", core_transport.mask_tokens(url))
        try:
            response = await self._client.post(url, content=body.encode("utf-8"))
        except httpx.TimeoutException as exc:
            raise TransportError(f"Router request timed out ({type(exc).__name__})") from None
        except httpx.HTTPError as exc:
            raise TransportError(f"Router request failed ({type(exc).__name__})") from None
        self._capture_and_verify(response)
        if response.status_code != 200:
            raise TransportError(f"Router returned HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise TransportError("Router response exceeds size limit")
        return response.text

    async def aclose(self) -> None:
        await self._client.aclose()

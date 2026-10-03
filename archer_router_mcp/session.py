"""Authenticated request session for the Archer AX53.

``RouterSession`` owns the login state and serialises every request through one
per-device lock (required for the rolling request hash and to prevent concurrent
logins). It lazily logs in, builds the per-request envelope, decrypts responses,
and re-authenticates exactly once when the router reports ``timeout`` (an expired
session). It never re-logs-in on a credential failure or a lockout.
"""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any
from urllib.parse import quote

from . import crypto, errors
from .auth import RouterAuthenticator, Session, merge_levels, parse_json, resolve_envelope
from .core.config import DeviceSettings
from .core.errors import TokenExpired
from .core.serial import SerialLock
from .errors import ProtocolError, RouterError, WriteOutcomeUnknown
from .transport import ArcherTransport

log = logging.getLogger(__name__)

LOGOUT_PATH = "admin/system"
LOGOUT_FORM = "logout"


class RouterSession:
    def __init__(
        self,
        settings: DeviceSettings,
        transport: ArcherTransport,
        authenticator: RouterAuthenticator,
        *,
        lock: SerialLock | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._auth = authenticator
        self._lock = lock or SerialLock()
        self._envelope = resolve_envelope(settings)
        self._session: Session | None = None

    @property
    def authenticated(self) -> bool:
        return self._session is not None

    @property
    def mode(self) -> str | None:
        return self._session.mode if self._session else None

    async def login(self, *, explicit: bool = True, force_takeover: bool = False) -> Session:
        """Explicitly (re)authenticate under the serial lock; returns the session."""
        return await self._lock.run(
            lambda: self._authenticate(explicit=explicit, force_takeover=force_takeover)
        )

    async def _authenticate(self, *, explicit: bool, force_takeover: bool = False) -> Session:
        self._session = await self._auth.login(explicit=explicit, force_takeover=force_takeover)
        return self._session

    async def request(
        self,
        path: str,
        form: str,
        operation: str,
        params: dict[str, Any] | None = None,
        *,
        idempotent: bool = True,
    ) -> dict[str, Any]:
        """Serialised authenticated request. Lazily logs in; re-logs-in once on timeout.

        ``idempotent=True`` (reads): on a ``timeout`` the session re-authenticates and
        replays the request a single time. ``idempotent=False`` (writes): a ``timeout``
        means the reply was lost after the write may already have committed — the session
        re-authenticates (so the caller can read back) but **never resends**, raising
        :class:`WriteOutcomeUnknown` instead of double-applying a non-idempotent write.
        """

        async def action() -> dict[str, Any]:
            if self._session is None:
                await self._authenticate(explicit=False)
            try:
                return await self._do_request(path, form, operation, params)
            except TokenExpired:
                # Session expired mid-use: re-login once (counts against the breaker).
                # A second timeout propagates — no third login.
                log.info("router session expired; re-authenticating once")
                await self._authenticate(explicit=False)
                if idempotent:
                    return await self._do_request(path, form, operation, params)
                raise WriteOutcomeUnknown(
                    "The write's reply was lost to a session timeout; it was NOT resent. "
                    "The session re-authenticated; the outcome must be read back."
                ) from None

        return await self._lock.run(action)

    async def _do_request(
        self,
        path: str,
        form: str,
        operation: str,
        params: dict[str, Any] | None,
    ) -> dict[str, Any]:
        session = self._session
        if session is None:  # pragma: no cover - callers always authenticate first
            raise ProtocolError("Internal error: request attempted without a session.")
        body_plain = crypto.build_request_body({"operation": operation, **(params or {})})
        wire = self._build_wire(session, body_plain)
        url_path = f"/{path}?form={form}"
        text = await self._transport.post(token=session.stok, path=url_path, body=wire)
        effective = self._decrypt(parse_json(text), session)
        code = errors.normalize_errorcode(effective)
        if code == errors.TIMEOUT:
            raise TokenExpired("The router reported 'timeout' (the session expired).")
        if code is not None:
            raise RouterError(code, meaning=errors.error_meaning(code))
        merged = merge_levels(effective)
        data = merged.get("data")
        return data if isinstance(data, dict) else effective

    def _build_wire(self, session: Session, body_plain: str) -> str:
        if self._envelope == "https-plain":
            return body_plain
        data_b64 = crypto.aes_encrypt(session.aes, body_plain)
        request_hash = crypto.rolling_hash(data_b64)
        sign = crypto.sign_request(session.aes, request_hash, session.seq, data_b64)
        return f"sign={sign}&data={quote(data_b64, safe='')}"

    def _decrypt(self, payload: dict[str, Any], session: Session) -> dict[str, Any]:
        if self._envelope != "https-plain" and isinstance(payload.get("data"), str):
            try:
                return parse_json(crypto.aes_decrypt(session.aes, payload["data"]))
            except (ValueError, ProtocolError):
                # A response we cannot decrypt is the router's 'timeout' condition.
                raise TokenExpired("The router response could not be decrypted.") from None
        return payload

    async def logout(self) -> None:
        """Log out and drop the session. Best-effort: local state is always cleared."""

        async def action() -> None:
            if self._session is None:
                return
            try:
                await self._do_request(LOGOUT_PATH, LOGOUT_FORM, "logout", None)
            except errors.DeviceError as exc:
                log.warning("logout request failed (%s); clearing local session anyway", exc.kind)
            finally:
                self._session = None
                self._transport.clear_session_cookie()

        await self._lock.run(action)

    async def close(self) -> None:
        await self._transport.aclose()

    async def __aenter__(self) -> RouterSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.logout()

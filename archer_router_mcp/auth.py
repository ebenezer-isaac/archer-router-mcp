"""Authentication for the Archer AX53 (SG-hardened profile).

``RouterAuthenticator`` performs the pre-login reads (``device_config``,
``login?form=keys``, ``login?form=auth``) and a single, explicit login. It never
auto-retries a failed login; the persistent breaker is consulted before any login
request leaves the process. The only time it sends a second login request in one
call is an authorised session takeover (``user conflict`` + env gate + argument).
"""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from . import crypto, errors
from .config import DeviceSettings
from .core.breaker import LoginBreaker
from .core.errors import LoginDisabled
from .core.state import Outcome, Reservation
from .crypto import AesKey
from .errors import (
    AuthFailed,
    LockedOut,
    ProtocolError,
    SessionConflict,
)
from .transport import ArcherTransport

log = logging.getLogger(__name__)

EXPECTED_UI_MARKER = "1.11.0"
# Keys the router uses for the model / UI version across firmware revisions.
_MODEL_KEYS = ("model", "device_model", "hardware_version", "hw_version", "product")
_UI_KEYS = ("sw_ver", "software_version", "version", "fw_version", "firmware_version")


def resolve_envelope(settings: DeviceSettings) -> str:
    """Resolve ``ARCHER_ROUTER_ENVELOPE`` to ``https-plain`` or ``http-encrypted``.

    ``auto`` mirrors the bundle's ``shouldSkipEncrypt()``: plain over HTTPS,
    AES+sign over HTTP. R0 confirms whether the router accepts the HTTPS-plain body.
    """
    mode = settings.envelope
    if mode == "auto":
        is_https = settings.base_url.lower().startswith("https")
        return "https-plain" if crypto.should_skip_encrypt(is_https) else "http-encrypted"
    return mode


def parse_json(text: str) -> dict[str, Any]:
    """Parse a router response body as a JSON object, or raise ``ProtocolError``.

    A login page or any HTML comes back where JSON was expected when the session
    has lapsed; that is a protocol error, never an unhandled exception.
    """
    stripped = text.lstrip()
    if stripped[:1] in ("<", ""):
        raise ProtocolError("The router returned a non-JSON response (an HTML page, likely login).")
    try:
        payload = json.loads(text)
    except ValueError:
        raise ProtocolError("The router returned a body that is not valid JSON.") from None
    if not isinstance(payload, dict):
        raise ProtocolError("The router returned JSON that is not an object.")
    return payload


def merge_levels(payload: dict[str, Any]) -> dict[str, Any]:
    """Flatten ``{..., "data": {...}}`` so fields can be read at either level."""
    data = payload.get("data")
    if isinstance(data, dict):
        return {**payload, **data}
    return payload


def extract_stok(payload: dict[str, Any]) -> str | None:
    merged = merge_levels(payload)
    value = merged.get("stok")
    return value if isinstance(value, str) and value else None


@dataclass(frozen=True)
class DeviceCapabilities:
    certification: list[str]
    flags: dict[str, bool]
    model: str | None
    ui_version: str | None
    mode: str | None


@dataclass(frozen=True)
class Session:
    stok: str = field(repr=False)
    aes: AesKey
    seq: int
    mode: str | None = None


@dataclass(frozen=True)
class _LoginOutcome:
    errorcode: str | None
    token: str | None
    data: dict[str, Any]


class RouterAuthenticator:
    def __init__(
        self,
        settings: DeviceSettings,
        transport: ArcherTransport,
        breaker: LoginBreaker,
        *,
        rng: random.Random | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._breaker = breaker
        self._rng = rng or random.SystemRandom()
        self._envelope = resolve_envelope(settings)

    # -- pre-login reads (credential-free, never gated by the breaker) ---------

    async def read_device_config(self) -> DeviceCapabilities:
        """Read ``device_config?form=config`` and derive the SG feature flags.

        Pre-login and credential-free, so it works even when
        ``ARCHER_ROUTER_LOGIN_DISABLED`` has frozen logins. Warns, never fails, on
        an unexpected UI version so a firmware bump does not take the server down.
        """
        merged = merge_levels(await self._read_prelogin("/device_config?form=config"))
        certification = merged.get("certification")
        if not isinstance(certification, list):
            certification = []
        flags = {flag: crypto.is_support(flag, certification) for flag in crypto.FEATURE_MAP}
        model = _first_str(merged, _MODEL_KEYS)
        ui_version = _first_str(merged, _UI_KEYS)
        if ui_version and EXPECTED_UI_MARKER not in ui_version:
            log.warning(
                "router UI version %r does not match the expected %s profile; "
                "the protocol may have shifted",
                ui_version,
                EXPECTED_UI_MARKER,
            )
        return DeviceCapabilities(
            certification=list(certification),
            flags=flags,
            model=model,
            ui_version=ui_version,
            mode=merged.get("mode"),
        )

    async def fetch_keys(self) -> tuple[str, str, str | None]:
        """``login?form=keys`` -> (modulus hex, exponent hex, mode)."""
        merged = merge_levels(await self._read_prelogin("/login?form=keys"))
        n_hex, e_hex = _require_key_pair(merged, "password")
        mode = merged.get("mode")
        return n_hex, e_hex, mode if isinstance(mode, str) else None

    async def fetch_auth(self) -> tuple[str, str, int]:
        """``login?form=auth`` -> (sig modulus hex, sig exponent hex, seq)."""
        merged = merge_levels(await self._read_prelogin("/login?form=auth"))
        n_hex, e_hex = _require_key_pair(merged, "key")
        seq = merged.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise ProtocolError("The router did not return a usable login sequence number.")
        return n_hex, e_hex, seq

    async def _read_prelogin(self, path: str) -> dict[str, Any]:
        # Whitelisted pre-login forms are always sent plain (never AES/signed).
        text = await self._transport.post(token="", path=path, body="operation=read")
        payload = parse_json(text)
        code = errors.normalize_errorcode(payload)
        if code is not None:
            meaning = errors.error_meaning(code)
            raise ProtocolError(
                f"The router refused a pre-login read ({code})"
                + (f": {meaning}" if meaning else "")
                + "."
            )
        return payload

    # -- login ---------------------------------------------------------------

    async def login(self, *, force_takeover: bool = False, explicit: bool = True) -> Session:
        """Perform exactly ONE login request (plus an optional, authorised takeover).

        ``LOGIN_DISABLED`` is checked before any network I/O (owned by the breaker),
        so a frozen breaker fetches nothing and sends nothing. The persistent breaker
        then reserves one attempt immediately before the login POST — the admit
        decision and the budget increment are one locked write — so a tripped or
        spent breaker refuses here with no login POST. The credential-free
        ``fetch_keys``/``fetch_auth`` reads stay outside the reservation. A failed
        login is never retried. ``user conflict`` becomes :class:`SessionConflict`
        unless ``ARCHER_ROUTER_FORCE_SESSION_TAKEOVER`` is set **and**
        ``force_takeover`` is passed, in which case the login is resent once with
        ``confirm=true`` (logged at WARNING) under the **same** reservation.

        ``explicit`` is accepted for call-site compatibility; the breaker now holds a
        single login budget rather than a separate implicit/explicit policy.
        """
        _ = explicit
        if self._breaker.login_disabled:
            raise LoginDisabled(
                f"Login refused: {self._settings.env_name('LOGIN_DISABLED')}=true. "
                "Authentication is frozen; no login request is sent."
            )
        n_pw, e_pw, mode = await self.fetch_keys()
        n_sig, e_sig, seq = await self.fetch_auth()
        aes = crypto.gen_aes_key(self._rng)
        pw_hash = crypto.password_hash(self._password)
        pw_rsa = crypto.rsa_pkcs1v15_hex(n_pw, e_pw, self._password)

        with self._breaker.reserve_attempt() as res:
            outcome = await self._post_login(aes, pw_hash, pw_rsa, seq, n_sig, e_sig, confirm=False)
            if outcome.errorcode is None and outcome.token:
                res.release(Outcome.SUCCESS)
                return Session(outcome.token, aes, seq, mode)
            if outcome.errorcode == errors.USER_CONFLICT:
                return await self._handle_conflict(
                    res,
                    aes,
                    pw_hash,
                    pw_rsa,
                    seq,
                    n_sig,
                    e_sig,
                    mode,
                    force_takeover=force_takeover,
                )
            self._raise_login_error(res, outcome)

    async def _handle_conflict(
        self,
        res: Reservation,
        aes: AesKey,
        pw_hash: str,
        pw_rsa: str,
        seq: int,
        n_sig: str,
        e_sig: str,
        mode: str | None,
        *,
        force_takeover: bool,
    ) -> Session:
        if not (self._settings.force_session_takeover and force_takeover):
            # Another administrator holds the session; the router answered "user
            # conflict" without evaluating the password, so this is not a credential
            # failure and must not spend the login budget (ABORT, not FAILURE).
            res.release(Outcome.ABORT)
            raise SessionConflict(
                "Another administrator is logged in. Set "
                f"{self._settings.env_name('FORCE_SESSION_TAKEOVER')}=true and request takeover "
                "to evict that session."
            )
        log.warning(
            "Session conflict: resending login with confirm=true to evict the other admin "
            "session (%s is enabled).",
            self._settings.env_name("FORCE_SESSION_TAKEOVER"),
        )
        outcome = await self._post_login(aes, pw_hash, pw_rsa, seq, n_sig, e_sig, confirm=True)
        if outcome.errorcode is None and outcome.token:
            res.release(Outcome.SUCCESS)
            return Session(outcome.token, aes, seq, mode)
        if outcome.errorcode == errors.USER_CONFLICT:
            res.release(Outcome.ABORT)
            raise SessionConflict("Session takeover was refused by the router.")
        self._raise_login_error(res, outcome)

    async def _post_login(
        self,
        aes: AesKey,
        pw_hash: str,
        pw_rsa: str,
        seq: int,
        n_sig: str,
        e_sig: str,
        *,
        confirm: bool,
    ) -> _LoginOutcome:
        body_plain = crypto.build_login_body(pw_rsa, confirm)
        if self._envelope == "https-plain":
            wire = body_plain
        else:
            data_b64 = crypto.aes_encrypt(aes, body_plain)
            sign = crypto.sign_login(aes, pw_hash, seq, data_b64, n_sig, e_sig)
            wire = f"sign={sign}&data={quote(data_b64, safe='')}"
        text = await self._transport.post(token="", path="/login?form=login", body=wire)
        return self._interpret(parse_json(text), aes)

    def _interpret(self, payload: dict[str, Any], aes: AesKey) -> _LoginOutcome:
        effective = payload
        if self._envelope != "https-plain" and isinstance(payload.get("data"), str):
            try:
                effective = parse_json(crypto.aes_decrypt(aes, payload["data"]))
            except (ValueError, ProtocolError):
                effective = payload
        code = errors.normalize_errorcode(effective)
        merged = merge_levels(effective)
        data = merged.get("data") if isinstance(merged.get("data"), dict) else merged
        return _LoginOutcome(errorcode=code, token=extract_stok(effective), data=data)

    def _raise_login_error(self, res: Reservation, outcome: _LoginOutcome) -> None:
        code = outcome.errorcode
        data = outcome.data
        if code == errors.LOGIN_FAILED:
            failure_count = _as_int(data.get("failureCount"))
            attempts_allowed = _as_int(data.get("attemptsAllowed"))
            # The password was evaluated and rejected: spend one failure on the budget.
            res.release(
                Outcome.FAILURE,
                failure={
                    "error": code,
                    "failure_count": failure_count,
                    "attempts_allowed": attempts_allowed,
                },
            )
            raise AuthFailed(
                f"Login failed: {failure_count} failed attempt(s); "
                f"{attempts_allowed} remaining before the account locks.",
                attempts_left=attempts_allowed,
                max_attempts=failure_count + attempts_allowed,
            )
        if code == errors.EXCEEDED_MAX_ATTEMPTS:
            seconds = _as_int(data.get("seconds_left")) or errors.MAX_ATTEMPT_LOCK_SECONDS
            # The device has locked the account: a failure plus a cooldown of the
            # reported lock window, so the breaker also refuses until it elapses.
            res.release(
                Outcome.FAILURE,
                cooldown_s=seconds,
                failure={"error": code, "seconds_left": seconds},
            )
            raise LockedOut(
                "The router has locked the admin account after too many attempts "
                "(about two hours).",
                seconds_left=seconds,
            )
        if code == errors.MULTIPLE_LOGIN:
            # Policy refusal (another session); the credential was not evaluated, so
            # no budget is spent (ABORT).
            res.release(Outcome.ABORT)
            raise LockedOut(
                "The router refused the login under its multiple-login policy.", seconds_left=None
            )
        if code == errors.TIMEOUT:
            # A transport/session timeout, not a credential verdict: no budget spent.
            res.release(Outcome.ABORT)
            raise ProtocolError("The router reported 'timeout' during login.")
        # Any other code is a protocol-level refusal, not a credential verdict: ABORT.
        res.release(Outcome.ABORT)
        meaning = errors.error_meaning(code)
        raise ProtocolError(
            f"The router refused the login ({code or 'unknown error'})"
            + (f": {meaning}" if meaning else "")
            + "."
        )

    @property
    def _password(self) -> str:
        return self._settings.password.get_secret_value()


def _first_str(merged: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = merged.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _require_key_pair(merged: dict[str, Any], key: str) -> tuple[str, str]:
    pair = merged.get(key)
    if (
        not isinstance(pair, list)
        or len(pair) < 2
        or not all(isinstance(item, str) and item for item in pair[:2])
    ):
        raise ProtocolError(f"The router did not return a usable '{key}' RSA key pair.")
    return pair[0], pair[1]


def _as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

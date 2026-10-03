"""Archer-router device settings, layered on the device-agnostic ``core.config``.

``core/config.py`` is copied verbatim across every repo (the identity test enforces
it), so it stays device-agnostic. The router's own settings — the request envelope,
session-takeover switch, presence-history caps, protected-MAC list and reboot
rate-limit interval — live here, outside ``core``, exactly as ``core/README.md``
requires ("device-specific code … belongs outside ``core/``"). ``DeviceSettings``
subclasses the core model to add them; the loaders reuse the core helpers but carry
the router's own ``<PREFIX>*`` suffix map so a typo'd router variable still fails loud.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from typing import Literal

from pydantic import Field, ValidationError, field_validator

from .core.config import (
    GLOBAL_ENV_SUFFIXES as _CORE_GLOBAL_SUFFIXES,
)
from .core.config import (
    DeviceSettings as _CoreDeviceSettings,
)
from .core.config import (
    GlobalSettings as _CoreGlobalSettings,
)
from .core.config import (
    _format_validation_error,
    host_is_set,
    reject_unknown_env,
)
from .core.errors import ConfigError
from .normalize import normalize_mac

__all__ = [
    "DEVICE_ENV_SUFFIXES",
    "GLOBAL_ENV_SUFFIXES",
    "DeviceSettings",
    "GlobalSettings",
    "host_is_set",
    "load_device_settings",
    "load_global_settings",
]

_PREFIX = re.compile(r"^[A-Z][A-Z0-9]*_(?:[A-Z0-9]+_)*$")

# The router's documented ``<PREFIX>*`` variables. The common device settings are
# inherited from the core model; the last six are router-specific.
DEVICE_ENV_SUFFIXES: dict[str, str] = {
    "HOST": "host",
    "PORT": "port",
    "USERNAME": "username",
    "PASSWORD": "password",
    "VERIFY_TLS": "verify_tls",
    "TLS_FINGERPRINT_SHA256": "tls_fingerprint_sha256",
    "TIMEOUT_SECONDS": "timeout_seconds",
    "ALLOW_WRITES": "allow_writes",
    "LOGIN_DISABLED": "login_disabled",
    "MAX_LOGIN_FAILURES": "max_login_failures",
    "DRY_RUN": "dry_run",
    "BACKUP_DIR": "backup_dir",
    "STATE_DIR": "state_dir",
    "FORCE_SESSION_TAKEOVER": "force_session_takeover",
    "ENVELOPE": "envelope",
    "PRESENCE_MAX_MB": "presence_max_mb",
    "PRESENCE_INTERVAL_S": "presence_interval_s",
    "PROTECTED_MACS": "protected_macs",
    "REBOOT_MIN_INTERVAL_S": "reboot_min_interval_s",
}
# The router adds a LOG_LEVEL global on top of the core TRANSPORT/HOST/PORT.
GLOBAL_ENV_SUFFIXES: dict[str, str] = {**_CORE_GLOBAL_SUFFIXES, "LOG_LEVEL": "mcp_log_level"}


class DeviceSettings(_CoreDeviceSettings):
    """Router device settings: the core model plus the router-specific switches."""

    force_session_takeover: bool = False
    envelope: Literal["auto", "https-plain", "http-encrypted"] = "auto"
    # Presence history (R3): JSON-lines log size cap, and the in-server sampler
    # interval. An interval of 0 disables the background sampler.
    presence_max_mb: float = Field(default=20.0, gt=0.0, le=1024.0, allow_inf_nan=False)
    presence_interval_s: float = Field(default=0.0, ge=0.0, le=86400.0, allow_inf_nan=False)
    # Write safety (R4): the server's and owner's own devices. REQUIRED (non-empty)
    # whenever writes are enabled; any block/limit/isolate/reservation-remove that
    # targets one of these MACs is refused. Parsed from a comma/space-separated list.
    protected_macs: tuple[str, ...] = ()
    # Minimum seconds between accepted reboots (persisted under STATE_DIR).
    reboot_min_interval_s: float = Field(default=900.0, ge=0.0, le=86400.0, allow_inf_nan=False)

    @field_validator("tls_fingerprint_sha256", mode="before")
    @classmethod
    def _blank_fingerprint_is_unset(cls, value: object) -> object:
        # An empty/whitespace value means "no pin" (unset), not an invalid pin; the
        # inherited core validator then normalises a real fingerprint. Runs before it.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("protected_macs", mode="before")
    @classmethod
    def _validate_protected_macs(cls, value: object) -> tuple[str, ...]:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            tokens = [tok for tok in re.split(r"[,\s]+", value.strip()) if tok]
        elif isinstance(value, (list, tuple)):
            tokens = [str(tok) for tok in value]
        else:
            raise ValueError("must be a comma- or space-separated list of MAC addresses")
        out: list[str] = []
        for tok in tokens:
            mac = normalize_mac(tok)
            if mac is None:
                raise ValueError("contains an entry that is not a valid MAC address")
            if mac not in out:
                out.append(mac)
        return tuple(out)


class GlobalSettings(_CoreGlobalSettings):
    """Server settings: the core model plus the router's log-level switch."""

    mcp_log_level: str = "INFO"

    @field_validator("mcp_log_level")
    @classmethod
    def _validate_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in logging.getLevelNamesMapping():
            raise ValueError("must be a logging level name such as INFO or DEBUG")
        return level


def load_device_settings(prefix: str, environ: Mapping[str, str] | None = None) -> DeviceSettings:
    """Build router :class:`DeviceSettings` from ``<prefix>*`` variables. Fails fast."""
    source = os.environ if environ is None else environ
    reject_unknown_env(prefix, DEVICE_ENV_SUFFIXES, source)
    raw: dict[str, object] = {
        field: source[prefix + suffix]
        for suffix, field in DEVICE_ENV_SUFFIXES.items()
        if prefix + suffix in source
    }
    field_to_env = {field: prefix + suffix for suffix, field in DEVICE_ENV_SUFFIXES.items()}
    try:
        return DeviceSettings.model_validate({**raw, "env_prefix": prefix})
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc, field_to_env)) from None


def load_global_settings(prefix: str, environ: Mapping[str, str] | None = None) -> GlobalSettings:
    """Build router :class:`GlobalSettings` from ``<prefix>*`` variables. Fails fast."""
    if not _PREFIX.fullmatch(prefix):
        raise ConfigError(f"invalid environment prefix {prefix!r}")
    source = os.environ if environ is None else environ
    reject_unknown_env(prefix, GLOBAL_ENV_SUFFIXES, source)
    raw = {
        field: source[prefix + suffix]
        for suffix, field in GLOBAL_ENV_SUFFIXES.items()
        if prefix + suffix in source
    }
    field_to_env = {field: prefix + suffix for suffix, field in GLOBAL_ENV_SUFFIXES.items()}
    try:
        return GlobalSettings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc, field_to_env)) from None

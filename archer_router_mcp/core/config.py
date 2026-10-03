"""Settings loaded from the environment and validated once at startup.

Device settings are read from ``<prefix><SUFFIX>`` variables (e.g. ``ACME_CAM_HOST``)
and server settings from ``<mcp_prefix><SUFFIX>`` (e.g. ``ACME_MCP_PORT``); the
prefixes are chosen by the device package. Validation errors name the variable
and the rule, never the offending value (it may be a password).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from .errors import ConfigError
from .transport import normalize_fingerprint

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
}
GLOBAL_ENV_SUFFIXES: dict[str, str] = {
    "TRANSPORT": "mcp_transport",
    "HOST": "mcp_host",
    "PORT": "mcp_port",
    "LOG_LEVEL": "mcp_log_level",
}

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NUMERIC_DOTTED = re.compile(r"^[\d.]+$")
_USERNAME = re.compile(r"^[\x21-\x7e]{1,64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_PREFIX = re.compile(r"^[A-Z][A-Z0-9]*_(?:[A-Z0-9]+_)*$")
_HOST_ERROR = "must be a hostname or IP address (no scheme, port or path)"

Port = Annotated[int, Field(ge=1, le=65535)]


def validate_host(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("must be a string")
    host = value.strip()
    if not host:
        raise ValueError("must not be empty")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    if len(host) > 253 or _NUMERIC_DOTTED.fullmatch(host):
        raise ValueError(_HOST_ERROR)
    if not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError(_HOST_ERROR)
    return host


class DeviceSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    env_prefix: str = Field(pattern=_PREFIX.pattern)
    host: str
    port: Port = 443
    username: str = "admin"
    password: SecretStr = Field(min_length=1, max_length=128)
    verify_tls: bool = False
    tls_fingerprint_sha256: str | None = None
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0, allow_inf_nan=False)
    allow_writes: bool = False
    login_disabled: bool = False
    max_login_failures: int = Field(default=1, ge=1, le=5)
    dry_run: bool = False
    backup_dir: str = Field(default="backups", min_length=1, max_length=1024)
    state_dir: str | None = None
    force_session_takeover: bool = False
    envelope: Literal["auto", "https-plain", "http-encrypted"] = "auto"
    # Presence history (R3): JSON-lines log size cap, and the in-server sampler
    # interval. An interval of 0 disables the background sampler.
    presence_max_mb: float = Field(default=20.0, gt=0.0, le=1024.0, allow_inf_nan=False)
    presence_interval_s: float = Field(default=0.0, ge=0.0, le=86400.0, allow_inf_nan=False)

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        return validate_host(value)

    @field_validator("tls_fingerprint_sha256", mode="before")
    @classmethod
    def _validate_fingerprint(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("must be a string")
        if not value.strip():
            return None
        return normalize_fingerprint(value)

    @field_validator("state_dir", mode="before")
    @classmethod
    def _validate_state_dir(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("must be a string")
        text = value.strip()
        if not text:
            return None
        if _CONTROL_CHARS.search(text):
            raise ValueError("must not contain control characters")
        if len(text) > 1024:
            raise ValueError("must be at most 1024 characters")
        return text

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        if not _USERNAME.fullmatch(value):
            raise ValueError("must be 1-64 printable ASCII characters without spaces")
        return value

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: SecretStr) -> SecretStr:
        if _CONTROL_CHARS.search(value.get_secret_value()):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("backup_dir")
    @classmethod
    def _validate_backup_dir(cls, value: str) -> str:
        if _CONTROL_CHARS.search(value):
            raise ValueError("must not contain control characters")
        return value

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}:{self.port}"

    def env_name(self, suffix: str) -> str:
        return f"{self.env_prefix}{suffix}"


class GlobalSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    mcp_transport: Literal["stdio", "streamable-http"] = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: Port = 8765
    mcp_log_level: str = "INFO"

    @field_validator("mcp_host")
    @classmethod
    def _validate_bind(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be an IP address literal such as 127.0.0.1") from exc
        return value

    @field_validator("mcp_log_level")
    @classmethod
    def _validate_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in logging.getLevelNamesMapping():
            raise ValueError("must be a logging level name such as INFO or DEBUG")
        return level

    @property
    def mcp_host_is_loopback(self) -> bool:
        return ipaddress.ip_address(self.mcp_host).is_loopback


def _format_validation_error(exc: ValidationError, field_to_env: Mapping[str, str]) -> str:
    lines = []
    for err in exc.errors(include_input=False, include_url=False):
        field = str(err["loc"][0]) if err["loc"] else "?"
        name = field_to_env.get(field, field)
        msg = str(err["msg"]).removeprefix("Value error, ")
        lines.append(f"{name}: {msg}")
    return "Invalid configuration: " + "; ".join(lines)


def host_is_set(prefix: str, environ: Mapping[str, str] | None = None) -> bool:
    source = os.environ if environ is None else environ
    return bool(source.get(f"{prefix}HOST", "").strip())


def _reject_unknown_keys(
    prefix: str, source: Mapping[str, str], suffixes: Mapping[str, str]
) -> None:
    """Fail loudly on any ``<prefix>*`` variable that is not a recognised setting.

    A silently dropped typo (``..._ALLOW_WRITE`` for ``..._ALLOW_WRITES``) is a
    security hazard: the operator believes a safety switch is set when it is not.
    Only names are listed, never values (they may be secrets).
    """
    known = set(suffixes)
    unknown = sorted(
        name for name in source if name.startswith(prefix) and name[len(prefix) :] not in known
    )
    if unknown:
        raise ConfigError(
            "Unknown environment variable(s): "
            + ", ".join(unknown)
            + ". Check for typos; remove or correct them."
        )


def load_device_settings(prefix: str, environ: Mapping[str, str] | None = None) -> DeviceSettings:
    """Build DeviceSettings from ``<prefix>*`` variables. Fails fast."""
    if not _PREFIX.fullmatch(prefix):
        raise ConfigError(f"invalid environment prefix {prefix!r}")
    source = os.environ if environ is None else environ
    _reject_unknown_keys(prefix, source, DEVICE_ENV_SUFFIXES)
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
    """Build GlobalSettings from ``<prefix>TRANSPORT/HOST/PORT/LOG_LEVEL``. Fails fast."""
    if not _PREFIX.fullmatch(prefix):
        raise ConfigError(f"invalid environment prefix {prefix!r}")
    source = os.environ if environ is None else environ
    _reject_unknown_keys(prefix, source, GLOBAL_ENV_SUFFIXES)
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

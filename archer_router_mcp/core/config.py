"""Settings loaded from the environment and validated once at startup.

Device settings are read from ``<prefix><SUFFIX>`` variables (e.g. ``ACME_CAM_HOST``)
and server settings from ``<mcp_prefix><SUFFIX>`` (e.g. ``ACME_MCP_PORT``); the
prefixes are chosen by the device package. Validation errors name the variable
and the rule, never the offending value (it may be a password).
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

from .errors import ConfigError

DEVICE_ENV_SUFFIXES: dict[str, str] = {
    "HOST": "host",
    "PORT": "port",
    "USERNAME": "username",
    "PASSWORD": "password",
    "VERIFY_TLS": "verify_tls",
    "TIMEOUT_SECONDS": "timeout_seconds",
    "ALLOW_WRITES": "allow_writes",
    "LOGIN_DISABLED": "login_disabled",
    "MAX_LOGIN_FAILURES": "max_login_failures",
    "DRY_RUN": "dry_run",
    "BACKUP_DIR": "backup_dir",
}
GLOBAL_ENV_SUFFIXES: dict[str, str] = {
    "TRANSPORT": "mcp_transport",
    "HOST": "mcp_host",
    "PORT": "mcp_port",
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
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0, allow_inf_nan=False)
    allow_writes: bool = False
    login_disabled: bool = False
    max_login_failures: int = Field(default=1, ge=1, le=5)
    dry_run: bool = False
    backup_dir: str = Field(default="backups", min_length=1, max_length=1024)

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, value: object) -> str:
        return validate_host(value)

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

    @field_validator("mcp_host")
    @classmethod
    def _validate_bind(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be an IP address literal such as 127.0.0.1") from exc
        return value

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


def load_device_settings(prefix: str, environ: Mapping[str, str] | None = None) -> DeviceSettings:
    """Build DeviceSettings from ``<prefix>*`` variables. Fails fast."""
    source = os.environ if environ is None else environ
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
    """Build GlobalSettings from ``<prefix>TRANSPORT/HOST/PORT``. Fails fast."""
    if not _PREFIX.fullmatch(prefix):
        raise ConfigError(f"invalid environment prefix {prefix!r}")
    source = os.environ if environ is None else environ
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

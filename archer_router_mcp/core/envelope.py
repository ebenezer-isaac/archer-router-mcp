"""Uniform ``{success, data, error}`` response envelope for every tool."""

from __future__ import annotations

from typing import Any

from .errors import DeviceError


def ok(data: Any) -> dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def fail(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "success": False,
        "data": None,
        "error": {"code": code, "message": message, "details": dict(details or {})},
    }


def from_error(exc: DeviceError) -> dict[str, Any]:
    return fail(exc.kind, str(exc), exc.details())

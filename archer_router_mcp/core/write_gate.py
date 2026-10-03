"""Two-key write gating: server-side ALLOW_WRITES plus per-call confirm_write."""

from __future__ import annotations

from typing import Any

from .config import DeviceSettings
from .envelope import fail

READ_METHODS = frozenset({"get"})


def check_write_gate(
    settings: DeviceSettings,
    method: str,
    confirm_write: object,
    *,
    read_methods: frozenset[str] = READ_METHODS,
) -> dict[str, Any] | None:
    """Return a refusal envelope if ``method`` may not run, else ``None``.

    ``confirm_write`` must be the boolean ``True``; truthy strings do not count.
    """
    if method in read_methods:
        return None
    if not settings.allow_writes:
        return fail(
            "WRITE_REFUSED",
            f"Method '{method}' modifies the device and writes are disabled. "
            f"Set {settings.env_name('ALLOW_WRITES')}=true on the server to enable them.",
        )
    if confirm_write is not True:
        return fail(
            "WRITE_REFUSED",
            f"Method '{method}' modifies the device. Re-send with confirm_write=true "
            "after confirming the change with the operator.",
        )
    return None

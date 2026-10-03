"""Shared tool wrapper: every tool returns a redacted ``{success, data, error}`` envelope."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .envelope import fail, from_error, ok
from .errors import DeviceError
from .redact import redact

log = logging.getLogger(__name__)


async def run_tool(name: str, action: Callable[[], Awaitable[Any]]) -> dict[str, Any]:
    """Run ``action`` and wrap its result (redacted) or its error in an envelope.

    Device errors map to their ``kind``; ValueError (input validation) to
    INVALID_INPUT; anything else is logged with a traceback and reported as a
    generic INTERNAL_ERROR so internals never reach the client.
    """
    try:
        return ok(redact(await action()))
    except DeviceError as exc:
        log.warning("tool %s failed: %s (%s)", name, exc.kind, exc)
        return from_error(exc)
    except ValueError as exc:
        return fail("INVALID_INPUT", str(exc))
    except Exception:
        log.exception("tool %s raised an unexpected error", name)
        return fail("INTERNAL_ERROR", "Unexpected server error; see server logs.")

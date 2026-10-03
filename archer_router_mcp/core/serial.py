"""Serialisation of guarded operations.

A guarded write is "read live state, check preconditions, write, read again".
Two such operations interleaving could each pass their checks and then clobber
one another, so every guarded write runs under one per-device ``SerialLock``.
The lock is not re-entrant: acquire it at the tool level only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


class SerialLock:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    async def run(self, action: Callable[[], Awaitable[T]]) -> T:
        """Run ``action`` with exclusive access; waits for any operation in flight."""
        async with self._lock:
            return await action()

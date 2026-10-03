"""BREAKER r3 / writes — F6: a token-expiry replay double-applies a non-idempotent insert.

Claim/spec under attack (R4 state machine): "token expiry between re-read and write
→ one re-login then proceed; failure mid-sequence leaves no partial reservation",
and the task axis "token expiry on the replay of a WRITE — replayed exactly once or
twice (double insert)?".

``RouterSession.request`` replays a request **once** after a ``timeout`` re-login.
The replay is unconditional: it does not distinguish "the write never landed" from
"the write landed but the response was lost/undecryptable". If the router applies
the ``insert`` and then the reply decrypts to ``timeout`` (session expired exactly
as it answered), the client re-logs in and re-sends the **same insert** — a second
row. ``insert`` is not idempotent (the fake, like the device, appends a new keyed
row each time), so the reservation table ends with two rows for one MAC.

This test seeds that exact race with a fake whose ``insert`` applies the mutation
and then reports ``timeout`` once. It asserts the claimed invariant (exactly one row
for the MAC after the replay) and FAILS.

Reachability: token expiry mid-batch is a known weekly-ish coincidence (per the
rubric); this sub-case (expiry on the reply *after* the write lands) is rarer, and
its only witness here is this crafted fake — scored conservatively.
"""

from __future__ import annotations

from typing import Any

from archer_router_mcp import server
from tests.fakes import FakeRouter, build_components

DEV = "00:00:5E:00:53:01"


class TimeoutAfterInsertRouter(FakeRouter):
    """Applies the first ``insert`` mutation, then reports ``timeout`` for it once,
    as a router whose session expires exactly as it commits the row would."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(stateful=True, envelope="https-plain", **kw)
        self._timed_out_once = False

    def _apply(
        self, module: str, form: str, operation: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        result = super()._apply(module, form, operation, params)
        if operation == "insert" and not self._timed_out_once:
            self._timed_out_once = True
            # The row is already committed above; the client sees a timeout and replays.
            return {"errorcode": "timeout"}
        return result


async def test_insert_is_not_double_applied_on_timeout_replay(tmp_path) -> None:
    fake = TimeoutAfterInsertRouter()
    c = build_components(
        fake,
        envelope="https-plain",
        state_dir=tmp_path,
        extra_env={
            "ARCHER_ROUTER_PROTECTED_MACS": "00:00:5E:00:53:AA",
            "ARCHER_ROUTER_ALLOW_WRITES": "true",
        },
    )
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        rows = fake._state["dhcps:reservation"]["rows"]
        dev_rows = [r for r in rows if r.get("mac") == "00-00-5E-00-53-01"]
        # Claim/spec: at most one reservation row for the MAC; no partial/duplicate write.
        assert len(dev_rows) == 1, (
            f"token-expiry replay double-applied the insert: {len(dev_rows)} rows for one MAC "
            f"(env success={env['success']})"
        )
    finally:
        await c.aclose()

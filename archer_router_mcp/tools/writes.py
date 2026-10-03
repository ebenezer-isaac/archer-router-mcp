"""Double-gated write tools (R4): DHCP reservations, Wi-Fi radio, reboot.

Access-control, speed-limit, schedule, isolation and WoL writes live in
``writes_access.py``; both modules share ``_write_common.py``. See that module and
the master plan for the gating contract: ``ARCHER_ROUTER_ALLOW_WRITES=true`` **and**
``confirm_write=True`` are both required; ``ARCHER_ROUTER_DRY_RUN=true`` returns the
exact ``{path, form, operation, params, body}`` and sends nothing; a live write
re-reads before and after and logs out at the end of the batch. Writes use the lazy
login with ``force_takeover=False`` and never evict the owner's session.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any

from ..core.errors import InvalidInput
from ..core.redact import is_sensitive_key
from ..core.state import Outcome
from ..errors import PreconditionFailed, WriteOutcomeUnknown
from ..normalize import as_bool, as_int, decode_name, first_present, mac_dashed, normalize_mac
from ._write_common import (
    IP_KEYS,
    MAC_KEYS,
    WIFI_BANDS,
    commit_write,
    find_by_mac,
    guarded,
    obj_of,
    plan,
    rows_of,
    valid_bool,
    valid_ipv4,
    valid_mac,
    valid_name,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..server import Components
    from ..session import RouterSession


def _reservation_view(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "mac": normalize_mac(first_present(r, MAC_KEYS)),
            "ip": first_present(r, IP_KEYS),
            "hostname": decode_name(first_present(r, ("hostname", "name"))),
            "enable": as_bool(r.get("enable")),
        }
        for r in rows
    ]


def _wifi_view(band: str, raw: Any) -> dict[str, Any]:
    fields = obj_of(raw)
    return {
        "band": band,
        "enable": as_bool(fields.get("enable")),
        "ssid": decode_name(fields.get("ssid")),
        "channel": as_int(first_present(fields, ("channel", "current_channel"))),
    }


# ============================================================ DHCP reservations


async def router_add_dhcp_reservation(
    components: Components, mac: str, ip: str, name: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Add a DHCP address reservation (``dhcps?form=reservation`` insert). MUTATES.

    Validates mac/ip/name, then (on a live write) refuses if that MAC is already
    reserved, if the IP is reserved for another device, or if the IP falls outside
    the LAN subnet (``network?form=lan_ipv4``). Double-gated; DRY_RUN shows the exact
    body (``new`` JSON with ``hostname``). Returns before/after reservation lists.
    """

    def prep() -> tuple[str, str, dict[str, Any]]:
        cmac = valid_mac(mac)
        cip = valid_ipv4(ip)
        cname = valid_name(name)
        params = {
            "new": {"hostname": cname, "enable": "on", "ip": cip, "mac": mac_dashed(cmac)},
            "index": 0,
        }
        return cmac, cip, plan("admin/dhcps", "reservation", "insert", params)

    async def dry() -> dict[str, Any]:
        *_rest, request = prep()
        return {"dry_run": request}

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(await session.request("admin/dhcps", "reservation", "load"))

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac, cip, request = prep()
        before = await _load(session)
        _check_reservation_free(before, cmac, cip)
        _check_in_lan_subnet(await session.request("admin/network", "lan_ipv4", "read"), cip)
        after, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: find_by_mac(rows, cmac)[1] is not None,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": _reservation_view(before),
            "after": _reservation_view(after),
            "outcome": outcome,
        }

    return await guarded(components, "router_add_dhcp_reservation", confirm_write, dry, live)


def _check_reservation_free(rows: list[dict[str, Any]], cmac: str, cip: str) -> None:
    for row in rows:
        rmac = normalize_mac(first_present(row, MAC_KEYS))
        rip = first_present(row, IP_KEYS)
        if rmac == cmac:
            raise PreconditionFailed(
                f"A DHCP reservation for {cmac} already exists.",
                reason="duplicate_mac",
                context={"mac": cmac},
            )
        if isinstance(rip, str) and rip.strip() == cip and rmac != cmac:
            raise PreconditionFailed(
                f"IP {cip} is already reserved for another device.",
                reason="ip_conflict",
                context={"ip": cip},
            )


def _check_in_lan_subnet(lan_raw: Any, cip: str) -> None:
    """Refuse a reservation IP that is not provably inside the LAN subnet (RW-F7).

    The subnet check used to fail OPEN when the LAN read lacked a mask. It now fails
    CLOSED: a mask lets us refuse any out-of-subnet IP; without a usable mask we fall
    back to the conventional ``/24`` to catch a clearly wrong network, and otherwise
    refuse ``subnet_unknown`` because membership cannot be confirmed.
    """
    fields = obj_of(lan_raw)
    ipaddr = first_present(fields, ("ipaddr", "lan_ipv4_ipaddr", "ip"))
    mask = first_present(fields, ("mask", "netmask"))
    try:
        target = ipaddress.ip_address(cip)
    except ValueError:  # pragma: no cover - cip is pre-validated by valid_ipv4
        return
    if isinstance(ipaddr, str) and isinstance(mask, str):
        try:
            net = ipaddress.ip_network(f"{ipaddr}/{mask}", strict=False)
        except ValueError:
            net = None
        if net is not None:
            if target not in net:
                raise PreconditionFailed(
                    f"{cip} is outside the LAN subnet {net}.",
                    reason="outside_lan_subnet",
                    context={"ip": cip, "subnet": str(net)},
                )
            return
    # No usable mask: fail closed. A clearly wrong network is reported as such; anything
    # else is refused because the subnet cannot be confirmed.
    if isinstance(ipaddr, str):
        try:
            assumed = ipaddress.ip_network(f"{ipaddr}/24", strict=False)
        except ValueError:
            assumed = None
        if assumed is not None and target not in assumed:
            raise PreconditionFailed(
                f"{cip} is outside the LAN subnet {assumed} (mask unknown; assumed /24).",
                reason="outside_lan_subnet",
                context={"ip": cip, "subnet": str(assumed), "mask": "assumed /24"},
            )
    raise PreconditionFailed(
        f"Refusing {cip}: the LAN subnet mask could not be determined, so the IP cannot be "
        "confirmed inside the LAN.",
        reason="subnet_unknown",
        context={"ip": cip},
    )


async def router_remove_dhcp_reservation(
    components: Components, mac: str, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Remove a DHCP reservation by MAC (``dhcps?form=reservation`` remove). MUTATES.

    Loads the table, finds the row for ``mac``, and removes it by its ``key`` and
    ``index``. Refused with ``PROTECTED_TARGET`` if ``mac`` is protected, and with
    ``PRECONDITION_FAILED`` if no such reservation exists. Double-gated; returns
    before/after lists.
    """

    def prep() -> str:
        return valid_mac(mac)

    async def dry() -> dict[str, Any]:
        cmac = prep()
        return {
            "dry_run": {
                "path": "admin/dhcps",
                "form": "reservation",
                "operation": "remove",
                "params": {"mac": cmac},
                "note": "key and index are resolved from a live reservation load at write time",
            }
        }

    async def _load(session: RouterSession) -> list[dict[str, Any]]:
        return rows_of(await session.request("admin/dhcps", "reservation", "load"))

    async def live(session: RouterSession) -> dict[str, Any]:
        cmac = prep()
        before = await _load(session)
        index, row = find_by_mac(before, cmac)
        if row is None:
            raise PreconditionFailed(
                f"No DHCP reservation found for {cmac}.",
                reason="no_such_mac",
                context={"mac": cmac},
            )
        request = plan(
            "admin/dhcps", "reservation", "remove", {"key": row.get("key"), "index": index}
        )
        after, outcome = await commit_write(
            session,
            request,
            read_back=_load,
            verify=lambda rows: find_by_mac(rows, cmac)[1] is None,
            context={"mac": cmac},
        )
        return {
            "applied": request,
            "before": _reservation_view(before),
            "after": _reservation_view(after),
            "outcome": outcome,
        }

    return await guarded(
        components,
        "router_remove_dhcp_reservation",
        confirm_write,
        dry,
        live,
        protect=(mac, "remove the reservation for"),
    )


# ====================================================================== Wi-Fi


async def router_set_wifi(
    components: Components, band: str, enabled: bool, *, confirm_write: bool = False
) -> dict[str, Any]:
    """Turn a Wi-Fi band's radio on or off (``wireless?form=wireless_<band>``). MUTATES.

    WARNING: the ``write_spf`` body is UNVERIFIED until the R0 live capture records
    it in ``docs/protocol/archer-ax53-verified.md``. Until then a live write is
    refused with ``R0_UNCONFIRMED``; DRY_RUN still shows the planned enable flip so it
    can be reviewed. The live write reads the band, flips ``enable`` on the whole band
    object (secret keys such as ``psk_key`` are preserved on the wire but never
    echoed), and writes it back. Disabling a band also returns a warning because the
    MCP host's own band cannot be determined from the router side. Double-gated.
    """

    def prep() -> str:
        b = str(band).strip().lower()
        if b not in WIFI_BANDS:
            raise InvalidInput("band must be one of: 2g, 5g")
        valid_bool(enabled, "enabled")
        return b

    def warning(b: str) -> str | None:
        if not enabled:
            return (
                f"Disabling the {b} radio: the MCP host's own Wi-Fi band is not "
                "determinable from the router, so confirm you are not on it."
            )
        return None

    async def dry() -> dict[str, Any]:
        b = prep()
        request = plan(
            "admin/wireless", f"wireless_{b}", "write_spf", {"enable": "on" if enabled else "off"}
        )
        request["unverified"] = "write_spf body fields are UNVERIFIED until the R0 live capture"
        out: dict[str, Any] = {"dry_run": request}
        if (warn := warning(b)) is not None:
            out["warning"] = warn
        return out

    async def _read(session: RouterSession) -> dict[str, Any]:
        return obj_of(await session.request("admin/wireless", f"wireless_{prep()}", "read_spf"))

    async def live(session: RouterSession) -> dict[str, Any]:
        # The R0 gate runs in the wrapper (router_set_wifi is INFERRED): this body is
        # only reached once the verified doc confirms the write_spf fields.
        b = prep()
        before = obj_of(await session.request("admin/wireless", f"wireless_{b}", "read_spf"))
        wire = {**before, "enable": "on" if enabled else "off"}
        wire.pop("data", None)
        echo = {k: v for k, v in wire.items() if not is_sensitive_key(k)}
        request = plan("admin/wireless", f"wireless_{b}", "write_spf", echo)
        # The full ``wire`` (secrets preserved) is written; only ``echo`` is reported.
        after, outcome = await commit_write(
            session,
            {
                "path": "admin/wireless",
                "form": f"wireless_{b}",
                "operation": "write_spf",
                "params": wire,
            },
            read_back=_read,
            verify=lambda obj: as_bool(obj.get("enable")) is enabled,
            context={"band": b},
        )
        out = {
            "applied": request,
            "before": _wifi_view(b, before),
            "after": _wifi_view(b, after),
            "outcome": outcome,
        }
        if (warn := warning(b)) is not None:
            out["warning"] = warn
        return out

    return await guarded(components, "router_set_wifi", confirm_write, dry, live)


# ====================================================================== reboot


async def router_reboot(components: Components, *, confirm_write: bool = False) -> dict[str, Any]:
    """Reboot the router (``system?form=reboot``). MUTATES; disruptive.

    Rate-limited to one reboot per ``ARCHER_ROUTER_REBOOT_MIN_INTERVAL_S`` (default
    900s) via a :class:`~archer_router_mcp.ratelimit.RebootLimiter` over the shared
    ``ReservationStore``: the attempt is **reserved under a cross-process lock before
    the reboot is sent** (reserve-before-act), so a call inside the window — or an
    unwritable ``STATE_DIR`` — is refused with ``RATE_LIMITED`` and sends nothing
    (fail closed, never fail open). The reservation is released after the request:
    on success (or a lost reply, where the reboot POST already left the process) the
    cooldown window starts; if the reboot is refused before it is sent (e.g. a login
    failure) the window is not consumed. There is no post-reboot re-read (the device
    is going down). DRY_RUN shows the next allowed time. Double-gated.
    """
    limiter = components.reboot_rate_limiter
    request = plan("admin/system", "reboot", "reboot", {})

    async def dry() -> dict[str, Any]:
        return {"dry_run": request, "rate_limit": limiter.status(components.clock())}

    async def live(session: RouterSession) -> dict[str, Any]:
        # Reserve BEFORE any reboot leaves the process. Raises RateLimited (within the
        # window, an in-flight reboot, or an unwritable store) with nothing sent.
        res = limiter.reserve()
        try:
            # A reboot is one-shot and non-idempotent: never resend it on a lost reply.
            ack = await session.request(
                request["path"],
                request["form"],
                request["operation"],
                request["params"],
                idempotent=False,
            )
        except WriteOutcomeUnknown:
            # The reboot POST left the process (reply lost): consume the window.
            res.release(Outcome.SUCCESS)
            raise
        except BaseException:
            # Refused before the reboot was sent (login/auth/device error): window intact.
            res.release(Outcome.ABORT)
            raise
        res.release(Outcome.SUCCESS)
        return {"applied": request, "ack": ack, "rate_limit": limiter.status(components.clock())}

    return await guarded(components, "router_reboot", confirm_write, dry, live)

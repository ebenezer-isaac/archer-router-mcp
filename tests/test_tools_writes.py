"""R4 write tools: double gating, dry-run exactness, read-modify-write, protected
MACs, preconditions, reboot rate limiting, the force_takeover default and secrets.

All data is anonymised (RFC 5737 ``192.0.2.x`` / RFC 7042 ``00:00:5E:00:53:xx``).
Tests drive the tools through the stateful fake router over the ``https-plain``
envelope (so the fake records each plaintext op and mutates real state) unless a
test needs the AES path for a token-expiry replay.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from archer_router_mcp import server
from archer_router_mcp.core.config import load_device_settings
from archer_router_mcp.core.errors import ConfigError
from archer_router_mcp.core.ratelimit import RateLimiter
from archer_router_mcp.crypto import build_request_body
from archer_router_mcp.errors import R0Unconfirmed
from archer_router_mcp.tools._write_common import require_r0_confirmed, wifi_write_confirmed
from tests.fakes import FakeRouter, build_components

PROTECTED = "00:00:5E:00:53:AA"
DEV = "00:00:5E:00:53:01"
DEV2 = "00:00:5E:00:53:02"


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _components(
    tmp_path: Path,
    *,
    state: dict | None = None,
    allow_writes: bool = True,
    dry_run: bool = False,
    protected: str = PROTECTED,
    envelope: str = "https-plain",
    clock: FakeClock | None = None,
    env_extra: dict | None = None,
    **fake_kw,
):
    fake = FakeRouter(envelope=envelope, stateful=True, state=state, **fake_kw)
    extra: dict[str, str] = {"ARCHER_ROUTER_PROTECTED_MACS": protected}
    extra["ARCHER_ROUTER_ALLOW_WRITES"] = "true" if allow_writes else "false"
    if dry_run:
        extra["ARCHER_ROUTER_DRY_RUN"] = "true"
    if env_extra:
        extra.update(env_extra)
    comps = build_components(
        fake, envelope=envelope, state_dir=tmp_path, extra_env=extra, clock=clock
    )
    return fake, comps


def _rebind(fake, tmp_path):
    """A fresh Components over the same fake + STATE_DIR (a new write batch)."""
    return build_components(
        fake,
        envelope="https-plain",
        state_dir=tmp_path,
        extra_env={"ARCHER_ROUTER_ALLOW_WRITES": "true", "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED},
    )


@pytest.fixture
def r0_confirmed(monkeypatch):
    """Bypass the structural R0 gate so a test can exercise an INFERRED tool's live
    read-modify-write logic. The gate itself (RW-F1) is covered by the breaker suite and
    by ``test_require_r0_confirmed_doc_gate``; here we only want the body logic."""
    from archer_router_mcp.tools import _write_common

    monkeypatch.setattr(_write_common, "require_r0_confirmed", lambda *a, **k: None)


# A uniform way to call every write tool with minimal valid args.
INVOCATIONS = {
    "add": lambda c, cw: server.router_add_dhcp_reservation(
        c, DEV, "192.0.2.50", "Dev", confirm_write=cw
    ),
    "remove": lambda c, cw: server.router_remove_dhcp_reservation(c, DEV, confirm_write=cw),
    "set_wifi": lambda c, cw: server.router_set_wifi(c, "2g", False, confirm_write=cw),
    "reboot": lambda c, cw: server.router_reboot(c, confirm_write=cw),
    "block": lambda c, cw: server.router_block_device(c, DEV, confirm_write=cw),
    "unblock": lambda c, cw: server.router_unblock_device(c, DEV, confirm_write=cw),
    "access_mode": lambda c, cw: server.router_set_access_mode(c, "blacklist", confirm_write=cw),
    "speed": lambda c, cw: server.router_set_client_speed_limit(
        c, DEV, 1000, 500, confirm_write=cw
    ),
    "schedule": lambda c, cw: server.router_set_wifi_schedule(c, [], confirm_write=cw),
    "isolate": lambda c, cw: server.router_isolate_device(c, DEV, True, confirm_write=cw),
    "wol": lambda c, cw: server.router_wol(c, DEV, confirm_write=cw),
}


# ========================================================================= gating


@pytest.mark.parametrize("tool", list(INVOCATIONS))
@pytest.mark.parametrize(
    ("allow_writes", "confirm"),
    [(False, True), (True, False), (False, False)],
    ids=["env-off", "confirm-false", "both-off"],
)
async def test_gating_sends_nothing(tmp_path, tool, allow_writes, confirm) -> None:
    fake, c = _components(tmp_path, allow_writes=allow_writes)
    try:
        env = await INVOCATIONS[tool](c, confirm)
        assert env["success"] is False
        assert env["error"]["code"] == "WRITE_REFUSED"
        # No request of any kind left the client.
        assert fake.login_posts == 0
        assert fake.write_posts == 0
        assert fake.mutations == []
    finally:
        await c.aclose()


# ======================================================================= dry-run


async def test_dry_run_add_body_is_exact(tmp_path) -> None:
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_add_dhcp_reservation(c, DEV, "192.0.2.50", "Dev")
        plan = env["data"]["dry_run"]
        assert plan["path"] == "admin/dhcps"
        assert plan["form"] == "reservation"
        assert plan["operation"] == "insert"
        assert plan["params"]["new"] == {
            "hostname": "Dev",
            "enable": "on",
            "ip": "192.0.2.50",
            "mac": "00-00-5E-00-53-01",
        }
        expected = build_request_body(
            {
                "operation": "insert",
                "new": {
                    "hostname": "Dev",
                    "enable": "on",
                    "ip": "192.0.2.50",
                    "mac": "00-00-5E-00-53-01",
                },
                "index": 0,
            }
        )
        assert plan["body"] == expected
        assert fake.login_posts == 0 and fake.write_posts == 0
    finally:
        await c.aclose()


async def test_dry_run_block_body_exact_and_no_send(tmp_path) -> None:
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_block_device(c, DEV2)
        plan = env["data"]["dry_run"]
        assert plan["operation"] == "insert"
        assert plan["params"]["new"] == {"mac": "00-00-5E-00-53-02"}
        assert fake.write_posts == 0 and fake.login_posts == 0
    finally:
        await c.aclose()


async def test_dry_run_reboot_shows_next_allowed(tmp_path) -> None:
    clock = FakeClock(5000.0)
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False, clock=clock)
    try:
        env = await server.router_reboot(c)
        assert env["data"]["dry_run"]["body"] == "operation=reboot"
        assert env["data"]["rate_limit"]["allowed"] is True
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_dry_run_protected_still_refused(tmp_path) -> None:
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_isolate_device(c, PROTECTED, True)
        assert env["success"] is False
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


# ============================================================ read-modify-write


async def test_add_reservation_live_roundtrip(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["success"] is True
        assert env["data"]["before"] == []
        macs = [r["mac"] for r in env["data"]["after"]]
        assert "00:00:5E:00:53:01" in macs
        assert fake.write_posts == 1
        # logout after the batch
        assert ("system", "logout", "logout") in fake.authed_ops
        assert c.session.authenticated is False
    finally:
        await c.aclose()


async def test_remove_reservation_live_roundtrip(tmp_path) -> None:
    state = {
        "dhcps:reservation": {
            "rows": [
                {
                    "key": "r1",
                    "mac": "00:00:5e:00:53:01",
                    "ip": "192.0.2.21",
                    "hostname": "P",
                    "enable": "on",
                }
            ],
            "max_rules": 32,
            "seq": 1,
        }
    }
    _fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_remove_dhcp_reservation(c, DEV, confirm_write=True)
        assert env["success"] is True
        assert [r["mac"] for r in env["data"]["before"]] == ["00:00:5E:00:53:01"]
        assert env["data"]["after"] == []
    finally:
        await c.aclose()


async def test_block_then_unblock(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_block_device(c, DEV2, confirm_write=True)
        assert env["success"] is True
        assert env["data"]["after"] == ["00:00:5E:00:53:02"]
    finally:
        await c.aclose()
    # a fresh batch sees the persisted state (same fake instance)
    c2 = _rebind(fake, tmp_path)
    try:
        env = await server.router_unblock_device(c2, DEV2, confirm_write=True)
        assert env["success"] is True
        assert env["data"]["after"] == []
    finally:
        await c2.aclose()


async def test_isolate_and_unisolate(tmp_path, r0_confirmed) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_isolate_device(c, DEV2, True, confirm_write=True)
        assert env["data"]["after"] == ["00:00:5E:00:53:02"]
    finally:
        await c.aclose()
    c2 = _rebind(fake, tmp_path)
    try:
        env = await server.router_isolate_device(c2, DEV2, False, confirm_write=True)
        assert env["data"]["after"] == []
    finally:
        await c2.aclose()


async def test_speed_limit_live(tmp_path, r0_confirmed) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_set_client_speed_limit(c, DEV2, 1000, 500, confirm_write=True)
        assert env["success"] is True
        after = {r["mac"]: r for r in env["data"]["after"]}
        assert after["00:00:5E:00:53:02"]["down_kbps"] == 1000
        assert after["00:00:5E:00:53:02"]["up_kbps"] == 500
    finally:
        await c.aclose()


async def test_set_access_mode_live(tmp_path) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_set_access_mode(c, "blacklist", confirm_write=True)
        assert env["success"] is True
        assert env["data"]["after"]["enabled"] is True
        assert env["data"]["after"]["mode"] == "blacklist"
    finally:
        await c.aclose()


async def test_set_wifi_schedule_live(tmp_path, r0_confirmed) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_set_wifi_schedule(
            c, [{"day": "mon", "start": "22:00", "end": "06:00"}], confirm_write=True
        )
        assert env["success"] is True
        assert env["data"]["after"]["enabled"] is True
        assert env["data"]["after"]["rule_count"] == 1
    finally:
        await c.aclose()


async def test_wol_live(tmp_path, r0_confirmed) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_wol(c, DEV2, confirm_write=True)
        assert env["success"] is True
        assert env["data"]["applied"]["operation"] == "wakeup"
        assert fake.wakeups == ["00-00-5E-00-53-02"]
    finally:
        await c.aclose()


# ============================================================= protected targets


@pytest.mark.parametrize(
    "call",
    [
        lambda c: server.router_remove_dhcp_reservation(c, PROTECTED, confirm_write=True),
        lambda c: server.router_block_device(c, PROTECTED, confirm_write=True),
        lambda c: server.router_set_client_speed_limit(c, PROTECTED, 100, 100, confirm_write=True),
        lambda c: server.router_isolate_device(c, PROTECTED, True, confirm_write=True),
    ],
)
async def test_protected_targets_refused(tmp_path, call) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await call(c)
        assert env["success"] is False
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_restorative_writes_refused_for_protected(tmp_path) -> None:
    # RW-F3: every MAC-targeting write refuses a protected MAC from the shared wrapper,
    # including the restorative/benign ops (unblock, un-isolate, WoL). Protected devices
    # are managed by hand.
    fake, c = _components(tmp_path)
    try:
        env = await server.router_unblock_device(c, PROTECTED, confirm_write=True)
        assert env["error"]["code"] == "PROTECTED_TARGET"
        env = await server.router_isolate_device(c, PROTECTED, False, confirm_write=True)
        assert env["error"]["code"] == "PROTECTED_TARGET"
        env = await server.router_wol(c, PROTECTED, confirm_write=True)
        assert env["error"]["code"] == "PROTECTED_TARGET"
        assert fake.write_posts == 0 and fake.wakeups == []
    finally:
        await c.aclose()


# ============================================================ whitelist precondition


async def test_whitelist_refused_when_protected_absent(tmp_path) -> None:
    _fake, c = _components(tmp_path)  # white_list empty by default
    try:
        env = await server.router_set_access_mode(c, "whitelist", confirm_write=True)
        assert env["success"] is False
        assert env["error"]["code"] == "PRECONDITION_FAILED"
        assert env["error"]["details"]["reason"] == "protected_not_whitelisted"
    finally:
        await c.aclose()


async def test_whitelist_allowed_when_protected_present(tmp_path) -> None:
    state = {
        "access_control:white_list": {
            "rows": [{"mac": "00:00:5e:00:53:aa", "key": "w1"}],
            "seq": 1,
        }
    }
    _fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_set_access_mode(c, "whitelist", confirm_write=True)
        assert env["success"] is True
        assert env["data"]["after"]["mode"] == "whitelist"
    finally:
        await c.aclose()


# ============================================= reservation preconditions


async def test_duplicate_mac_refused(tmp_path) -> None:
    state = {
        "dhcps:reservation": {
            "rows": [
                {"key": "r1", "mac": "00:00:5e:00:53:01", "ip": "192.0.2.21", "hostname": "P"}
            ],
            "max_rules": 32,
            "seq": 1,
        }
    }
    fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["error"]["code"] == "PRECONDITION_FAILED"
        assert env["error"]["details"]["reason"] == "duplicate_mac"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_ip_conflict_refused(tmp_path) -> None:
    state = {
        "dhcps:reservation": {
            "rows": [
                {"key": "r1", "mac": "00:00:5e:00:53:09", "ip": "192.0.2.50", "hostname": "Other"}
            ],
            "max_rules": 32,
            "seq": 1,
        }
    }
    fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["error"]["details"]["reason"] == "ip_conflict"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_ip_outside_subnet_refused(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "198.51.100.5", "Dev", confirm_write=True
        )
        assert env["error"]["details"]["reason"] == "outside_lan_subnet"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


class TimeoutBeforeInsertRouter(FakeRouter):
    """Reports ``timeout`` for the first ``insert`` BEFORE applying it, as a router whose
    session expires before the write commits (the reply is lost, nothing landed)."""

    def __init__(self, **kw) -> None:
        super().__init__(stateful=True, envelope="https-plain", **kw)
        self._timed_out_once = False

    def _apply(self, module, form, operation, params):
        if operation == "insert" and not self._timed_out_once:
            self._timed_out_once = True
            return {"errorcode": "timeout"}  # never applied
        return super()._apply(module, form, operation, params)


async def test_lost_reply_without_commit_reports_not_landed(tmp_path) -> None:
    # RW-F6: a write whose reply is lost but which did NOT land is read back and reported
    # not_landed (never resent). success is false so the caller can safely retry.
    fake = TimeoutBeforeInsertRouter()
    c = build_components(
        fake,
        envelope="https-plain",
        state_dir=tmp_path,
        extra_env={"ARCHER_ROUTER_ALLOW_WRITES": "true", "ARCHER_ROUTER_PROTECTED_MACS": PROTECTED},
    )
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["success"] is False
        assert env["error"]["code"] == "WRITE_OUTCOME_UNKNOWN"
        assert env["error"]["details"]["outcome"] == "not_landed"
        assert fake._state["dhcps:reservation"]["rows"] == []  # nothing committed, not resent
    finally:
        await c.aclose()


async def test_reservation_refused_when_subnet_mask_unknown(tmp_path) -> None:
    # RW-F7: with no mask the subnet cannot be confirmed; an in-/24-looking IP is refused
    # subnet_unknown (fail closed) rather than allowed.
    state = {"network:lan_ipv4": {"obj": {"ipaddr": "192.0.2.1"}}}  # no mask
    fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["success"] is False
        assert env["error"]["details"]["reason"] == "subnet_unknown"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_remove_missing_mac_refused(tmp_path) -> None:
    _fake, c = _components(tmp_path)
    try:
        env = await server.router_remove_dhcp_reservation(c, DEV, confirm_write=True)
        assert env["error"]["details"]["reason"] == "no_such_mac"
    finally:
        await c.aclose()


# ============================================================= input validation


@pytest.mark.parametrize("bad_name", ["x" * 33, "ev\x00il", "line\nbreak", ""])
async def test_reservation_name_rejected(tmp_path, bad_name) -> None:
    _fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_add_dhcp_reservation(c, DEV, "192.0.2.50", bad_name)
        assert env["success"] is False
        assert env["error"]["code"] == "INVALID_INPUT"
    finally:
        await c.aclose()


@pytest.mark.parametrize("bad_mac", ["not-a-mac", "00:00:5e:00:53", "zz:zz:zz:zz:zz:zz"])
async def test_bad_mac_rejected(tmp_path, bad_mac) -> None:
    _fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_block_device(c, bad_mac)
        assert env["error"]["code"] == "INVALID_INPUT"
    finally:
        await c.aclose()


async def test_mac_separators_normalised_in_body(tmp_path) -> None:
    _fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        for form in ("00-00-5e-00-53-02", "00005E005302", "00:00:5e:00:53:02"):
            env = await server.router_block_device(c, form)
            assert env["data"]["dry_run"]["params"]["new"]["mac"] == "00-00-5E-00-53-02"
    finally:
        await c.aclose()


async def test_name_injection_is_encoded_not_broken(tmp_path) -> None:
    # & = and friends must be percent-encoded inside new=, never break the body.
    _fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_add_dhcp_reservation(c, DEV, "192.0.2.50", 'a&b=c"d')
        body = env["data"]["dry_run"]["body"]
        # exactly three top-level &-separated fields: operation, new, index
        assert body.count("&") == 2
        assert "operation=insert" in body
        # the raw injection characters do not appear unencoded in the body
        assert "a&b=c" not in body
    finally:
        await c.aclose()


@pytest.mark.parametrize("bad_kbps", [-1, True, 1.5, "100"])
async def test_speed_limit_bad_kbps_rejected(tmp_path, bad_kbps) -> None:
    _fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_set_client_speed_limit(c, DEV2, bad_kbps, 0)
        assert env["error"]["code"] == "INVALID_INPUT"
    finally:
        await c.aclose()


@pytest.mark.parametrize(
    "call",
    [
        lambda c: server.router_set_wifi(c, "6g", False),  # bad band
        lambda c: server.router_set_wifi(c, "2g", "yes"),  # enabled not a bool
        lambda c: server.router_isolate_device(c, DEV2, "yes"),  # isolate not a bool
        lambda c: server.router_set_wifi_schedule(c, "notalist"),  # rules not a list
        lambda c: server.router_set_wifi_schedule(c, ["notdict"]),  # rule not an object
        lambda c: server.router_set_access_mode(c, "sideways"),  # bad mode
        lambda c: server.router_add_dhcp_reservation(c, DEV, 12345, "Dev"),  # ip not a str
        lambda c: server.router_add_dhcp_reservation(c, DEV, "999.1.1.1", "Dev"),  # bad ipv4
    ],
)
async def test_invalid_inputs_rejected(tmp_path, call) -> None:
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await call(c)
        assert env["success"] is False
        assert env["error"]["code"] == "INVALID_INPUT"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


def test_wifi_write_confirmed_doc_gate(tmp_path) -> None:
    doc = tmp_path / "verified.md"
    assert wifi_write_confirmed(doc) is False  # missing
    doc.write_text("captured: operation=read only", encoding="utf-8")
    assert wifi_write_confirmed(doc) is False  # present but no write body
    doc.write_text("the write_spf enable body is: enable=off", encoding="utf-8")
    assert wifi_write_confirmed(doc) is True


def test_require_r0_confirmed_doc_gate(tmp_path) -> None:
    doc = tmp_path / "verified.md"
    # Missing doc: every INFERRED tool is refused (fail closed).
    with pytest.raises(R0Unconfirmed):
        require_r0_confirmed("router_set_wifi", doc)
    # A table that confirms only router_wol: it passes, others still refuse.
    doc.write_text(
        "# Verified AX53 write bodies\n\n"
        "| tool | confirmed_on | note |\n"
        "|------|--------------|------|\n"
        "| router_wol | 2026-10-05 | wakeup body captured live |\n",
        encoding="utf-8",
    )
    require_r0_confirmed("router_wol", doc)  # listed -> no raise
    with pytest.raises(R0Unconfirmed):
        require_r0_confirmed("router_set_wifi", doc)  # not listed


async def test_speed_limit_over_max_refused(tmp_path, r0_confirmed) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_set_client_speed_limit(c, DEV2, 9_000_000, 0, confirm_write=True)
        assert env["error"]["details"]["reason"] == "down_over_max"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


# ==================================================================== set_wifi R0


async def test_set_wifi_live_refused_until_r0(tmp_path) -> None:
    fake, c = _components(tmp_path)
    try:
        env = await server.router_set_wifi(c, "2g", False, confirm_write=True)
        assert env["success"] is False
        assert env["error"]["code"] == "R0_UNCONFIRMED"
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_set_wifi_dry_run_shape_only_and_unverified(tmp_path) -> None:
    assert "UNVERIFIED" in server.router_set_wifi.__doc__
    fake, c = _components(tmp_path, dry_run=True, allow_writes=False)
    try:
        env = await server.router_set_wifi(c, "2g", False)
        plan = env["data"]["dry_run"]
        assert plan["operation"] == "write_spf"
        assert plan["params"] == {"enable": "off"}
        assert "unverified" in plan
        assert "warning" in env["data"]  # disabling warns about the host's own band
        assert fake.write_posts == 0
    finally:
        await c.aclose()


async def test_set_wifi_live_preserves_secret_but_never_echoes_it(tmp_path, r0_confirmed) -> None:
    state = {
        "wireless:wireless_2g": {
            "obj": {"enable": "on", "ssid": "Home", "psk_key": "supersecretpass", "channel": "6"}
        }
    }
    fake, c = _components(tmp_path, state=state)
    try:
        env = await server.router_set_wifi(c, "2g", False, confirm_write=True)
        assert env["success"] is True
        assert env["data"]["after"]["enable"] is False
        # the secret is preserved on the wire (not wiped) ...
        assert fake._state["wireless:wireless_2g"]["obj"]["psk_key"] == "supersecretpass"
        # ... but never leaks into the envelope.
        blob = json.dumps(env)
        assert "supersecretpass" not in blob
        assert "psk_key" not in blob
    finally:
        await c.aclose()


# ===================================================================== reboot


async def test_reboot_rate_limited_within_window(tmp_path) -> None:
    clock = FakeClock(1000.0)
    fake, c = _components(tmp_path, clock=clock)
    try:
        first = await server.router_reboot(c, confirm_write=True)
        assert first["success"] is True
        assert fake.reboots == 1
        # a second reboot inside the window sends nothing
        clock.t = 1000.0 + 60.0
        second = await server.router_reboot(c, confirm_write=True)
        assert second["success"] is False
        assert second["error"]["code"] == "RATE_LIMITED"
        assert fake.reboots == 1
        # after the interval it is allowed again
        clock.t = 1000.0 + 901.0
        third = await server.router_reboot(c, confirm_write=True)
        assert third["success"] is True
        assert fake.reboots == 2
    finally:
        await c.aclose()


async def test_reboot_rate_limit_persists_across_instances(tmp_path) -> None:
    clock = FakeClock(2000.0)
    _fake, c = _components(tmp_path, clock=clock)
    try:
        assert (await server.router_reboot(c, confirm_write=True))["success"] is True
    finally:
        await c.aclose()
    # a brand-new Components over the same STATE_DIR still sees the cooldown.
    fake2, c2 = _components(tmp_path, clock=FakeClock(2000.0 + 10.0))
    try:
        env = await server.router_reboot(c2, confirm_write=True)
        assert env["error"]["code"] == "RATE_LIMITED"
        assert fake2.reboots == 0
    finally:
        await c2.aclose()


# ============================================================ force_takeover default


async def test_router_login_does_not_take_over_by_default(tmp_path) -> None:
    # A conflicting admin session must surface, not be evicted, when the env gate
    # is off — proving the tool surface defaults force_takeover to False (RA-obs).
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(fake, state_dir=tmp_path)
    try:
        env = await server.router_login(c)
        assert env["success"] is False
        assert env["error"]["code"] == "SESSION_CONFLICT"
        assert fake.confirm_values == [False]  # never resent with confirm=true
    finally:
        await c.aclose()


async def test_router_login_force_takeover_needs_env_too(tmp_path) -> None:
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(fake, state_dir=tmp_path)  # env gate off
    try:
        env = await server.router_login(c, force_takeover=True)
        assert env["error"]["code"] == "SESSION_CONFLICT"  # double-gated: env still off
    finally:
        await c.aclose()


async def test_router_login_force_takeover_with_env(tmp_path) -> None:
    fake = FakeRouter(conflict_until_confirm=True)
    c = build_components(
        fake, state_dir=tmp_path, extra_env={"ARCHER_ROUTER_FORCE_SESSION_TAKEOVER": "true"}
    )
    try:
        env = await server.router_login(c, force_takeover=True)
        assert env["success"] is True
        assert fake.confirm_values == [False, True]  # one confirm=true re-login
    finally:
        await c.aclose()


# ============================================================ state machine / breaker


async def test_token_expiry_mid_batch_relogs_in_once(tmp_path) -> None:
    fake, c = _components(tmp_path, envelope="http-encrypted", authed_errors=["timeout"])
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["success"] is True
        assert fake.login_posts == 2  # initial + exactly one re-login
        assert [r["mac"] for r in env["data"]["after"]] == ["00:00:5E:00:53:01"]
    finally:
        await c.aclose()


async def test_error_mid_sequence_leaves_no_partial_write(tmp_path) -> None:
    # Error the insert itself (3rd authed op: before-load, lan-read, insert).
    fake, c = _components(tmp_path, authed_errors=[None, None, "operation failed"])
    try:
        env = await server.router_add_dhcp_reservation(
            c, DEV, "192.0.2.50", "Dev", confirm_write=True
        )
        assert env["success"] is False
        assert env["error"]["code"] == "ROUTER_ERROR"
        assert fake._state["dhcps:reservation"]["rows"] == []  # nothing committed
    finally:
        await c.aclose()


async def test_breaker_open_blocks_writes(tmp_path) -> None:
    fake, c = _components(tmp_path, env_extra={"ARCHER_ROUTER_LOGIN_DISABLED": "true"})
    try:
        env = await server.router_block_device(c, DEV2, confirm_write=True)
        assert env["success"] is False
        assert env["error"]["code"] == "LOGIN_REFUSED"
        assert fake.login_posts == 0 and fake.write_posts == 0
    finally:
        await c.aclose()


# ========================================================= RateLimiter (core unit)


def test_ratelimiter_allows_first_then_blocks(tmp_path) -> None:
    limiter = RateLimiter(tmp_path, "rl.json", 900.0)
    assert limiter.status(1000.0)["allowed"] is True
    limiter.record(1000.0)
    status = limiter.status(1100.0)
    assert status["allowed"] is False
    assert status["next_allowed"] == 1900.0
    assert status["retry_after_s"] == 800.0
    assert limiter.status(1900.0)["allowed"] is True


def test_ratelimiter_persists_across_instances(tmp_path) -> None:
    RateLimiter(tmp_path, "rl.json", 900.0).record(5000.0)
    assert RateLimiter(tmp_path, "rl.json", 900.0).status(5100.0)["allowed"] is False


def test_ratelimiter_corrupt_file_is_treated_as_empty(tmp_path) -> None:
    path = tmp_path / "rl.json"
    path.write_text("not json", encoding="utf-8")
    limiter = RateLimiter(tmp_path, "rl.json", 900.0)
    assert limiter.last_time() is None
    assert limiter.status(0.0)["allowed"] is True


# ============================================================ config: protected macs


def test_protected_macs_parsed_and_canonicalised() -> None:
    env = {
        "ARCHER_ROUTER_HOST": "192.0.2.1",
        "ARCHER_ROUTER_PASSWORD": "TestPass123",
        "ARCHER_ROUTER_PROTECTED_MACS": "00:00:5e:00:53:01, 00-00-5E-00-53-02 00005e005303",
    }
    settings = load_device_settings("ARCHER_ROUTER_", env)
    assert settings.protected_macs == (
        "00:00:5E:00:53:01",
        "00:00:5E:00:53:02",
        "00:00:5E:00:53:03",
    )


def test_protected_macs_invalid_entry_rejected() -> None:
    env = {
        "ARCHER_ROUTER_HOST": "192.0.2.1",
        "ARCHER_ROUTER_PASSWORD": "TestPass123",
        "ARCHER_ROUTER_PROTECTED_MACS": "not-a-mac",
    }
    with pytest.raises(ConfigError):
        load_device_settings("ARCHER_ROUTER_", env)


def test_writes_require_protected_macs_at_startup(tmp_path) -> None:
    env = {
        "ARCHER_ROUTER_HOST": "192.0.2.1",
        "ARCHER_ROUTER_PASSWORD": "TestPass123",
        "ARCHER_ROUTER_ALLOW_WRITES": "true",
        "ARCHER_ROUTER_STATE_DIR": str(tmp_path),
    }
    with pytest.raises(ConfigError, match="PROTECTED_MACS"):
        server.Components.from_env(env)

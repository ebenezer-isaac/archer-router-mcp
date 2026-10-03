"""R2 additions to the copied core: persistent breaker, rule-based redaction,
fail-loud config, and TLS fingerprint primitives. Plus the device_config
feature-flag layer reproduced across every certification set in the breaker fixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from archer_router_mcp import crypto
from archer_router_mcp.core import breaker, transport
from archer_router_mcp.core.config import load_device_settings, load_global_settings
from archer_router_mcp.core.errors import ConfigError, LockoutGuard, TransportError
from archer_router_mcp.core.redact import REDACTED, redact
from tests.helpers import DOC_HOST, ROUTER_PREFIX, router_env

# --------------------------------------------------------------- persistent breaker


def _settings(state_dir: Path, **overrides: str):
    return load_device_settings(ROUTER_PREFIX, router_env(STATE_DIR=str(state_dir), **overrides))


def test_breaker_persists_failures_across_instances(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    first = breaker.LoginBreaker(tmp_path, s)
    first.check(explicit=True)  # fresh: allowed
    first.record_failure({"error": "login failed", "failure_count": 1})
    # A brand-new instance reads the same file and now refuses (budget of 1).
    second = breaker.LoginBreaker(tmp_path, s)
    with pytest.raises(LockoutGuard, match="failed login"):
        second.check(explicit=True)
    assert second.snapshot().failed == 1


def test_breaker_clear_reopens(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    b = breaker.LoginBreaker(tmp_path, s)
    b.record_failure({"error": "login failed"})
    b.clear()
    b.check(explicit=True)  # no raise
    assert b.snapshot().failed == 0


def test_breaker_file_is_atomic_and_restrictive(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    b = breaker.LoginBreaker(tmp_path, s)
    b.record_success()
    assert b.path.exists()
    # No leftover temp files from the atomic write.
    assert list(tmp_path.glob(".breaker-*")) == []


@pytest.mark.parametrize("content", ["{ not json", "[]", '{"failed": -1}', '{"failed": "x"}', ""])
def test_corrupt_breaker_file_fails_closed(tmp_path: Path, content: str) -> None:
    s = _settings(tmp_path)
    (tmp_path / breaker.STATE_FILENAME).write_text(content, encoding="utf-8")
    b = breaker.LoginBreaker(tmp_path, s)
    assert b.snapshot().corrupt is True
    with pytest.raises(LockoutGuard, match="unreadable"):
        b.check(explicit=True)
    assert b.show()["state"] == "corrupt"


def test_missing_breaker_file_is_allowing(tmp_path: Path) -> None:
    assert breaker.load_ledger(tmp_path / "nope.json").corrupt is False
    s = _settings(tmp_path)
    breaker.LoginBreaker(tmp_path, s).check(explicit=True)  # no raise


def test_breaker_show_is_json_safe(tmp_path: Path) -> None:
    s = _settings(tmp_path)
    b = breaker.LoginBreaker(tmp_path, s)
    b.record_failure({"error": "login failed", "failure_count": 2})
    json.dumps(b.show())  # must not raise
    assert b.show()["failed"] == 1


# ------------------------------------------------------------------- rule redaction


@pytest.mark.parametrize(
    "key",
    [
        "ciphertext",
        "stok",
        "token",
        "nonce",
        "cookie",
        "secret",
        "authorization",
        "pubkey",
        "key",
        "sysauth",
        "psk_key",  # endswith _key
        "access_token",  # contains token
        "my_password",  # contains pass
        "user_pwd",  # contains pwd
        "client_secret",  # contains secret
        "aes_cipher",  # contains cipher
    ],
)
def test_sensitive_keys_redacted(key: str) -> None:
    assert redact({key: "v"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "key", ["auth_result", "online", "uuid", "device_uuid", "keyring_name", "monkey", "username"]
)
def test_safe_keys_survive(key: str) -> None:
    assert redact({key: "v"}) == {key: "v"}


# ------------------------------------------------------------------- fail-loud config


def test_unknown_device_env_key_fails_loudly() -> None:
    env = router_env()
    env["ARCHER_ROUTER_ALLOW_WRITE"] = "true"  # typo: missing trailing S
    with pytest.raises(ConfigError, match="ARCHER_ROUTER_ALLOW_WRITE"):
        load_device_settings(ROUTER_PREFIX, env)


def test_unknown_global_env_key_fails_loudly() -> None:
    with pytest.raises(ConfigError, match="ARCHER_MCP_BOGUS"):
        load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_BOGUS": "1"})


def test_known_r2_keys_are_accepted() -> None:
    s = load_device_settings(
        ROUTER_PREFIX,
        router_env(
            STATE_DIR="/tmp/state",
            FORCE_SESSION_TAKEOVER="true",
            ENVELOPE="https-plain",
            TLS_FINGERPRINT_SHA256=":".join(["AB"] * 32),
        ),
    )
    assert s.force_session_takeover is True
    assert s.envelope == "https-plain"
    assert s.state_dir == "/tmp/state"
    assert s.tls_fingerprint_sha256 == "ab" * 32


def test_global_log_level_known_and_validated() -> None:
    assert load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_LOG_LEVEL": "debug"}).mcp_log_level == (
        "DEBUG"
    )
    with pytest.raises(ConfigError, match="ARCHER_MCP_LOG_LEVEL"):
        load_global_settings("ARCHER_MCP_", {"ARCHER_MCP_LOG_LEVEL": "LOUD"})


@pytest.mark.parametrize("bad", ["xyz", "ab", "gg" * 32, "12:34"])
def test_bad_fingerprint_rejected(bad: str) -> None:
    with pytest.raises(ConfigError, match="ARCHER_ROUTER_TLS_FINGERPRINT_SHA256"):
        load_device_settings(ROUTER_PREFIX, router_env(TLS_FINGERPRINT_SHA256=bad))


def test_empty_fingerprint_is_none() -> None:
    assert (
        load_device_settings(
            ROUTER_PREFIX, router_env(TLS_FINGERPRINT_SHA256="")
        ).tls_fingerprint_sha256
        is None
    )


def test_prefix_isolation_still_holds_with_fail_loud() -> None:
    env = {**router_env(), "OTHER_DEV_HOST": DOC_HOST, "OTHER_DEV_PASSWORD": "x"}
    # Loading ARCHER_ROUTER_ must not trip over the unrelated OTHER_DEV_ keys.
    assert load_device_settings(ROUTER_PREFIX, env).host == DOC_HOST


# ----------------------------------------------------------- fingerprint primitives


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AB" * 32, "ab" * 32),
        (":".join(["ab"] * 32), "ab" * 32),
        ("ab " * 31 + "ab", "ab" * 32),
    ],
)
def test_normalize_fingerprint(raw: str, expected: str) -> None:
    assert transport.normalize_fingerprint(raw) == expected


@pytest.mark.parametrize("bad", ["", "zz" * 32, "ab" * 31, "ab" * 33, 123])
def test_normalize_fingerprint_rejects(bad: object) -> None:
    with pytest.raises(ValueError, match="fingerprint"):
        transport.normalize_fingerprint(bad)  # type: ignore[arg-type]


def test_verify_fingerprint_pin() -> None:
    transport.verify_fingerprint_pin("AB" * 32, "ab" * 32)  # match, no raise
    with pytest.raises(TransportError, match="does not match"):
        transport.verify_fingerprint_pin("ab" * 32, "cd" * 32)
    with pytest.raises(TransportError, match="could not be observed"):
        transport.verify_fingerprint_pin("ab" * 32, None)


def test_fingerprint_sha256_known_value() -> None:
    import hashlib

    assert transport.fingerprint_sha256(b"abc") == hashlib.sha256(b"abc").hexdigest()


# -------------------------------------------- feature flags across all certification sets

_BREAKER_FIX = json.loads(
    (
        Path(__file__).parent / "breaker" / "r1" / "crypto" / "fixtures" / "breaker_vectors.json"
    ).read_text(encoding="utf-8")
)
# The actual certification arrays the fixture generator fed to each labelled set.
_CERT_SETS = {
    "SG": ["US FCC", "SG CLS L1 STAGE2"],
    "US_only": ["US FCC"],
    "empty": [],
    "RG": ["RG"],
    "CE_RED": ["CE RED"],
}


@pytest.mark.parametrize("label", list(_CERT_SETS))
def test_is_support_reproduces_bundle_for_every_cert_set(label: str) -> None:
    certs = _CERT_SETS[label]
    expected = _BREAKER_FIX["isSupport_by_cert"][label]
    produced = {
        flag: crypto.is_support(flag, certs) for flag in _BREAKER_FIX["feature_map_all_flags"]
    }
    assert produced == expected


def test_should_skip_encrypt_follows_https() -> None:
    assert crypto.should_skip_encrypt(True) is True
    assert crypto.should_skip_encrypt(False) is False

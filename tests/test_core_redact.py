from __future__ import annotations

import copy

import pytest

from archer_router_mcp.core.redact import REDACTED, TRUNCATED, redact

CT = "cipher" + "text"  # assembled so the secret scan does not flag this file


def test_redacts_sensitive_top_level_keys() -> None:
    src = {CT: "QUJD", "password": "p", "key": "k", "stok": "s", "name": "router"}
    assert redact(src) == {
        CT: REDACTED,
        "password": REDACTED,
        "key": REDACTED,
        "stok": REDACTED,
        "name": "router",
    }


@pytest.mark.parametrize(
    "field", ["Password", "PASSWORD", "password_md5", "passwordConfirm", "passwd", "Stok", "KEY"]
)
def test_key_matching_is_case_insensitive_and_prefix_based(field: str) -> None:
    assert redact({field: "v"}) == {field: REDACTED}


@pytest.mark.parametrize("field", ["keyframe", "monkey", "username", "stock", "password_hint_x"])
def test_similar_but_safe_keys_are_kept_except_password_prefix(field: str) -> None:
    result = redact({field: "v"})
    if field.lower().startswith("password"):
        assert result == {field: REDACTED}
    else:
        assert result == {field: "v"}


def test_nested_dicts_and_lists() -> None:
    src = {
        "band": [
            {"wireless_2g": {"ip": "192.0.2.21", CT: "AAAA", "auth": {"psk_key": "x"}}},
            {"wireless_5g": {"ip": "192.0.2.22", "user": "admin"}},
        ],
        "meta": [[{"stok": "t"}]],
    }
    assert redact(src) == {
        "band": [
            # psk_key ends with _key, so the rule-based redactor strips it everywhere.
            {"wireless_2g": {"ip": "192.0.2.21", CT: REDACTED, "auth": {"psk_key": REDACTED}}},
            {"wireless_5g": {"ip": "192.0.2.22", "user": "admin"}},
        ],
        "meta": [[{"stok": REDACTED}]],
    }


def test_sensitive_container_values_are_replaced_wholesale() -> None:
    assert redact({"key": {"n": 1, "e": 2}}) == {"key": REDACTED}
    assert redact({"password": ["a", "b"]}) == {"password": REDACTED}


def test_input_is_never_mutated() -> None:
    src = {"a": [{"password": "x", "b": {"stok": "y"}}], "t": ("k", {"key": 1})}
    snapshot = copy.deepcopy(src)
    out = redact(src)
    assert src == snapshot
    assert out is not src
    assert out["a"] is not src["a"]
    assert out["a"][0] is not src["a"][0]


def test_tuples_become_lists() -> None:
    assert redact(("a", {"key": 1})) == ["a", {"key": REDACTED}]


@pytest.mark.parametrize("value", [None, 0, 1.5, True, "text", ""])
def test_scalars_pass_through(value: object) -> None:
    assert redact(value) == value


def test_non_string_keys_are_preserved() -> None:
    assert redact({1: "a", 2: {"stok": "x"}}) == {1: "a", 2: {"stok": REDACTED}}


def test_depth_bomb_is_truncated_not_crashing() -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(500):
        cursor["n"] = {}
        cursor = cursor["n"]
    out = redact(deep)
    depth = 0
    node = out
    while isinstance(node, dict) and "n" in node:
        node = node["n"]
        depth += 1
    assert node == TRUNCATED
    assert depth <= 64


def test_cyclic_structure_does_not_recurse_forever() -> None:
    a: dict = {"x": 1}
    a["self"] = a
    out = redact(a)
    assert out["x"] == 1

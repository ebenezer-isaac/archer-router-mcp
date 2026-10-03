"""CLI surface: ``--list-tools`` (the gate uses it) and help/arg handling."""

from __future__ import annotations

import pytest

from archer_router_mcp import cli


def test_list_tools_lists_the_router_tools() -> None:
    assert cli.list_tools() == [
        "router_status",
        "router_check_auth",
        "router_login",
        "router_logout",
    ]


def test_list_tools_flag_prints_tools_and_exits_zero(capsys) -> None:
    rc = cli.main(["--list-tools"])
    assert rc == 0
    assert capsys.readouterr().out.split() == cli.list_tools()


def test_no_args_prints_help_to_stderr_and_exits_zero(capsys) -> None:
    rc = cli.main([])
    captured = capsys.readouterr()
    assert rc == 0
    assert "archer-router-mcp" in captured.err
    assert captured.out == ""


def test_unknown_flag_is_rejected() -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["--bogus"])
    assert info.value.code == 2


def test_module_entrypoint_imports() -> None:
    import archer_router_mcp.__main__ as entry

    assert entry.main is cli.main

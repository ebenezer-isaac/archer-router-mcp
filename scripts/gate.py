#!/usr/bin/env python3
"""Release gate. Runs every check, prints one line per check, then PASS or FAIL.

Checks:
  1. ruff check and ruff format --check
  2. pytest with coverage: archer_router_mcp/core >= 90%, whole package >= 80%
  3. scripts/check_no_secrets.py
  4. stub scan under archer_router_mcp/: NotImplementedError, TODO, FIXME, bare ``...`` bodies
  5. ``archer-router-mcp --list-tools`` exits 0 (and, once registered, lists router_status)

Usage: python scripts/gate.py      (exit 0 = PASS, 1 = FAIL)
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "archer_router_mcp"
CORE_MIN = 90.0
PACKAGE_MIN = 80.0
STUB_WORDS = re.compile(r"\b(NotImplementedError|TODO|FIXME)\b")

Check = Callable[[], tuple[bool, str]]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)


def _tail(text: str, lines: int = 15) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def check_ruff() -> tuple[bool, str]:
    lint = _run([sys.executable, "-m", "ruff", "check", "."])
    fmt = _run([sys.executable, "-m", "ruff", "format", "--check", "."])
    ok = lint.returncode == 0 and fmt.returncode == 0
    return ok, "clean" if ok else _tail(lint.stdout + fmt.stdout)


def _coverage_percent(files: dict[str, dict], predicate: Callable[[str], bool]) -> float:
    covered = total = 0
    for name, info in files.items():
        if predicate(name.replace("\\", "/")):
            s = info["summary"]
            covered += s["covered_lines"] + s.get("covered_branches", 0)
            total += s["num_statements"] + s.get("num_branches", 0)
    return 100.0 * covered / total if total else 0.0


def check_tests() -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "coverage.json"
        result = _run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--cov=archer_router_mcp",
                "--cov-branch",
                f"--cov-report=json:{report}",
            ]
        )
        summary = _tail(result.stdout, 1)
        if result.returncode != 0 or not report.exists():
            return False, _tail(result.stdout)
        files = json.loads(report.read_text(encoding="utf-8"))["files"]
    core = _coverage_percent(files, lambda n: "archer_router_mcp/core/" in n)
    package = _coverage_percent(files, lambda n: "archer_router_mcp/" in n)
    ok = core >= CORE_MIN and package >= PACKAGE_MIN
    return ok, (
        f"{summary}; coverage core {core:.1f}% (min {CORE_MIN:.0f}), "
        f"package {package:.1f}% (min {PACKAGE_MIN:.0f})"
    )


def check_secrets() -> tuple[bool, str]:
    result = _run([sys.executable, str(ROOT / "scripts" / "check_no_secrets.py")])
    return result.returncode == 0, _tail(result.stdout + result.stderr)


def _ellipsis_bodies(tree: ast.AST) -> list[int]:
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            first = body[0] if body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                body = body[1:]  # skip docstring
            if (
                len(body) == 1
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and body[0].value.value is Ellipsis
            ):
                hits.append(node.lineno)
    return hits


def scan_stubs(package: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted(package.rglob("*.py")):
        rel = path.relative_to(package.parent).as_posix()
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if STUB_WORDS.search(line):
                problems.append(f"{rel}:{lineno}: {STUB_WORDS.search(line).group(0)}")
        problems.extend(f"{rel}:{n}: bare ... body" for n in _ellipsis_bodies(ast.parse(text)))
    return problems


def check_stubs() -> tuple[bool, str]:
    problems = scan_stubs(PACKAGE)
    return not problems, "none" if not problems else "\n".join(problems)


def check_list_tools() -> tuple[bool, str]:
    exe = shutil.which("archer-router-mcp", path=str(Path(sys.executable).parent))
    args = (
        [exe, "--list-tools"]
        if exe
        else [sys.executable, "-m", "archer_router_mcp", "--list-tools"]
    )
    result = _run(args)
    tools = result.stdout.split()
    # R1 registers no tools yet; later phases must list router_status.
    ok = result.returncode == 0 and ("router_status" in tools or not tools)
    return ok, f"{len(tools)} tools: {' '.join(tools)}" if ok else _tail(result.stderr)


CHECKS: list[tuple[str, Check]] = [
    ("ruff", check_ruff),
    ("pytest+coverage", check_tests),
    ("secret-scan", check_secrets),
    ("stub-scan", check_stubs),
    ("list-tools", check_list_tools),
]


def main() -> int:
    failed = 0
    for name, check in CHECKS:
        ok, detail = check()
        failed += not ok
        print(f"[{'ok' if ok else 'FAIL'}] {name}: {detail}")
    print("PASS" if failed == 0 else f"FAIL ({failed} check(s) failed)")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

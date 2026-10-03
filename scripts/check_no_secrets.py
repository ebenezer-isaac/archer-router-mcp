#!/usr/bin/env python3
"""Fail if anything that looks like a secret or real network data would be committed.

Scans every tracked file plus every untracked-but-not-ignored file (i.e. what
``git add -A`` would pick up). Exit code 0 = clean, 1 = findings, 2 = error.

A single line can be exempted with the marker ``secret-scan: allow`` followed
by a short justification. Use it sparingly and only for documented,
non-secret test vectors.

Usage:
    python scripts/check_no_secrets.py [repo_root]
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARKER = "secret-scan: allow"

# Each rule: (name, compiled regex). Placeholders such as <token>, {token},
# $VAR, and RFC 5737 documentation addresses (192.0.2.x etc.) do not match.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_ipv4",
        re.compile(
            r"(?<![\d.])(?:"
            r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r")(?![\d])"
        ),
    ),
    (
        "mac_address",
        re.compile(
            r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}"
            r"[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"
        ),
    ),
    ("hex32", re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")),
    ("stok", re.compile(r"stok=[A-Za-z0-9]")),
    (
        "ciphertext",
        re.compile(r"(?i)[\"']?ciphertext[\"']?\s*[:=]\s*[\"'](?!<)[^\"']+"),
    ),
    ("password_assign", re.compile(r"(?i)passw(?:or)?d=(?![<${\s\"'`]|$)")),
)

# Paths that must never be committed regardless of content.
FORBIDDEN_PATH_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env_file", re.compile(r"(?:^|/)(?:[^/]*\.env|\.env)$")),
    ("capture_dir", re.compile(r"(?:^|/)captures/")),
    ("backup_dir", re.compile(r"(?:^|/)backups/")),
)
ALLOWED_PATHS = frozenset({".env.example"})

# Files exempt from CONTENT rules. Each entry needs a justification. Keep tiny.
CONTENT_ALLOWLIST = frozenset(
    {
        # Byte-exact AX53 login/request vectors for the dummy password
        # "TestPass123": RSA moduli, AES ciphertexts and HMAC/RSA signatures
        # (hex) plus a throwaway test RSA private key, all generated offline
        # with no device involved. The hex32 rule would otherwise flag these.
        "tests/fixtures/router_auth_vectors.json",
    }
)

SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "captures",
        "backups",
        "htmlcov",
    }
)
MAX_FILE_BYTES = 2_000_000


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str

    def __str__(self) -> str:
        # Never echo the matched value: the report itself must be safe to share.
        return f"{self.path}:{self.line}: possible secret ({self.rule})"


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for name, pattern in RULES:
            if pattern.search(line):
                findings.append(Finding(path=path, line=lineno, rule=name))
    return findings


def scan_file(file_path: Path, display: str) -> list[Finding]:
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return [Finding(path=display, line=0, rule="file_too_large_to_scan")]
        raw = file_path.read_bytes()
    except OSError as exc:
        print(f"error: cannot read {display}: {exc}", file=sys.stderr)
        return [Finding(path=display, line=0, rule="unreadable")]
    if b"\x00" in raw:
        return []  # binary
    return scan_text(raw.decode("utf-8", errors="replace"), display)


def forbidden_path_findings(paths: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in paths:
        normalised = rel.replace("\\", "/")
        if normalised.rsplit("/", 1)[-1] in ALLOWED_PATHS:
            continue
        for name, pattern in FORBIDDEN_PATH_RULES:
            if pattern.search(normalised):
                findings.append(Finding(path=normalised, line=0, rule=name))
    return findings


def _git_candidate_files(root: Path) -> list[str] | None:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return sorted({p for p in result.stdout.decode("utf-8").split("\0") if p})


def _walk_files(root: Path) -> list[str]:
    files: list[str] = []
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_file():
            files.append("/".join(rel_parts))
    return sorted(files)


def scan_repo(root: Path) -> list[Finding]:
    candidates = _git_candidate_files(root)
    if candidates is None:
        candidates = _walk_files(root)
    findings = forbidden_path_findings(candidates)
    for rel in candidates:
        full = root / rel
        if rel in CONTENT_ALLOWLIST:
            continue
        if full.is_file():
            findings.extend(scan_file(full, rel))
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parent.parent
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    findings = scan_repo(root)
    for finding in findings:
        print(finding)
    if findings:
        print(f"\n{len(findings)} possible secret(s) found. Commit blocked.", file=sys.stderr)
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

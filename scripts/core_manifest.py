#!/usr/bin/env python3
"""Compute / regenerate ``<package>/core/VERSION``: the semver + sha256 manifest
of every ``core/`` file and the canonical conformance test.

``core/`` is written once and copied verbatim into all three repos, so a per-repo
drift is a bug. This records the exact bytes. The only documented exception is the
single line in ``core/README.md`` that names the package (it legitimately differs
per repo): the package directory name is normalised to ``<PACKAGE>`` before hashing.

Usage:
  python scripts/core_manifest.py            # regenerate core/VERSION
  python scripts/core_manifest.py --check     # exit 1 if VERSION is stale
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

VERSION = "1.3.0"
ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = ROOT / "archer_router_mcp"
CORE_DIR = PACKAGE_DIR / "core"
CONFORMANCE = ROOT / "tests" / "conformance" / "test_breaker_contract.py"
VERSION_FILE = CORE_DIR / "VERSION"


def _normalise(rel: str, data: bytes, package_name: str) -> bytes:
    """Normalise before hashing so the manifest is stable across repos/platforms.

    CRLF is folded to LF (a Windows-vs-Linux checkout must not change the hash), and
    the one package-name line in ``core/README.md`` is neutralised to ``<PACKAGE>``.
    """
    data = data.replace(b"\r\n", b"\n")
    if rel == "core/README.md":
        return data.decode("utf-8").replace(package_name, "<PACKAGE>").encode("utf-8")
    return data


def _manifest_paths() -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = []
    for path in sorted(CORE_DIR.rglob("*")):
        if not path.is_file() or path.name == "VERSION" or "__pycache__" in path.parts:
            continue
        paths.append((f"core/{path.relative_to(CORE_DIR).as_posix()}", path))
    paths.append(("tests/conformance/test_breaker_contract.py", CONFORMANCE))
    return paths


def compute_manifest(root: Path | None = None) -> dict[str, str]:
    """Return ``{relative_path: sha256}`` for every hashed core/conformance file."""
    package_name = PACKAGE_DIR.name
    manifest: dict[str, str] = {}
    for rel, path in _manifest_paths():
        data = _normalise(rel, path.read_bytes(), package_name)
        manifest[rel] = hashlib.sha256(data).hexdigest()
    return manifest


def read_version(root: Path | None = None) -> dict[str, object]:
    return json.loads(VERSION_FILE.read_text(encoding="utf-8"))


def _document() -> dict[str, object]:
    return {
        "version": VERSION,
        "note": (
            "sha256 of every core/ file and the canonical conformance test; the "
            "package-name line in core/README.md is normalised to <PACKAGE>. "
            "Regenerate with scripts/core_manifest.py."
        ),
        "manifest": compute_manifest(),
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    document = _document()
    if "--check" in args:
        if not VERSION_FILE.exists():
            print("core/VERSION is missing; run scripts/core_manifest.py", file=sys.stderr)
            return 1
        current = json.loads(VERSION_FILE.read_text(encoding="utf-8"))
        if current.get("manifest") != document["manifest"]:
            print("core/VERSION is stale; run scripts/core_manifest.py", file=sys.stderr)
            return 1
        print("core/VERSION is up to date.")
        return 0
    VERSION_FILE.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"wrote {VERSION_FILE} ({len(document['manifest'])} files, v{VERSION})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Contributing

Thanks for your interest. This project is a clean-room MCP server for the TP-Link
Archer AX53; a few rules keep it safe to run against real hardware and clean to
publish.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
python scripts/gate.py
```

The **gate must pass before every commit**. It runs:

1. `ruff check` + `ruff format --check`
2. `pytest` with coverage (`core/` ≥ 90%, whole package ≥ 80%)
3. the secret scanner (`scripts/check_no_secrets.py`)
4. a stub scan (no `NotImplementedError` / `TODO` / `FIXME` / bare `...` bodies)
5. `archer-router-mcp --list-tools`

CI runs the same gate on Ubuntu and Windows across Python 3.11–3.13.

## Commits and PRs

- **Conventional commits:** `feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
  `chore:`, `perf:`, `ci:`.
- Keep files roughly 200–400 lines (hard max 800); organise by feature.
- Prefer immutable code (return new objects, don't mutate inputs); handle errors
  explicitly, never swallow them; validate at boundaries.
- A PR should explain what changed and how it was tested, and the gate must be
  green.

## Tests are fault-finding

Tests exist to break the code. For any non-trivial module cover happy path (minimal),
edge cases (primary: boundaries, null/NaN, unicode, encoding), adversarial
(injection in strings, oversized input, a login page returned instead of JSON,
IDOR/auth-bypass shapes), and state-machine cases (expired token mid-batch,
breaker tripped, writes disabled). If a test fails, **fix the code, not the
test**. Don't add happy-path-only tests for new behaviour.

## Secrets and real network data — never commit them

This is a **public** repo with zero secrets and zero real network data. No real
IPs (use RFC 5737 `192.0.2.x`), no real MACs (use the RFC 7042 range
`00:00:5E:00:53:xx`), no hostnames, serials, site/person names, or captured
responses. The secret scanner enforces this and runs in the gate and CI. The one
content-allowlisted file is `tests/fixtures/router_auth_vectors.json` — offline,
throwaway test vectors for the dummy password `TestPass123`.

## Live hardware

Do not add anything that contacts a real device to the test suite — tests run
against fakes only (`tests/fakes.py`). Live verification (an "R0" capture, or the
reservation round-trip) is done deliberately by a maintainer with the router
owner present, one login at a time, and its results are recorded — sanitised — in
`docs/protocol/archer-ax53-verified.md`. See [`deploy/install.md`](deploy/install.md).

## The `core/` directory is canonical elsewhere — do not edit it here

`archer_router_mcp/core/` is a **device-agnostic template that is canonical in a
sibling project (`vigi-nvr-mcp`) and copied verbatim into this repo.** It is
hashed: `archer_router_mcp/core/VERSION` carries a semver plus a SHA-256 manifest
of every file under `core/` (and the conformance suite), and
`tests/test_core_identity.py` fails the gate if any copy drifts.

**Never edit files under `core/` in this repo to fix a bug or add a feature.** A
change made only here will fail the identity test, and will silently diverge the
three copies. Instead:

1. Make the change in the **canonical** `vigi-nvr-mcp/vigi_nvr_mcp/core/`.
2. Bump `core/VERSION` and regenerate its manifest there.
3. Copy the changed files **verbatim** into `archer_router_mcp/core/` (and the
   conformance test into `tests/conformance/`).
4. Run the conformance suite **and** `tests/test_core_identity.py` here.
5. Commit the synced copies together.

Device-specific code (the Archer protocol, error table, tool names, env prefix)
lives **outside** `core/` — in `archer_router_mcp/` proper. That is where fixes
and features belong.

## The `vigi_nvr_mcp/` shim at the repo root

There is a tiny `vigi_nvr_mcp/__init__.py` at the repo root. It is **test-only
infrastructure**, not a dependency and not shipped:

- The breaker **conformance suite** (`tests/conformance/test_breaker_contract.py`)
  is copied verbatim from the canonical repo and hashed by the identity test, so
  its imports must read `vigi_nvr_mcp.core.*` byte-for-byte in every repo.
- The shim aliases that canonical namespace onto **this** repo's
  `archer_router_mcp.core` (reusing the exact module objects), so the verbatim
  suite runs here unchanged — including inside spawned `multiprocessing` workers,
  which is why it sits on the import path at the repo root rather than under
  `tests/`.
- It is **excluded from the published package**: the wheel and sdist contain only
  `archer_router_mcp` (verified — `pyproject.toml` `[tool.hatch.build.targets.wheel]`
  packages just that one). Do not add it to the package build.

Leave it where it is; moving it risks breaking the conformance suite's spawned
workers.

## License

By contributing you agree your contributions are licensed under the MIT License
(see `LICENSE`). Do not add GPL or other copyleft code; the clean-room boundary in
`NOTICE` must hold.

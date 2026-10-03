---
name: Bug report
about: Something doesn't work as documented
title: ""
labels: bug
assignees: ""
---

**Do not include secrets.** No router passwords, session tokens, captured
responses, real MACs, or private IPs. Redact them (use `192.0.2.1` and
`00:00:5E:00:53:01` placeholders). For a security vulnerability, use private
reporting instead — see `SECURITY.md`.

## What happened

A clear description of the bug and what you expected instead.

## Steps to reproduce

1. ...
2. ...

The tool call or CLI command, and the `{success, data, error}` envelope or error
you got back (redacted).

## Environment

- Router model / web UI version (from `router_status`):
- `router_status` `feature_flags` / `certification` (redacted):
- archer-router-mcp version:
- Python version and OS:
- Transport (`ARCHER_MCP_TRANSPORT`) and envelope (`ARCHER_ROUTER_ENVELOPE`):

## Notes

Anything else — logs (redacted), whether writes were enabled, etc.

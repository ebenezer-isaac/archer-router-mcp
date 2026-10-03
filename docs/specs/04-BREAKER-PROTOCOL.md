# 04 — Breaker protocol (imported from `my-dear-bob` `.claude/rules/process.md` §3, D107; owner rulings 2026-09-20 → 2026-10-03)

Builders build. Breakers break. Nobody grades their own work. The orchestrator decides priority; it never writes the adversarial tests itself and never reviews quality itself (mechanical checks — running the gate — are fine).

## 1. Sequence per phase

```
builder agent (phase spec) ─► orchestrator runs scripts/gate.py ─► GREEN? ─► breaker round 1 (several vectors in parallel, fresh agents)
   ─► findings scored on the rubric ─► no Critical, no Major → CONVERGED, merge
                                      ─► any Critical/Major → fixer agent (fresh) builds the fixes → round 2 (fresh breakers)
                                      ─► round 2 clean → merge   |   round 2 not clean → STOP. Root-cause agent (cause + refactor spec), never a third battery.
```

- **The harness runs before the breaker.** A red gate is sent back to a builder; a breaker is never briefed on a red gate.
- **A clean first round has converged.** Never run a confirming round on a clean round.
- **Two rounds without convergence is a design finding.** Launch a root-cause agent briefed with the claim, every round's findings and the code; deliverable = the structural cause (usually one fact kept in more than one place and reconciled by checks) and a refactor spec. Build the refactor as one greenfield pass; at most two rounds on it; if those do not converge, the spec named the wrong cause — report to the owner, do not patch. The token trade is decided in favour of the refactor.
- **Fresh agents, never resumed.** One agent, one job, one report. A breaker's findings go to a new fixer, never back to the builder. Briefs are self-contained: repo path, branch, commit SHA, findings file, exact acceptance. (Owner 2026-10-02: long-running agents degrade.)
- **Model**: every agent runs on the pinned subagent model (`CLAUDE_CODE_SUBAGENT_MODEL` in `.claude/settings.local.json`); every report states the model ID it ran on.

## 2. The breaker brief (template)

> You are a breaker. Your job is to **disprove** this claim, not to review the code: **"<the claim, e.g. `NvrClient` can never issue more than one login attempt per explicit call and never auto-retries a failed login>"**.
> Repo `<path>`, branch `<name>`, commit `<sha>`. Read `docs/specs/00-MASTER-PLAN.md` §1 and the phase spec first.
> Attack axes (cover every one, say which produced nothing): **state machine** (wrong-order calls, duplicate calls, ops after close, expired token mid-batch, breaker tripped mid-batch); **clocks and time** (timeouts, token expiry, breaker cooldown, sleeps in `poe_cycle`); **concurrency and durability** (parallel tool calls on one client, the serial lock, breaker file written by two processes, state dir unwritable); **arithmetic and encoding edges** (URL-encoding double/none, `+ / % =` in passwords, 0/65535/70000 ports, NaN/inf timeouts, unicode and NUL in names, tenths-of-a-watt conversions, channel ids as strings vs ints); **fail-open paths** (`except Exception: pass`, defaults that allow writes, redaction misses a key spelling, dry-run that still sends, write gate bypass via `nvr_raw_call`, `confirm_write` coerced from strings, catalog `mutates` wrong); **the central claim** itself; **secrets** (anything that can print a password, token, ciphertext or the server's RSA key into logs, errors, envelopes or files); **device-destructive outcomes** (a path that could delete a live channel, move onto an occupied slot, cycle a protected port, kick the owner's router session, or spend a login attempt without being asked).
> Deliverable: **failing test code** under `tests/breaker/r<N>/test_<vector>.py` (pytest, runs against mocks only — you have no device access and must not add any), plus `tests/breaker/r<N>/FINDINGS.md` using the rubric in §3 with impact and likelihood **each justified from evidence** (the test, a log, a measurement). Prose without a failing test is not a finding. Do not fix anything. Do not weaken or edit existing tests. Do not touch files outside `tests/breaker/`. Commit on a branch `breaker/r<N>-<vector>` with the trailer line. End with the FINDINGS.md pasted and the model ID you ran on.

Run 3–5 vectors in parallel per round, one agent each, e.g. for the NVR: `auth-lockout`, `wire-redact-secrets`, `write-gate-dryrun-channels`, `config-cli-server`, `catalog-gateway`.

## 3. Rubric — one rubric for every finding (D107)

A breaker **proposes** severity from evidence; it never decides what is fixed. Every finding carries both scores and the evidence for each, or it is scored 1.

**Impact — what one occurrence costs the owner**

| | |
|---|---|
| 4 | He is misled or something is lost: a tool answer he would act on that is wrong; a write that removes or moves a **real** camera channel, kicks his router session, cycles the uplink or the server's port, locks the admin account; a password, token, ciphertext or key written anywhere it should not be |
| 3 | The server stops serving: a tool that hangs or crashes the process, a breaker file that can never clear, a device left unreachable until a human intervenes |
| 2 | A visible failure he can get past: an error envelope where he can see it, and a retry works |
| 1 | Nothing he would ever notice |

**Likelihood — how often it happens, measured**

| | |
|---|---|
| 4 | On the ordinary path: every call, or every day |
| 3 | A path he reaches weekly, or one common coincidence away (token expiry mid-batch, a camera re-leasing an IP, the owner logged into the web UI at the same time) |
| 2 | An uncommon combination that has happened at least once on record |
| 1 | A state nobody has produced outside a test |

No evidence → 1. "Could theoretically" → 1. A finding whose only witness is the breaker's own test is 1 until measured elsewhere. **Exception, stated on the finding every time it is used:** where reaching the state is somebody's *goal* (an injected tool argument from an LLM client, a crafted device response from a compromised LAN host), likelihood is how reachable the state is for someone who wants it.

**Severity = impact × likelihood**

| Score | Band | What happens |
|---|---|---|
| 12–16 | Critical | Nothing else ships until it is fixed |
| 6–9 | Major | Fixed before the phase is ticked |
| 3–4 | Minor | Recorded as a task line; never blocks |
| 1–2 | Won't fix | One line saying why; closed. The one case where the **test** changes, with both scores written beside it |

**Convergence is mechanical:** a round converged iff it produced no Critical and no Major. The owner is told Critical and Major; Minor is a list line.

## 4. Fixer brief (template)

> Fix the Critical and Major findings in `tests/breaker/r<N>/FINDINGS.md` on branch `<name>` at `<sha>`. A failing breaker test is a bug: **fix the code, never weaken or delete the test**; the only exception is a finding the orchestrator has scored Won't-fix, listed here: `<list or "none">`. Keep the phase spec's constraints (no stubs, file sizes, immutability, gate). Merge the breaker branches' test files into `tests/breaker/` so they run in CI. Run `scripts/gate.py` (now including the breaker tests) → PASS before committing. Report: per finding, the root cause in one sentence, the fix, and the test that now passes; the gate tail; the model ID.

## 5. FINDINGS.md format

```
# Breaker round <N> — vector <name> — <repo> @ <sha>
Model: <id>
Claim attacked: <…>
Axes with no finding: <list>

## F1 <short title>  — Impact <n> (<evidence>) × Likelihood <n> (<evidence; adversary-reading? yes/no>) = <score> <Band>
Test: tests/breaker/r<N>/test_<vector>.py::<name>
What happens: <one paragraph, concrete inputs → wrong outcome>
Why (root cause hypothesis): <one sentence; do not fix>
```

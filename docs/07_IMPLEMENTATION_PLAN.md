# Implementation plan

Status at document creation: specifications only; every milestone NOT STARTED. Update status only after verifiable work.

## M1: contracts and ingestion — LOCAL COMPLETE; CI VERIFIED (commit 511daf8)
Implement packaging, typed models, CSV parsers, strict validation, duplicate semantics and fixtures. Tests cover valid and malformed inputs. Exit: exact diagnostics and reconciliation counts; no policy code necessary yet.

## M2: policy and evidence — LOCAL COMPLETE; CI PENDING
Implement validated JSON policy, explicit as-of/freshness, first-match evaluator and deterministic ordering. Exit: all policy unit cases and reviewed synthetic expected outputs pass. Explain policy tradeoffs in plain language.

Local: 135/135 tests pass; ruff check clean; ruff format clean.
Files: src/triageledger/policy.py, src/triageledger/models.py (PolicyConfig/EvidenceSummary/Decision),
  policies/demo-policy-v1.json, tests/unit/test_policy.py, tests/integration/test_evaluate.py.
CI status: pending remote run on pushed commit.

## M3: outputs and replay — LOCAL COMPLETE; CI PENDING
Implement CLI orchestration, JSON/CSV/Markdown rendering, manifest hashes, injection mitigations, atomic publication and exits. Exit: clean-checkout demo, output failure tests, byte-level replay and readable briefing.

Local: 230/230 tests pass; ruff check clean; ruff format clean.
Files: src/triageledger/cli.py, src/triageledger/reporting.py,
  tests/unit/test_reporting.py, tests/integration/test_cli.py, .gitignore.
Demo command exits 3 (13/16 decisions flagged); all six artifacts produced.
Limitations: rename-based publication is not crash-safe or concurrency-safe;
  --overwrite deferred to v2 (fresh output directory always required).
CI status: pending remote run on pushed commit.

## M4: proof of work
Create severity-only comparator, three evidence-based decision diffs, README, architecture diagram in text, limitations and CI. Measure performance if time permits; never insert placeholder metrics as real results. Exit: user can present a 3-minute demo and defend the rules without Claude.

## M5: reviewer-driven refinement
Collect actual feedback when available; log feedback, make bounded changes and retain regression tests. Optional workflow persistence for analyst decisions requires separate schema/ADR; do not fake implemented overrides in CLI v1.

## M6: optional SaaS pilot
Requires explicit user go-ahead and docs/06 security plan. Build thin API, PostgreSQL persistence, identity, tenant isolation, roles and audit. Retain shared evaluator. Exit: complete security gates and limited pilot definition; still not certified enterprise readiness.

## Scope discipline
Do not parallel-build a dashboard, agent, model and cloud platform. If demo time is short, cut optional integrations before validation, explanations or tests. Every change identifies the analyst problem it solves and its verification method.

## Suggested local checks after implementation
python -m pytest
python -m ruff check .
python -m ruff format --check .

These commands are planned checks, not claims of current executability. Package metadata and development setup instructions must make them work from a clean environment.

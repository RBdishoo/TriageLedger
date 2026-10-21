# TriageLedger

A local CLI prototype for explainable vulnerability triage. Given scanner findings, an asset
inventory, and dated threat evidence, it produces a priority queue where every recommendation
cites the rule that matched, the evidence consulted, and the data gaps that remain.

**Prototype status.** This is an independent portfolio project using synthetic data. It is not an
IEX product, not deployed, and not a validated enterprise risk model. Policy thresholds are
illustrative, not NIST/CISA mandates or organizational requirements.

---

## Problem

Severity alone misses context. A critical finding on a standard internal host and a high finding
on a public-facing critical service may need to be ordered differently — and the right answer
depends on asset context, threat evidence, and data freshness, not just a CVSS number. This tool
applies a versioned, inspectable policy and records what it knew, what was missing, and why.

---

## Quickstart

**Requirements:** Python 3.12 or later.

```bash
# 1. Clone and install with dev dependencies
git clone https://github.com/RBdishoo/TriageLedger.git
cd TriageLedger
pip install -e ".[dev]"

# 2. Run the demo evaluation
python -m triageledger.cli evaluate \
  --assets samples/assets.csv \
  --findings samples/findings.csv \
  --threat-evidence samples/threat_evidence.csv \
  --policy policies/demo-policy-v1.json \
  --as-of 2026-10-19T00:00:00Z \
  --output-dir artifacts/demo

# Exit 3 means: completed with review flags present (not a failure).
# Six artifacts are written to artifacts/demo/.
```

Committed reference artifacts from this exact command are in `samples/demo/`. Do not generate
directly into `samples/demo/`; use a separate output directory and compare if you want to verify
reproducibility.

---

## Three decision examples

From `samples/demo/decisions.json`, as-of 2026-10-19T00:00:00Z, policy demo-policy-v1 v1.0.0.
See `docs/comparison.md` for full details and the severity-only baseline comparison.

**F-001 (high severity) → P1, rule P-01**
Asset A-001 (critical, exposed). Fresh active exploitation evidence (E-001, observed 2026-10-17).
Rule P-01 matches confirmed applicability with active exploitation and assigns P1 regardless of
severity. In a severity-only queue, F-001 would rank 4th (below three critical-severity findings).
Flag: `conflicting_threat_evidence` — a second record (E-009) reports not_observed for the same
vulnerability; an analyst should review both.

**F-004 (critical severity) → P2, rule P-03**
Asset A-003 (standard, not_exposed). Rules EX-01, P-01, and P-02 do not match; P-03 then triggers
on critical severity and assigns P2. In a severity-only queue, F-004 ranks 2nd. In the
context-aware queue it is position 7, because six P1 findings occupy positions 1–6. The threat
evidence (E-004) is 9 days old, outside the 7-day freshness window; effective exploitation reverts
to unknown. Flags: `historical_active`, `threat_stale`, `threat_unknown`.

**F-011 (unknown severity) → P2, rule P-06**
Asset A-008 (standard, not_exposed). The illustrative unknown-severity rule assigns P2 for
expedited clarification. In a severity-only queue, unknown severity sorts last (position 15). In
the context-aware queue it is position 8. Flag: `severity_unknown`.

A changed queue position is not evidence of a better decision. These examples reflect illustrative
rule assumptions and synthetic data.

---

## Architecture

```
samples/assets.csv          ─┐
samples/findings.csv          ├─▶ ingest.py ─▶ models.py ─▶ policy.py ─▶ reporting.py ─▶ artifacts/
samples/threat_evidence.csv  ─┘                              ▲
policies/demo-policy-v1.json ────────────────────────────────┘
```

| Module | Responsibility |
|---|---|
| `models.py` | Typed dataclasses, enums, field validation primitives |
| `ingest.py` | Bounded file reads, schema checks, normalization, reconciliation, diagnostics |
| `policy.py` | Load validated policy config; first-match rule evaluation; pure function, no I/O |
| `reporting.py` | Deterministic rendering, injection mitigations, SHA-256 manifest |
| `cli.py` | Argument handling, UTC as-of injection, safe staged output publication |

---

## Output artifacts

All artifacts are staged in a temporary sibling directory and published by rename on success. This applies to both the six-artifact successful path and the diagnostics-only fatal path. The rename reduces the chance of partial writes reaching the destination but is not crash-safe or concurrency-safe.

| File | Contents |
|---|---|
| `decisions.json` | Canonical structured decisions with provenance and run identity |
| `queue.csv` | Spreadsheet-friendly queue for all decisions, including excluded (not\_affected) findings |
| `review.csv` | Subset of flagged decisions requiring data or analyst investigation |
| `briefing.md` | Top actions by priority, uncertainty flag counts, stated limitations |
| `diagnostics.json` | Row-level parse errors, duplicate counts, reconciliation summary, policy validation failures |
| `manifest.json` | Schema/policy/tool versions, input hashes, row counts, artifact hashes |

Exit codes: 0 = complete, no flags; 1 = operational failure; 2 = bad inputs or policy;
3 = complete, at least one flag present.

---

## Setup and testing

```bash
# Install dev dependencies (pytest, ruff)
pip install -e ".[dev]"

# Run all tests
python -m pytest

# Lint
python -m ruff check .

# Format check
python -m ruff format --check .
```

Tests cover: policy rule cases for all specified scenarios, ingest validation (invalid enums,
missing headers, duplicate rows, malformed CSV, formula injection, blank IDs), CLI exit codes,
destination collision handling, replay determinism across different PYTHONHASHSEED values, and
manifest hash integrity.

Passing tests demonstrate that the implemented rule cases and parsing boundaries behave as
specified. They do not validate real-world prioritization effectiveness.

---

## Implemented capabilities

- Strict CSV parsing with per-row diagnostics and duplicate normalization
- Versioned policy evaluation (EX-01, P-01 through P-07) with first-match semantics
- Explicit uncertainty flags for stale context, missing assets, unknown severity, conflicting evidence
- Deterministic artifacts: same inputs + policy + as-of + tool version + absolute input paths produce byte-identical output
- CSV formula injection mitigation and Markdown injection escaping
- Atomic staged output; no partial writes reach the destination on failure

## Not implemented in v1

- `--overwrite` flag (fresh output directory required)
- SaaS API, database persistence, multi-user access
- Live scanner integration, automatic patching, LLM-based decisions
- Usability study, performance benchmark, or real-analyst validation

---

## Limitations

- All data (assets, findings, evidence) is synthetic. No real systems are referenced.
- Policy thresholds (7-day evidence freshness, 30-day context freshness) are illustrative.
- The rename-based publication is not crash-safe or concurrency-safe on all platforms.
- Priority is an ordinal recommendation requiring analyst review, not a calibrated risk estimate.
- Unknown values are preserved and flagged, not converted to low risk.

---

## Synthetic data and non-affiliation disclaimer

All asset names, vulnerability identifiers (SYN-*), evidence records, and domain references are
fictional and use reserved example domains. This project is not affiliated with, endorsed by, or
representative of IEX or any other organization. No real infrastructure is assessed or referenced.

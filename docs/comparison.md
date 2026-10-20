# Severity-only vs context-aware comparison

Evaluation timestamp: 2026-10-19T00:00:00Z
Policy: demo-policy-v1 v1.0.0
Findings evaluated: 15 actionable
Excluded: 1 (F-010, disposition not_affected by rule EX-01)

---

## Baseline definition

The severity-only baseline ranks the same 15 actionable findings by:

1. Severity: critical > high > medium > low > unknown
2. Detected-at ascending (earlier detections rank higher within a tier)
3. Asset ID lexicographic ascending
4. Finding ID lexicographic ascending

This baseline does not use asset context (criticality, exposure), threat evidence, or
applicability. It represents a queue an analyst might produce by sorting a scanner export
on the severity column alone.

### Runnable verification snippet

```python
import csv
from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

rows = []
with open("samples/findings.csv") as f:
    for row in csv.DictReader(f):
        if row["finding_id"] == "F-010":  # excluded (not_affected)
            continue
        dt = datetime.fromisoformat(row["detected_at"].replace("Z", "+00:00"))
        rows.append((SEV_ORDER.get(row["severity"], 4), dt, row["asset_id"], row["finding_id"]))

rows.sort()
for i, (_, _, _, fid) in enumerate(rows, 1):
    print(i, fid)
```

Run from the repository root. Expected output matches the baseline positions in the table below.

---

## Context-aware definition

Context-aware positions are taken directly from the evaluator output (decisions.json),
which sorts actionable findings by priority (P1→P4), then detected_at ascending,
then asset_id, then finding_id. The evaluator applies the rule sequence defined in
demo-policy-v1.json: EX-01, P-01, P-02, P-03, P-04, P-05, P-06, P-07.

---

## Full comparison table

Excluded finding (not in either ranking): F-010 (SYN-007, A-007, not_affected, EX-01).

| finding_id | severity | baseline pos | context pos | priority | rule_id | effective_criticality | effective_exposure | effective_exploitation | uncertainty flags |
|---|---|---|---|---|---|---|---|---|---|
| F-002 | critical | 1 | 2 | P1 | P-01 | critical | exposed | active | — |
| F-004 | critical | **2** | **7** | P2 | P-03 | standard | not_exposed | unknown | historical_active, threat_stale, threat_unknown |
| F-014 | critical | 3 | 6 | P1 | P-02 | critical | exposed | unknown | historical_active, threat_stale, threat_unknown |
| F-001 | high | **4** | **1** | P1 | P-01 | critical | exposed | active | conflicting_threat_evidence |
| F-003 | high | 5 | 3 | P1 | P-02 | critical | exposed | not_observed | — |
| F-006 | high | 6 | 4 | P1 | P-01 | critical | exposed | active | conflicting_threat_evidence |
| F-007 | high | 7 | 5 | P1 | P-01 | critical | exposed | active | conflicting_threat_evidence, possible_duplicate |
| F-012 | high | 8 | 11 | P3 | P-05 | unknown | unknown | unknown | context_stale, criticality_unknown, exposure_unknown, historical_active, owner_missing, owner_unverified, threat_stale, threat_unknown |
| F-016 | high | 9 | 13 | P3 | P-05 | unknown | unknown | unknown | asset_unmatched, context_missing, criticality_unknown, exposure_unknown, threat_unknown |
| F-005 | medium | 10 | 9 | P3 | P-05 | unknown | unknown | unknown | applicability_unconfirmed, context_stale, criticality_unknown, exposure_unknown, owner_unverified, threat_stale, threat_unknown |
| F-009 | medium | 11 | 10 | P3 | P-05 | standard | not_exposed | unknown | missing_vulnerability_id, owner_missing, threat_unknown |
| F-015 | medium | 12 | 12 | P3 | P-05 | standard | not_exposed | unknown | applicability_unconfirmed, threat_unknown |
| F-008 | low | 13 | 14 | P4 | P-07 | standard | not_exposed | unknown | owner_missing, threat_unknown |
| F-013 | low | 14 | 15 | P4 | P-07 | standard | not_exposed | unknown | threat_unknown |
| F-011 | unknown | **15** | **8** | P2 | P-06 | standard | not_exposed | not_observed | severity_unknown |

Findings with no position change: F-015 (12→12).
Findings with a position change: 14 of 15.

---

## Three selected examples

These three were chosen because they illustrate distinct policy behaviors and show
the largest absolute position changes.

### Example 1 — F-001: high severity, active confirmed exploitation (baseline 4 → context 1)

| Field | Value |
|---|---|
| Asset | A-001 (Order Router Alpha, critical, exposed, owner: trading-ops) |
| Severity | high |
| Applicability | confirmed |
| Evidence | E-001 (SYN-001, active, observed 2026-10-17 — 2 days, fresh) |
| Conflicting evidence | E-009 (SYN-001, not_observed, observed 2026-10-18 — 1 day, fresh) |
| Effective exploitation | active |
| Rule | P-01: confirmed applicability and active exploitation → P1 |
| Uncertainty flag | conflicting_threat_evidence (E-001 active, E-009 not_observed for the same SYN-001) |

In the severity-only baseline, F-001 ranks 4th — below all three critical-severity findings.
In the context-aware queue, it rises to position 1 because rule P-01 fires on confirmed applicability
and active exploitation regardless of severity. The conflicting_threat_evidence flag marks that
contradicting evidence also exists; an analyst should examine both records.

A changed rank is not automatically an improvement. P-01 reflects an illustrative rule assumption,
not a validated risk model.

---

### Example 2 — F-004: critical severity (baseline 2 → context 7)

| Field | Value |
|---|---|
| Asset | A-003 (Internal Reporting DB, standard, not_exposed, owner: analytics) |
| Severity | critical (synthetic vulnerability SYN-004) |
| Applicability | confirmed |
| Evidence | E-004 (SYN-004, active, observed 2026-10-10 — 9 days, stale beyond 7-day threshold) |
| Effective exploitation | unknown (evidence exists but is stale) |
| Rule | P-03: critical severity → P2 (after EX-01, P-01, P-02 do not match) |
| Uncertainty flags | historical_active, threat_stale, threat_unknown |

Rules EX-01, P-01, and P-02 do not match F-004: the finding is not marked not_affected, there
is no fresh active exploitation, and P-02's conditions are not met. P-03 then triggers on critical
severity and assigns P2. In the severity-only baseline, F-004 is position 2 (second critical
finding by detected_at). In the context-aware queue it is position 7 because six findings receive
P1 under rules P-01 and P-02, and all P1 findings precede all P2 findings in the output ordering.

The stale evidence flags (historical_active, threat_stale) indicate active exploitation was recorded
9 days before as-of but is outside the illustrative 7-day freshness window; the effective exploitation
reverts to unknown. An analyst should verify whether evidence has been updated.

A changed rank is not automatically an improvement.

---

### Example 3 — F-011: unknown severity (baseline 15 → context 8)

| Field | Value |
|---|---|
| Asset | A-008 (Batch Reconciler, standard, not_exposed, owner: operations) |
| Severity | unknown |
| Applicability | confirmed |
| Evidence | E-007 (SYN-008, not_observed, observed 2026-10-18 — 1 day, fresh) |
| Effective exploitation | not_observed |
| Rule | P-06: severity unknown → P2, severity_unknown flag |
| Uncertainty flag | severity_unknown |

The illustrative unknown-severity rule assigns P2 for expedited clarification. In the
severity-only baseline, unknown severity sorts last (position 15). In the context-aware queue,
F-011 is position 8: it follows all six P1 findings and one earlier P2 finding (F-004, detected
earlier).

P-06 does not guarantee the finding is high risk. The rule reflects that if severity is unknown,
the consequence is also unknown. Once severity is confirmed, an analyst can re-run with updated
inputs.

---

## Limitations

- These rankings are derived from synthetic data and an illustrative policy. They are not validated
  against real-world analyst decisions or a calibrated risk model.
- A change in queue position is not evidence that the context-aware result is more accurate. It
  reflects the assumptions encoded in demo-policy-v1.
- The 7-day evidence freshness and 30-day context freshness thresholds are illustrative, not
  NIST/CISA mandates.
- The baseline does not use any context; a real baseline alternative might incorporate additional
  analyst heuristics.

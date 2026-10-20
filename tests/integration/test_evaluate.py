"""Integration tests: evaluate all sample files and verify decisions against hand-derived
golden outcomes.

All expected rule_id, priority, and flag values below were computed manually from
docs/04_DECISION_POLICY.md, the sample CSV data, and the approved M2 clarifications,
BEFORE running the evaluator implementation.

Fixed evaluation point: AS_OF = 2026-10-19T00:00:00Z
Policy: policies/demo-policy-v1.json (context_freshness_days=30, evidence_freshness_days=7)

Evidence freshness boundary (7 days):  observed_at >= 2026-10-12T00:00:00Z → fresh
Context freshness boundary (30 days):  context_updated_at >= 2026-09-19T00:00:00Z → fresh
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from triageledger.ingest import parse_assets, parse_findings, parse_threat_evidence
from triageledger.models import BusinessCriticality, ExploitationStatus, InternetExposure
from triageledger.policy import evaluate, load_policy

SAMPLES = Path(__file__).parent.parent.parent / "samples"
POLICIES = Path(__file__).parent.parent.parent / "policies"
AS_OF = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fixture: load all inputs once per module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def decisions():
    policy = load_policy(POLICIES / "demo-policy-v1.json")
    ar = parse_assets(SAMPLES / "assets.csv", AS_OF)
    fr = parse_findings(SAMPLES / "findings.csv", AS_OF)
    er = parse_threat_evidence(SAMPLES / "threat_evidence.csv", AS_OF)
    assert not ar.fatal and not fr.fatal and not er.fatal
    return evaluate(fr.findings, ar.assets, er.threat_evidence, policy, AS_OF)


@pytest.fixture(scope="module")
def by_id(decisions):
    return {d.finding_id: d for d in decisions}


# ---------------------------------------------------------------------------
# Baseline: count and completeness
# ---------------------------------------------------------------------------


def test_all_16_findings_produce_decisions(decisions) -> None:
    assert len(decisions) == 16


def test_load_demo_policy_valid() -> None:
    """The committed demo-policy-v1.json passes validation without changes."""
    policy = load_policy(POLICIES / "demo-policy-v1.json")
    assert policy.policy_id == "demo-policy-v1"
    assert policy.context_freshness_days == 30
    assert policy.evidence_freshness_days == 7
    assert len(policy.rules) == 8


# ---------------------------------------------------------------------------
# F-001: A-001, SYN-001 (fresh active + fresh not_observed), high, confirmed
# Expected: P-01 / P1 — active exploitation with confirmed applicability.
# Flags: conflicting_threat_evidence (E-001 active + E-009 not_observed both fresh).
# ---------------------------------------------------------------------------


def test_f001_rule_and_priority(by_id) -> None:
    d = by_id["F-001"]
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert d.disposition == "review_recommended"


def test_f001_active_exploitation_and_conflict(by_id) -> None:
    d = by_id["F-001"]
    assert d.effective_exploitation == ExploitationStatus.ACTIVE
    assert "conflicting_threat_evidence" in d.flags
    # Both evidence IDs must be retained.
    assert "E-001" in d.evidence_ids
    assert "E-009" in d.evidence_ids


# ---------------------------------------------------------------------------
# F-002: A-001, SYN-002 (fresh active), critical, confirmed
# Expected: P-01 / P1 — fresh active + confirmed.
# ---------------------------------------------------------------------------


def test_f002_rule_and_priority(by_id) -> None:
    d = by_id["F-002"]
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert d.effective_exploitation == ExploitationStatus.ACTIVE
    assert "E-002" in d.evidence_ids


# ---------------------------------------------------------------------------
# F-003: A-002 (critical/exposed/fresh), SYN-003 (fresh not_observed), high, confirmed
# Expected: P-02 / P1 — exposed + critical + high; no active exploitation.
# ---------------------------------------------------------------------------


def test_f003_rule_and_priority(by_id) -> None:
    d = by_id["F-003"]
    assert d.rule_id == "P-02"
    assert d.priority == "P1"
    assert d.effective_exploitation == ExploitationStatus.NOT_OBSERVED
    assert d.effective_criticality == BusinessCriticality.CRITICAL
    assert d.effective_exposure == InternetExposure.EXPOSED


# ---------------------------------------------------------------------------
# F-004: A-003 (standard/not_exposed/fresh), SYN-004 (stale active), critical, confirmed
# Expected: P-03 / P2 — critical severity fires P-03; stale active → historical_active.
# ---------------------------------------------------------------------------


def test_f004_rule_and_priority(by_id) -> None:
    d = by_id["F-004"]
    assert d.rule_id == "P-03"
    assert d.priority == "P2"


def test_f004_stale_evidence_flags(by_id) -> None:
    d = by_id["F-004"]
    # E-004 is stale active (2026-10-10, age 9 days > 7-day threshold).
    assert d.effective_exploitation == ExploitationStatus.UNKNOWN
    assert "historical_active" in d.flags
    assert "threat_stale" in d.flags
    assert "threat_unknown" in d.flags
    assert "E-004" in d.evidence_ids


# ---------------------------------------------------------------------------
# F-005: A-004 (standard/not_exposed/STALE ctx 48d), SYN-005 (stale unknown), medium, unconfirmed
# Expected: P-05 / P3 — stale context → effective unknown; medium falls to P-05.
# Flags: context_stale, exposure_unknown, criticality_unknown, owner_unverified,
#        applicability_unconfirmed, threat_stale, threat_unknown.
# ---------------------------------------------------------------------------


def test_f005_rule_and_priority(by_id) -> None:
    d = by_id["F-005"]
    assert d.rule_id == "P-05"
    assert d.priority == "P3"


def test_f005_stale_context_flags(by_id) -> None:
    d = by_id["F-005"]
    assert d.effective_criticality == BusinessCriticality.UNKNOWN
    assert d.effective_exposure == InternetExposure.UNKNOWN
    # Original values must be retained.
    assert d.original_criticality is not None
    assert d.original_exposure is not None
    assert "context_stale" in d.flags
    assert "exposure_unknown" in d.flags
    assert "criticality_unknown" in d.flags
    assert "owner_unverified" in d.flags
    assert "applicability_unconfirmed" in d.flags
    assert "threat_stale" in d.flags
    assert "threat_unknown" in d.flags


# ---------------------------------------------------------------------------
# F-006: A-005 (critical/exposed/fresh), SYN-001 (active+conflicting), high, confirmed
# Expected: P-01 / P1 — fresh active + confirmed.
# Flags: conflicting_threat_evidence.
# ---------------------------------------------------------------------------


def test_f006_rule_and_priority(by_id) -> None:
    d = by_id["F-006"]
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert "conflicting_threat_evidence" in d.flags


# ---------------------------------------------------------------------------
# F-007: A-005, SYN-001, high, confirmed — possible_duplicate of F-006
# Expected: P-01 / P1; possible_duplicate flag preserved.
# ---------------------------------------------------------------------------


def test_f007_rule_and_priority_and_possible_duplicate(by_id) -> None:
    d = by_id["F-007"]
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert "possible_duplicate" in d.flags
    assert "conflicting_threat_evidence" in d.flags


# ---------------------------------------------------------------------------
# F-008: A-006 (standard/not_exposed/fresh/owner_missing), SYN-006 (no evidence), low, confirmed
# Expected: P-07 / P4 — low severity; owner_missing and threat_unknown flags set.
# ---------------------------------------------------------------------------


def test_f008_rule_and_priority(by_id) -> None:
    d = by_id["F-008"]
    assert d.rule_id == "P-07"
    assert d.priority == "P4"
    assert "owner_missing" in d.flags
    assert "threat_unknown" in d.flags
    assert d.evidence_ids == ()


# ---------------------------------------------------------------------------
# F-009: A-006 (owner_missing), no vulnerability_id, medium, confirmed
# Expected: P-05 / P3 — no evidence lookup; missing_vulnerability_id and threat_unknown.
# ---------------------------------------------------------------------------


def test_f009_rule_priority_and_missing_vuln(by_id) -> None:
    d = by_id["F-009"]
    assert d.rule_id == "P-05"
    assert d.priority == "P3"
    assert d.vulnerability_id is None
    assert "missing_vulnerability_id" in d.flags
    assert "threat_unknown" in d.flags
    assert "owner_missing" in d.flags
    assert d.evidence_ids == ()


# ---------------------------------------------------------------------------
# F-010: A-007 (critical/exposed/fresh), SYN-007 (fresh active at 7d boundary), not_affected
# Expected: EX-01 / null — not_affected fires first; evidence retained.
# ---------------------------------------------------------------------------


def test_f010_not_affected(by_id) -> None:
    d = by_id["F-010"]
    assert d.rule_id == "EX-01"
    assert d.priority is None
    assert d.disposition == "not_affected"


def test_f010_evidence_retained_despite_not_affected(by_id) -> None:
    # E-006 is fresh active (exactly 7-day boundary). Evidence must not be erased.
    d = by_id["F-010"]
    assert "E-006" in d.evidence_ids
    assert d.effective_exploitation == ExploitationStatus.ACTIVE


# ---------------------------------------------------------------------------
# F-011: A-008 (standard/not_exposed/fresh), SYN-008 (fresh not_observed), unknown severity
# Expected: P-06 / P2 — unknown severity conservative default; severity_unknown flag.
# ---------------------------------------------------------------------------


def test_f011_rule_and_priority(by_id) -> None:
    d = by_id["F-011"]
    assert d.rule_id == "P-06"
    assert d.priority == "P2"
    assert "severity_unknown" in d.flags
    assert d.effective_exploitation == ExploitationStatus.NOT_OBSERVED


# ---------------------------------------------------------------------------
# F-012: A-009 (unknown/unknown/STALE ctx 110d/owner_missing), SYN-009 (stale active)
# Expected: P-05 / P3 — stale context on already-unknown asset; high falls to P-05.
# Flags: owner_missing, owner_unverified, context_stale, exposure_unknown,
#        criticality_unknown, historical_active, threat_stale, threat_unknown.
# ---------------------------------------------------------------------------


def test_f012_rule_and_priority(by_id) -> None:
    d = by_id["F-012"]
    assert d.rule_id == "P-05"
    assert d.priority == "P3"


def test_f012_flags(by_id) -> None:
    d = by_id["F-012"]
    assert "owner_missing" in d.flags
    assert "owner_unverified" in d.flags
    assert "context_stale" in d.flags
    assert "exposure_unknown" in d.flags
    assert "criticality_unknown" in d.flags
    assert "historical_active" in d.flags
    assert "threat_stale" in d.flags
    assert "threat_unknown" in d.flags


# ---------------------------------------------------------------------------
# F-013: A-010 (standard/not_exposed/fresh), SYN-010 (no evidence), low, confirmed
# Expected: P-07 / P4.
# ---------------------------------------------------------------------------


def test_f013_rule_and_priority(by_id) -> None:
    d = by_id["F-013"]
    assert d.rule_id == "P-07"
    assert d.priority == "P4"
    assert "threat_unknown" in d.flags


# ---------------------------------------------------------------------------
# F-014: A-011 (critical/exposed/fresh), SYN-004 (stale active), critical, confirmed
# Expected: P-02 / P1 — exposed + critical + critical severity; stale active evidence noted.
# P-01 skipped because exploitation is unknown (stale active → unknown).
# ---------------------------------------------------------------------------


def test_f014_rule_and_priority(by_id) -> None:
    d = by_id["F-014"]
    assert d.rule_id == "P-02"
    assert d.priority == "P1"
    assert d.effective_exploitation == ExploitationStatus.UNKNOWN
    assert "historical_active" in d.flags
    assert "threat_stale" in d.flags


# ---------------------------------------------------------------------------
# F-015: A-012 (standard/not_exposed/fresh), SYN-011 (no evidence), medium, unconfirmed
# Expected: P-05 / P3; applicability_unconfirmed and threat_unknown flags.
# ---------------------------------------------------------------------------


def test_f015_rule_and_priority(by_id) -> None:
    d = by_id["F-015"]
    assert d.rule_id == "P-05"
    assert d.priority == "P3"
    assert "applicability_unconfirmed" in d.flags
    assert "threat_unknown" in d.flags


# ---------------------------------------------------------------------------
# F-016: UNMATCHED-999 (no asset), SYN-012 (no evidence), high, confirmed
# Expected: P-05 / P3 — missing asset; high with unknown context falls to P-05.
# Flags: asset_unmatched, context_missing, exposure_unknown, criticality_unknown, threat_unknown.
# ---------------------------------------------------------------------------


def test_f016_unmatched_asset(by_id) -> None:
    d = by_id["F-016"]
    assert d.rule_id == "P-05"
    assert d.priority == "P3"
    assert d.asset_id == "UNMATCHED-999"
    assert d.original_criticality is None
    assert d.original_exposure is None
    assert d.context_age_days is None


def test_f016_flags(by_id) -> None:
    d = by_id["F-016"]
    assert "asset_unmatched" in d.flags
    assert "context_missing" in d.flags
    assert "exposure_unknown" in d.flags
    assert "criticality_unknown" in d.flags
    assert "threat_unknown" in d.flags


# ---------------------------------------------------------------------------
# Sort order: verify golden sequence for the 16 decisions
# ---------------------------------------------------------------------------


def test_sort_order_golden(decisions) -> None:
    """Verify the exact sorted order against the hand-derived sequence.

    Sort key: (is_excluded, priority_order, detected_at, asset_id, finding_id).
    Actionable P1..P4 first, then excluded (not_affected).

    Hand-derived order:
      P1: F-001 (10-05/A-001), F-002 (10-06/A-001), F-003 (10-07/A-002),
          F-006 (10-10/A-005), F-007 (10-10/A-005), F-014 (10-15/A-011)
      P2: F-004 (10-08/A-003), F-011 (10-11/A-008)
      P3: F-005 (09-15/A-004), F-009 (10-02/A-006), F-012 (10-13/A-009),
          F-015 (10-16/A-012), F-016 (10-17/UNMATCHED-999)
      P4: F-008 (10-01/A-006), F-013 (10-14/A-010)
      Excluded: F-010 (10-09/A-007)
    """
    expected = [
        "F-001",
        "F-002",
        "F-003",
        "F-006",
        "F-007",
        "F-014",  # P1
        "F-004",
        "F-011",  # P2
        "F-005",
        "F-009",
        "F-012",
        "F-015",
        "F-016",  # P3
        "F-008",
        "F-013",  # P4
        "F-010",  # excluded
    ]
    actual = [d.finding_id for d in decisions]
    assert actual == expected


# ---------------------------------------------------------------------------
# Supporting facts traceability
# ---------------------------------------------------------------------------


def test_f005_supporting_facts_retain_original_stale_values(by_id) -> None:
    """F-005 has stale context: supporting_facts must show both original and effective."""
    d = by_id["F-005"]
    # A-004 is standard/not_exposed originally.
    assert d.supporting_facts["original_criticality"] == "standard"
    assert d.supporting_facts["original_exposure"] == "not_exposed"
    assert d.supporting_facts["effective_criticality"] == "unknown"
    assert d.supporting_facts["effective_exposure"] == "unknown"


def test_f010_supporting_facts_show_not_affected(by_id) -> None:
    d = by_id["F-010"]
    assert d.supporting_facts["applicability"] == "not_affected"
    assert d.supporting_facts["effective_exploitation"] == "active"


# ---------------------------------------------------------------------------
# Next-action content spot checks
# ---------------------------------------------------------------------------


def test_p1_findings_have_urgent_next_action(decisions) -> None:
    p1 = [d for d in decisions if d.priority == "P1"]
    for d in p1:
        assert "Urgent analyst review" in d.next_action, f"{d.finding_id} missing urgent action"


def test_f008_owner_missing_appended_to_next_action(by_id) -> None:
    """owner_missing supplement is appended without lowering P4 action text."""
    d = by_id["F-008"]
    assert "Routine review" in d.next_action
    assert "Assign owner" in d.next_action


def test_not_affected_next_action_does_not_claim_remediation(by_id) -> None:
    d = by_id["F-010"]
    # Must not use words that claim the finding is fixed or verified.
    lower = d.next_action.lower()
    assert "fixed" not in lower
    assert "remediat" not in lower or "not treat as verified" in d.next_action


# ---------------------------------------------------------------------------
# Schema version and rule version propagated
# ---------------------------------------------------------------------------


def test_schema_version_set_on_all_decisions(decisions) -> None:
    for d in decisions:
        assert d.schema_version == "1.0"


def test_rule_version_matches_policy_version(decisions) -> None:
    for d in decisions:
        assert d.rule_version == "1.0.0"


def test_as_of_propagated(decisions) -> None:
    for d in decisions:
        assert d.as_of == AS_OF

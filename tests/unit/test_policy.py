"""Unit tests for triageledger.policy: load_policy, aggregate_evidence, evaluate.

Expected outcomes are derived manually from docs/04_DECISION_POLICY.md and the
approved M2 clarifications. They were NOT produced by running the evaluator.

Spec cross-references:
  [SPEC-n] = case n from docs/05_TEST_AND_EVALUATION.md § Unit cases
  [M2-agg] = approved M2 evidence aggregation rules
  [M2-flags] = approved M2 independent flag definitions
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from triageledger.models import (
    REQUIRED_RULE_SEQUENCE,
    Applicability,
    Asset,
    BusinessCriticality,
    ExploitationStatus,
    Finding,
    InternetExposure,
    PolicyConfig,
    Severity,
    ThreatEvidence,
)
from triageledger.policy import aggregate_evidence, evaluate, load_policy

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

AS_OF = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)

# Evidence freshness boundary (7 days)
_EV_FRESH_BOUNDARY = AS_OF - timedelta(seconds=7 * 24 * 3600)  # exactly at limit → fresh
_EV_STALE_BOUNDARY = AS_OF - timedelta(seconds=7 * 24 * 3600 + 1)  # one second over → stale
_EV_FRESH = AS_OF - timedelta(days=1)
_EV_STALE = AS_OF - timedelta(days=10)

# Context freshness boundary (30 days)
_CTX_FRESH_BOUNDARY = AS_OF - timedelta(seconds=30 * 24 * 3600)  # exactly at limit → fresh
_CTX_STALE_BOUNDARY = AS_OF - timedelta(seconds=30 * 24 * 3600 + 1)  # one second over → stale
_CTX_FRESH = AS_OF - timedelta(days=1)
_CTX_STALE = AS_OF - timedelta(days=40)

_DETECTED = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)

# A minimal valid PolicyConfig used across all evaluate() unit tests.
POLICY = PolicyConfig(
    policy_id="unit-test-policy",
    version="0.0.1",
    description="Unit test policy — not a real mandate",
    context_freshness_days=30,
    evidence_freshness_days=7,
    rules=REQUIRED_RULE_SEQUENCE,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _asset(
    asset_id: str = "A-UNIT",
    criticality: str = "standard",
    exposure: str = "not_exposed",
    owner_team: str | None = "test-team",
    context_updated_at: datetime | None = None,
    owner_missing: bool = False,
) -> Asset:
    return Asset(
        asset_id=asset_id,
        display_name=f"Unit {asset_id}",
        business_criticality=BusinessCriticality(criticality),
        internet_exposure=InternetExposure(exposure),
        owner_team=owner_team,
        context_updated_at=context_updated_at if context_updated_at is not None else _CTX_FRESH,
        owner_missing=owner_missing,
    )


def _finding(
    finding_id: str = "F-UNIT",
    asset_id: str = "A-UNIT",
    vulnerability_id: str | None = "SYN-UNIT",
    severity: str = "high",
    applicability: str = "confirmed",
    detected_at: datetime | None = None,
    missing_vulnerability_id: bool = False,
    possible_duplicate: bool = False,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        severity=Severity(severity),
        applicability=Applicability(applicability),
        detected_at=detected_at if detected_at is not None else _DETECTED,
        description=None,
        missing_vulnerability_id=missing_vulnerability_id,
        possible_duplicate=possible_duplicate,
    )


def _evidence(
    evidence_id: str,
    vulnerability_id: str = "SYN-UNIT",
    status: str = "active",
    observed_at: datetime | None = None,
) -> ThreatEvidence:
    return ThreatEvidence(
        evidence_id=evidence_id,
        vulnerability_id=vulnerability_id,
        exploitation_status=ExploitationStatus(status),
        source_label="Synthetic Unit Test",
        source_reference="synthetic://unit-test",
        observed_at=observed_at if observed_at is not None else _EV_FRESH,
    )


def _single(findings, assets, evidence, finding_id: str):
    """Run evaluate() and return the single decision matching finding_id."""
    decisions = evaluate(findings, assets, evidence, POLICY, AS_OF)
    matches = [d for d in decisions if d.finding_id == finding_id]
    assert len(matches) == 1, f"Expected 1 decision for {finding_id!r}, got {len(matches)}"
    return matches[0]


def _valid_policy_dict() -> dict:
    return {
        "policy_id": "test-policy",
        "version": "1.0.0",
        "description": "Test",
        "context_freshness_days": 30,
        "evidence_freshness_days": 7,
        "rules": list(REQUIRED_RULE_SEQUENCE),
    }


# ---------------------------------------------------------------------------
# load_policy — valid
# ---------------------------------------------------------------------------


def test_load_policy_valid(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(_valid_policy_dict()), encoding="utf-8")
    cfg = load_policy(p)
    assert cfg.policy_id == "test-policy"
    assert cfg.version == "1.0.0"
    assert cfg.context_freshness_days == 30
    assert cfg.evidence_freshness_days == 7
    assert cfg.rules == REQUIRED_RULE_SEQUENCE


# ---------------------------------------------------------------------------
# load_policy — invalid configurations
# ---------------------------------------------------------------------------


def test_load_policy_unknown_key_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["extra_key"] = "surprise"
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown keys"):
        load_policy(p)


def test_load_policy_missing_key_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    del d["policy_id"]
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required keys"):
        load_policy(p)


def test_load_policy_wrong_rule_order_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["rules"] = ["P-01", "EX-01", "P-02", "P-03", "P-04", "P-05", "P-06", "P-07"]
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="rules must be exactly"):
        load_policy(p)


def test_load_policy_missing_rule_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["rules"] = [r for r in REQUIRED_RULE_SEQUENCE if r != "P-03"]
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="rules must be exactly"):
        load_policy(p)


def test_load_policy_duplicate_rule_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["rules"] = list(REQUIRED_RULE_SEQUENCE) + ["P-01"]
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="rules must be exactly"):
        load_policy(p)


def test_load_policy_boolean_freshness_rejected(tmp_path: Path) -> None:
    # bool is a subclass of int; must be explicitly rejected.
    d = _valid_policy_dict()
    d["context_freshness_days"] = True
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="positive integer, not a boolean"):
        load_policy(p)


def test_load_policy_zero_freshness_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["evidence_freshness_days"] = 0
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="positive integer"):
        load_policy(p)


def test_load_policy_negative_freshness_rejected(tmp_path: Path) -> None:
    d = _valid_policy_dict()
    d["context_freshness_days"] = -1
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ValueError, match="positive integer"):
        load_policy(p)


def test_load_policy_invalid_json_rejected(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text("not valid json {{{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_policy(p)


def test_load_policy_not_object_rejected(tmp_path: Path) -> None:
    p = tmp_path / "policy.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_policy(p)


def test_load_policy_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Cannot read"):
        load_policy(tmp_path / "nonexistent.json")


# ---------------------------------------------------------------------------
# aggregate_evidence — evidence combination scenarios [M2-agg] [M2-flags]
# ---------------------------------------------------------------------------


def test_agg_fresh_active_only() -> None:
    """Single fresh active → effective=active, no stale flags."""
    e = _evidence("E-1", status="active", observed_at=_EV_FRESH)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_unknown
    assert not s.threat_stale
    assert not s.historical_active
    assert not s.conflicting_threat_evidence
    assert s.evidence_ids == ("E-1",)


def test_agg_fresh_not_observed_only() -> None:
    """Single fresh not_observed, no active → effective=not_observed."""
    e = _evidence("E-1", status="not_observed", observed_at=_EV_FRESH)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.NOT_OBSERVED
    assert not s.threat_unknown
    assert not s.threat_stale
    assert not s.historical_active
    assert not s.conflicting_threat_evidence


def test_agg_stale_active_only() -> None:
    """Stale active → effective=unknown; historical_active and threat_stale set. [M2-agg rule 2]"""
    e = _evidence("E-1", status="active", observed_at=_EV_STALE)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.UNKNOWN
    assert s.threat_unknown  # effective is unknown
    assert s.threat_stale
    assert s.historical_active
    assert not s.conflicting_threat_evidence


def test_agg_stale_active_with_fresh_not_observed() -> None:
    """Stale active + fresh not_observed → effective=unknown (stale active takes priority
    over fresh not_observed per approved rule 2). [M2-agg]"""
    e_stale_active = _evidence("E-stale", status="active", observed_at=_EV_STALE)
    e_fresh_not_obs = _evidence("E-fresh", status="not_observed", observed_at=_EV_FRESH)
    s = aggregate_evidence([e_stale_active, e_fresh_not_obs], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.UNKNOWN
    assert s.threat_unknown
    assert s.threat_stale
    assert s.historical_active
    # Both active and not_observed statuses present → contradiction flag.
    assert s.conflicting_threat_evidence


def test_agg_fresh_active_with_stale_active() -> None:
    """Fresh active + stale active → effective=active; historical_active still set. [M2-flags]"""
    e_fresh = _evidence("E-fresh", status="active", observed_at=_EV_FRESH)
    e_stale = _evidence("E-stale", status="active", observed_at=_EV_STALE)
    s = aggregate_evidence([e_fresh, e_stale], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_unknown
    assert s.threat_stale  # stale row exists
    assert s.historical_active  # stale active exists even though fresh active also exists
    assert not s.conflicting_threat_evidence  # only active status present


def test_agg_fresh_active_with_stale_not_observed() -> None:
    """Fresh active + stale not_observed → effective=active; stale row sets threat_stale;
    conflicting flag set because both active and not_observed statuses are present. [M2-flags]"""
    e_fresh_active = _evidence("E-active", status="active", observed_at=_EV_FRESH)
    e_stale_not_obs = _evidence("E-not-obs", status="not_observed", observed_at=_EV_STALE)
    s = aggregate_evidence([e_fresh_active, e_stale_not_obs], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_unknown
    assert s.threat_stale  # stale not_observed row exists
    assert not s.historical_active  # no stale active row
    assert s.conflicting_threat_evidence  # active + not_observed present


def test_agg_fresh_unknown_only() -> None:
    """Fresh evidence with unknown status → effective=unknown (no active or not_observed)."""
    e = _evidence("E-1", status="unknown", observed_at=_EV_FRESH)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.UNKNOWN
    assert s.threat_unknown
    assert not s.threat_stale  # fresh row
    assert not s.historical_active
    assert not s.conflicting_threat_evidence


def test_agg_fresh_active_plus_fresh_not_observed() -> None:
    """Fresh active + fresh not_observed → effective=active + conflicting flag. [SPEC-11]"""
    e_active = _evidence("E-a", status="active", observed_at=_EV_FRESH)
    e_not_obs = _evidence("E-n", status="not_observed", observed_at=_EV_FRESH)
    s = aggregate_evidence([e_active, e_not_obs], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_unknown
    assert not s.threat_stale
    assert not s.historical_active
    assert s.conflicting_threat_evidence


def test_agg_evidence_boundary_exactly_fresh() -> None:
    """Evidence at exactly the freshness boundary counts as fresh. [SPEC-9]"""
    e = _evidence("E-boundary", status="active", observed_at=_EV_FRESH_BOUNDARY)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_stale


def test_agg_evidence_boundary_one_second_stale() -> None:
    """Evidence one second past the boundary counts as stale. [SPEC-9]"""
    e = _evidence("E-stale", status="active", observed_at=_EV_STALE_BOUNDARY)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.UNKNOWN
    assert s.threat_stale
    assert s.historical_active


def test_agg_multiple_vulnerabilities_isolated() -> None:
    """Evidence for different vuln_ids produces independent summaries."""
    e1 = _evidence("E-1", vulnerability_id="SYN-A", status="active")
    e2 = _evidence("E-2", vulnerability_id="SYN-B", status="not_observed")
    summaries = aggregate_evidence([e1, e2], AS_OF, 7)
    assert summaries["SYN-A"].effective_exploitation == ExploitationStatus.ACTIVE
    assert summaries["SYN-B"].effective_exploitation == ExploitationStatus.NOT_OBSERVED
    assert "SYN-A" not in summaries["SYN-B"].evidence_ids
    assert "SYN-B" not in summaries["SYN-A"].evidence_ids


def test_agg_evidence_order_independence() -> None:
    """Reversing evidence order does not change effective_exploitation or flags. [M2-agg]"""
    e1 = _evidence("E-active", status="active", observed_at=_EV_FRESH)
    e2 = _evidence("E-not-obs", status="not_observed", observed_at=_EV_FRESH)
    s_fwd = aggregate_evidence([e1, e2], AS_OF, 7)["SYN-UNIT"]
    s_rev = aggregate_evidence([e2, e1], AS_OF, 7)["SYN-UNIT"]
    assert s_fwd.effective_exploitation == s_rev.effective_exploitation
    assert s_fwd.threat_unknown == s_rev.threat_unknown
    assert s_fwd.threat_stale == s_rev.threat_stale
    assert s_fwd.historical_active == s_rev.historical_active
    assert s_fwd.conflicting_threat_evidence == s_rev.conflicting_threat_evidence
    assert frozenset(s_fwd.evidence_ids) == frozenset(s_rev.evidence_ids)


def test_agg_empty_returns_empty_dict() -> None:
    summaries = aggregate_evidence([], AS_OF, 7)
    assert summaries == {}


# ---------------------------------------------------------------------------
# evaluate — spec cases [SPEC-1 … SPEC-12]
# ---------------------------------------------------------------------------


def test_spec_1_confirmed_fresh_active_is_p1() -> None:
    """[SPEC-1] Confirmed + fresh active exploitation → P1/P-01 regardless of low severity."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="low", applicability="confirmed")
    evidence = [_evidence("E-1", status="active", observed_at=_EV_FRESH)]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert d.disposition == "review_recommended"
    assert "E-1" in d.evidence_ids


def test_spec_2_exposed_critical_high_no_active_is_p1_p02() -> None:
    """[SPEC-2] Exposed + critical asset + high severity, no active evidence → P1/P-02."""
    asset = _asset(criticality="critical", exposure="exposed")
    finding = _finding(severity="high", applicability="confirmed")
    evidence = [_evidence("E-1", status="not_observed", observed_at=_EV_FRESH)]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.rule_id == "P-02"
    assert d.priority == "P1"
    assert d.effective_exploitation == ExploitationStatus.NOT_OBSERVED


def test_spec_3_critical_severity_standard_internal_is_p2_p03() -> None:
    """[SPEC-3] Critical severity + standard internal asset → P2/P-03.
    Standard + not_exposed must not downgrade below P-03."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="critical", applicability="confirmed")
    d = _single([finding], [asset], [], "F-UNIT")
    assert d.rule_id == "P-03"
    assert d.priority == "P2"


def test_spec_4_high_standard_not_exposed_is_p3_p05() -> None:
    """[SPEC-4] High severity + standard not_exposed → P3/P-05."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="high", applicability="confirmed")
    d = _single([finding], [asset], [], "F-UNIT")
    assert d.rule_id == "P-05"
    assert d.priority == "P3"


def test_spec_5_unknown_severity_is_p2_p06() -> None:
    """[SPEC-5] Unknown severity → P2/P-06, severity_unknown flag set."""
    asset = _asset()
    finding = _finding(severity="unknown")
    d = _single([finding], [asset], [], "F-UNIT")
    assert d.rule_id == "P-06"
    assert d.priority == "P2"
    assert "severity_unknown" in d.flags


def test_spec_6_missing_asset_retained_with_flags() -> None:
    """[SPEC-6] Missing asset → finding retained; context flags set; never disappears."""
    finding = _finding(asset_id="GHOST-ASSET", finding_id="F-GHOST")
    # No asset in the list for GHOST-ASSET.
    d = _single([finding], [], [], "F-GHOST")
    assert d.asset_id == "GHOST-ASSET"
    assert d.original_criticality is None
    assert d.original_exposure is None
    assert d.context_age_days is None
    assert "asset_unmatched" in d.flags
    assert "context_missing" in d.flags
    assert "exposure_unknown" in d.flags
    assert "criticality_unknown" in d.flags


def test_spec_7_not_affected_with_active_evidence_is_ex01() -> None:
    """[SPEC-7] not_affected + active evidence → EX-01 / priority null.
    Evidence is preserved; do not claim verified or remediated."""
    asset = _asset(criticality="critical", exposure="exposed")
    finding = _finding(severity="critical", applicability="not_affected")
    evidence = [_evidence("E-active", status="active", observed_at=_EV_FRESH)]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.rule_id == "EX-01"
    assert d.priority is None
    assert d.disposition == "not_affected"
    # Evidence IDs must be preserved; do not erase.
    assert "E-active" in d.evidence_ids
    assert "not_affected" not in d.next_action.lower().replace("not_affected", "")  # not "verified"


def test_spec_8_missing_owner_does_not_lower_priority() -> None:
    """[SPEC-8] Missing owner does not reduce priority; owner_missing flag set.
    Exposed critical + high severity → P1/P-02 even without an owner."""
    asset = _asset(criticality="critical", exposure="exposed", owner_team=None, owner_missing=True)
    finding = _finding(severity="high", applicability="confirmed")
    d = _single([finding], [asset], [], "F-UNIT")
    assert d.rule_id == "P-02"
    assert d.priority == "P1"
    assert "owner_missing" in d.flags
    # Owner-related supplement must appear in next_action without replacing P1 action.
    assert "Urgent analyst review" in d.next_action
    assert "Assign owner" in d.next_action


def test_spec_9_context_boundary_exactly_fresh() -> None:
    """[SPEC-9] Exactly 30-day context age → fresh; uses actual criticality/exposure."""
    asset = _asset(
        criticality="critical", exposure="exposed", context_updated_at=_CTX_FRESH_BOUNDARY
    )
    finding = _finding(severity="high", applicability="confirmed")
    d = _single([finding], [asset], [], "F-UNIT")
    # Fresh context → P-02 (exposed + critical + high)
    assert d.rule_id == "P-02"
    assert d.effective_criticality == BusinessCriticality.CRITICAL
    assert d.effective_exposure == InternetExposure.EXPOSED
    assert "context_stale" not in d.flags


def test_spec_9_context_boundary_one_second_stale() -> None:
    """[SPEC-9] 30 days + 1 second → stale; effective criticality/exposure become unknown."""
    asset = _asset(
        criticality="critical", exposure="exposed", context_updated_at=_CTX_STALE_BOUNDARY
    )
    finding = _finding(severity="high", applicability="confirmed")
    d = _single([finding], [asset], [], "F-UNIT")
    # Stale → effective values are unknown → P-02 cannot fire; P-05 (high) fires instead.
    assert d.rule_id == "P-05"
    assert d.effective_criticality == BusinessCriticality.UNKNOWN
    assert d.effective_exposure == InternetExposure.UNKNOWN
    assert d.original_criticality == BusinessCriticality.CRITICAL
    assert d.original_exposure == InternetExposure.EXPOSED
    assert "context_stale" in d.flags
    assert "owner_unverified" in d.flags
    assert "exposure_unknown" in d.flags
    assert "criticality_unknown" in d.flags


def test_spec_10_stale_active_recorded_not_erased() -> None:
    """[SPEC-10] Stale active evidence → historical_active + threat_stale; effective=unknown.
    Fresh not_observed does not erase the stale active history.
    Decision should not reach P-01 (exploitation not active)."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="high", applicability="confirmed")
    evidence = [
        _evidence("E-stale-act", status="active", observed_at=_EV_STALE),
        _evidence("E-fresh-not", status="not_observed", observed_at=_EV_FRESH),
    ]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.effective_exploitation == ExploitationStatus.UNKNOWN
    assert d.rule_id == "P-05"  # high, standard, not_exposed → P-05 (not P-01)
    assert "historical_active" in d.flags
    assert "threat_stale" in d.flags
    assert "threat_unknown" in d.flags
    # Both evidence IDs must be retained in the decision.
    assert "E-stale-act" in d.evidence_ids
    assert "E-fresh-not" in d.evidence_ids


def test_spec_11_fresh_active_fresh_not_observed_is_active_with_conflict() -> None:
    """[SPEC-11] Fresh active + fresh not_observed → effective=active + conflicting flag."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="high", applicability="confirmed")
    evidence = [
        _evidence("E-act", status="active", observed_at=_EV_FRESH),
        _evidence("E-not", status="not_observed", observed_at=_EV_FRESH),
    ]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.effective_exploitation == ExploitationStatus.ACTIVE
    assert d.rule_id == "P-01"
    assert d.priority == "P1"
    assert "conflicting_threat_evidence" in d.flags
    assert not any(f == "historical_active" for f in d.flags)


def test_spec_12_unconfirmed_low_active_evidence_is_p2_p03() -> None:
    """[SPEC-12] Unconfirmed low severity + active evidence → P2/P-03 + applicability flag.
    P-01 requires confirmed applicability; P-03 fires on active exploitation regardless."""
    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="low", applicability="unconfirmed")
    evidence = [_evidence("E-1", status="active", observed_at=_EV_FRESH)]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.rule_id == "P-03"
    assert d.priority == "P2"
    assert "applicability_unconfirmed" in d.flags


# ---------------------------------------------------------------------------
# evaluate — missing vulnerability ID [M2-flags]
# ---------------------------------------------------------------------------


def test_missing_vulnerability_id_no_threat_lookup() -> None:
    """Finding with missing_vulnerability_id=True → no evidence lookup; threat_unknown set."""
    asset = _asset()
    # Simulate a finding whose vuln_id was blank in the CSV.
    finding = Finding(
        finding_id="F-NOVULN",
        asset_id="A-UNIT",
        vulnerability_id=None,
        severity=Severity.MEDIUM,
        applicability=Applicability.CONFIRMED,
        detected_at=_DETECTED,
        description=None,
        missing_vulnerability_id=True,
        possible_duplicate=False,
    )
    # Add evidence for an unrelated vuln_id to confirm no cross-contamination.
    evidence = [_evidence("E-other", vulnerability_id="SYN-OTHER", status="active")]
    d = _single([finding], [asset], evidence, "F-NOVULN")
    assert d.evidence_ids == ()
    assert "threat_unknown" in d.flags
    assert "missing_vulnerability_id" in d.flags
    # No evidence for this finding → P-05 (medium severity)
    assert d.rule_id == "P-05"


# ---------------------------------------------------------------------------
# evaluate — context staleness and owner_unverified
# ---------------------------------------------------------------------------


def test_stale_context_sets_owner_unverified() -> None:
    """Stale context → owner_unverified flag; stale owner is unverified, not erased."""
    asset = _asset(context_updated_at=_CTX_STALE, owner_team="legacy-team")
    finding = _finding(severity="medium")
    d = _single([finding], [asset], [], "F-UNIT")
    assert "context_stale" in d.flags
    assert "owner_unverified" in d.flags
    assert d.owner_team == "legacy-team"  # team name retained, not erased


# ---------------------------------------------------------------------------
# evaluate — possible_duplicate flag preserved
# ---------------------------------------------------------------------------


def test_possible_duplicate_flag_preserved() -> None:
    """possible_duplicate from ingest is carried through to the decision flags."""
    asset = _asset()
    finding = _finding(possible_duplicate=True)
    d = _single([finding], [asset], [], "F-UNIT")
    assert "possible_duplicate" in d.flags


# ---------------------------------------------------------------------------
# evaluate — deterministic sort order
# ---------------------------------------------------------------------------


def test_sort_p1_before_p2_before_p3_before_p4_before_excluded() -> None:
    """Actionable priorities in order P1 < P2 < P3 < P4; excluded (not_affected) last."""
    # A-3 is exposed+critical so F-P1 (high severity) fires P-02 → P1.
    assets = [
        _asset("A-0"),  # standard, not_exposed
        _asset("A-1"),
        _asset("A-2"),
        _asset("A-3", criticality="critical", exposure="exposed"),
        _asset("A-4"),
    ]
    findings = [
        _finding("F-P4", asset_id="A-0", severity="low"),  # → P4/P-07
        _finding("F-EX", asset_id="A-1", severity="high", applicability="not_affected"),  # excluded
        _finding("F-P2", asset_id="A-2", severity="critical"),  # → P2/P-03
        _finding("F-P1", asset_id="A-3", severity="high"),  # → P1/P-02
        _finding("F-P3", asset_id="A-4", severity="medium"),  # → P3/P-05
    ]
    decisions = evaluate(findings, assets, [], POLICY, AS_OF)
    priorities = [d.priority for d in decisions]
    # Expected order: P1, P2, P3, P4, None
    assert priorities == ["P1", "P2", "P3", "P4", None]


def test_sort_same_priority_by_detected_at_then_asset_id_then_finding_id() -> None:
    """Within the same priority, sort by detected_at asc, then asset_id lex, then finding_id lex."""
    asset = _asset()
    t1 = datetime(2026, 10, 1, tzinfo=UTC)
    t2 = datetime(2026, 10, 5, tzinfo=UTC)
    findings = [
        _finding("F-Z", detected_at=t1),  # same asset, earlier time, later ID
        _finding("F-A", detected_at=t2),  # same asset, later time, earlier ID
        _finding("F-M", detected_at=t1),  # same asset, earlier time, middle ID
    ]
    decisions = evaluate(findings, [asset], [], POLICY, AS_OF)
    ids = [d.finding_id for d in decisions]
    # t1 < t2; among t1 ties, "F-M" < "F-Z"
    assert ids == ["F-M", "F-Z", "F-A"]


def test_sort_excluded_findings_included_in_result() -> None:
    """Excluded (not_affected) findings appear in results after all actionable rows."""
    asset = _asset()
    f_action = _finding("F-ACT", severity="high")  # → P3/P-05
    f_excl = _finding("F-EXC", applicability="not_affected")  # → excluded
    decisions = evaluate([f_action, f_excl], [asset], [], POLICY, AS_OF)
    assert len(decisions) == 2
    assert decisions[0].finding_id == "F-ACT"
    assert decisions[1].finding_id == "F-EXC"
    assert decisions[1].priority is None
    assert decisions[1].disposition == "not_affected"


# ---------------------------------------------------------------------------
# evaluate — supporting facts traceability
# ---------------------------------------------------------------------------


def test_supporting_facts_contain_original_and_effective_values() -> None:
    """Stale context: supporting_facts preserves both original and effective values."""
    asset = _asset(criticality="critical", exposure="exposed", context_updated_at=_CTX_STALE)
    finding = _finding(severity="high")
    d = _single([finding], [asset], [], "F-UNIT")
    assert d.supporting_facts["original_criticality"] == "critical"
    assert d.supporting_facts["original_exposure"] == "exposed"
    assert d.supporting_facts["effective_criticality"] == "unknown"
    assert d.supporting_facts["effective_exposure"] == "unknown"


# ---------------------------------------------------------------------------
# threat_unknown contract: present whenever effective_exploitation == unknown [M2-flags]
# ---------------------------------------------------------------------------


def test_agg_stale_not_observed_only_is_threat_unknown() -> None:
    """Stale not_observed: no active, no stale active, no fresh not_observed → effective=unknown.
    threat_unknown must be set; historical_active must NOT be set (no stale active)."""
    e = _evidence("E-stale-no", status="not_observed", observed_at=_EV_STALE)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.UNKNOWN
    assert s.threat_unknown  # effective is unknown → flag required by contract
    assert s.threat_stale  # stale row exists
    assert not s.historical_active  # no stale active
    assert not s.conflicting_threat_evidence  # only not_observed status


def test_evaluate_no_evidence_for_vuln_id_sets_threat_unknown() -> None:
    """Finding has a valid vuln_id but there are zero matching evidence rows.
    effective_exploitation is unknown → threat_unknown flag required."""
    asset = _asset()
    finding = _finding(vulnerability_id="SYN-NOEVIDENCE", severity="medium")
    # Evidence exists for a different vuln_id only.
    evidence = [_evidence("E-other", vulnerability_id="SYN-OTHER", status="active")]
    d = _single([finding], [asset], evidence, "F-UNIT")
    assert d.effective_exploitation == ExploitationStatus.UNKNOWN
    assert "threat_unknown" in d.flags
    assert d.evidence_ids == ()


def test_agg_fresh_active_no_threat_unknown() -> None:
    """Fresh active evidence → effective=active; threat_unknown must NOT be set."""
    e = _evidence("E-1", status="active", observed_at=_EV_FRESH)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.ACTIVE
    assert not s.threat_unknown


def test_agg_fresh_not_observed_no_threat_unknown() -> None:
    """Fresh not_observed (no active) → effective=not_observed; threat_unknown must NOT be set."""
    e = _evidence("E-1", status="not_observed", observed_at=_EV_FRESH)
    s = aggregate_evidence([e], AS_OF, 7)["SYN-UNIT"]
    assert s.effective_exploitation == ExploitationStatus.NOT_OBSERVED
    assert not s.threat_unknown


# ---------------------------------------------------------------------------
# as_of validation: reject non-datetime and timezone-naive inputs [item 2]
# ---------------------------------------------------------------------------


def test_evaluate_rejects_naive_datetime() -> None:
    """evaluate() must raise ValueError for a naive (tz-unaware) datetime."""
    naive = datetime(2026, 10, 19, 0, 0, 0)  # no tzinfo
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluate([], [], [], POLICY, naive)


def test_evaluate_rejects_non_datetime() -> None:
    """evaluate() must raise TypeError when as_of is not a datetime."""
    with pytest.raises(TypeError, match="datetime"):
        evaluate([], [], [], POLICY, "2026-10-19T00:00:00Z")  # type: ignore[arg-type]


def test_aggregate_evidence_rejects_naive_datetime() -> None:
    """aggregate_evidence() must raise ValueError for a naive datetime."""
    naive = datetime(2026, 10, 19, 0, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        aggregate_evidence([], naive, 7)


def test_aggregate_evidence_rejects_non_datetime() -> None:
    """aggregate_evidence() must raise TypeError when as_of is not a datetime."""
    with pytest.raises(TypeError, match="datetime"):
        aggregate_evidence([], 1234567890, 7)  # type: ignore[arg-type]


def test_evaluate_equivalent_instants_same_decisions() -> None:
    """Timezone-aware datetimes representing the same UTC instant must produce identical decisions.

    2026-10-19T05:00:00+05:00 equals 2026-10-19T00:00:00Z.
    Evidence observed at 2026-10-17T00:00:00Z is fresh in both cases (age=2 days < 7 days).
    """
    as_of_utc = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)
    as_of_plus5 = datetime(2026, 10, 19, 5, 0, 0, tzinfo=timezone(timedelta(hours=5)))

    asset = _asset(criticality="standard", exposure="not_exposed")
    finding = _finding(severity="high", applicability="confirmed")
    # Evidence observed 2 days before as_of — fresh in both cases.
    evidence = [_evidence("E-1", status="active", observed_at=datetime(2026, 10, 17, tzinfo=UTC))]

    d_utc = evaluate([finding], [asset], evidence, POLICY, as_of_utc)
    d_plus5 = evaluate([finding], [asset], evidence, POLICY, as_of_plus5)

    assert len(d_utc) == len(d_plus5) == 1
    assert d_utc[0].rule_id == d_plus5[0].rule_id
    assert d_utc[0].priority == d_plus5[0].priority
    assert d_utc[0].effective_exploitation == d_plus5[0].effective_exploitation
    assert d_utc[0].flags == d_plus5[0].flags
    # as_of stored on decision is normalized to UTC in both cases.
    assert d_utc[0].as_of == d_plus5[0].as_of == as_of_utc

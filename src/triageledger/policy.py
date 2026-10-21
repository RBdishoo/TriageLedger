"""Policy loading, evidence aggregation, and first-match rule evaluation for TriageLedger v1.

Design constraints (from M2 approval):
- File I/O is isolated to load_policy; aggregate_evidence and evaluate are pure functions.
- No executable expressions or general-purpose rule language. Conditions are Python.
- Policy validation rejects unknown keys, wrong rule order, missing rules, non-integer thresholds.
- Evidence aggregation and flag semantics follow the approved rules in EvidenceSummary docstring.
- Sorting: actionable P1→P4 first by detected_at asc, asset_id lex, finding_id lex; excluded last.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from triageledger.models import (
    DECISION_SCHEMA_VERSION,
    REQUIRED_RULE_SEQUENCE,
    Applicability,
    Asset,
    BusinessCriticality,
    Decision,
    EvidenceSummary,
    ExploitationStatus,
    Finding,
    InternetExposure,
    PolicyConfig,
    Severity,
    ThreatEvidence,
)

# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------

_REQUIRED_POLICY_KEYS = frozenset(
    {
        "policy_id",
        "version",
        "description",
        "context_freshness_days",
        "evidence_freshness_days",
        "rules",
    }
)


def load_policy(path: Path, raw_bytes: bytes | None = None) -> PolicyConfig:
    """Load and validate a policy JSON file. Raises ValueError on any failure.

    If raw_bytes is provided it is decoded and used as the file content; the
    file is not re-read. This ensures the same snapshot is used for policy
    loading and for provenance hashing in the caller.

    Validation rules:
    - Must be a JSON object with exactly the required keys (no unknown keys).
    - policy_id and version must be non-empty strings.
    - context_freshness_days and evidence_freshness_days must be positive integers (not booleans).
    - rules must be exactly REQUIRED_RULE_SEQUENCE in order.
    """
    if raw_bytes is not None:
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Cannot decode policy file {path}: not valid UTF-8") from exc
    else:
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Cannot decode policy file {path}: not valid UTF-8") from exc
        except OSError as exc:
            raise ValueError(f"Cannot read policy file {path}: {exc}") from exc

    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Policy file {path} is not valid JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("Policy must be a JSON object at the top level")

    unknown = set(data.keys()) - _REQUIRED_POLICY_KEYS
    if unknown:
        raise ValueError("Unknown keys present in policy")

    missing = _REQUIRED_POLICY_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"Missing required keys in policy: {sorted(missing)}")

    policy_id = data["policy_id"]
    if not isinstance(policy_id, str) or not policy_id:
        raise ValueError("policy_id must be a non-empty string")

    version = data["version"]
    if not isinstance(version, str) or not version:
        raise ValueError("version must be a non-empty string")

    description = data["description"]
    if not isinstance(description, str):
        raise ValueError("description must be a string")

    for key in ("context_freshness_days", "evidence_freshness_days"):
        val = data[key]
        if isinstance(val, bool):  # bool subclasses int; reject it explicitly
            raise ValueError(f"{key} must be a positive integer, not a boolean")
        if not isinstance(val, int) or val <= 0:
            raise ValueError(f"{key} must be a positive integer")

    rules = data["rules"]
    if not isinstance(rules, list):
        raise ValueError("rules must be a JSON array")

    if tuple(rules) != REQUIRED_RULE_SEQUENCE:
        raise ValueError(f"rules must be exactly {list(REQUIRED_RULE_SEQUENCE)} in order")

    return PolicyConfig(
        policy_id=policy_id,
        version=version,
        description=description,
        context_freshness_days=data["context_freshness_days"],
        evidence_freshness_days=data["evidence_freshness_days"],
        rules=tuple(rules),
    )


# ---------------------------------------------------------------------------
# Evidence aggregation
# ---------------------------------------------------------------------------


def _is_fresh(age_seconds: float, freshness_days: int) -> bool:
    """Age <= threshold is fresh (exactly at boundary counts as fresh)."""
    return age_seconds <= freshness_days * 24 * 3600


def _validate_as_of(as_of: datetime) -> datetime:
    """Validate and normalize as_of to UTC. Raises TypeError/ValueError on bad input."""
    if not isinstance(as_of, datetime):
        raise TypeError(f"as_of must be a datetime, got {type(as_of).__name__!r}")
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware (tzinfo required)")
    return as_of.astimezone(UTC)


def aggregate_evidence(
    evidence: list[ThreatEvidence],
    as_of: datetime,
    evidence_freshness_days: int,
) -> dict[str, EvidenceSummary]:
    """Group evidence by vulnerability_id and compute effective exploitation and flags.

    Pure function; no I/O. as_of must be a timezone-aware datetime; it is normalized to UTC.

    Approved aggregation rules (applied in order, first match wins):
    1. Any fresh active evidence → effective = active.
    2. Otherwise any stale active evidence → effective = unknown.
    3. Otherwise any fresh not_observed evidence → effective = not_observed.
    4. Otherwise → effective = unknown.

    Flag definitions:
    - threat_unknown: effective_exploitation is unknown.
    - threat_stale: any evidence row is stale.
    - historical_active: any active evidence row is stale (set even when fresh active also exists).
    - conflicting_threat_evidence: both active and not_observed statuses present (any freshness).
    """
    as_of = _validate_as_of(as_of)
    groups: dict[str, list[ThreatEvidence]] = {}
    for e in evidence:
        groups.setdefault(e.vulnerability_id, []).append(e)

    result: dict[str, EvidenceSummary] = {}
    for vuln_id, rows in groups.items():
        ages = {r.evidence_id: (as_of - r.observed_at).total_seconds() for r in rows}

        def fresh(r: ThreatEvidence) -> bool:
            return _is_fresh(ages[r.evidence_id], evidence_freshness_days)

        fresh_active = [
            r for r in rows if fresh(r) and r.exploitation_status == ExploitationStatus.ACTIVE
        ]
        stale_active = [
            r for r in rows if not fresh(r) and r.exploitation_status == ExploitationStatus.ACTIVE
        ]
        fresh_not_observed = [
            r for r in rows if fresh(r) and r.exploitation_status == ExploitationStatus.NOT_OBSERVED
        ]
        stale_rows = [r for r in rows if not fresh(r)]

        all_statuses = {r.exploitation_status for r in rows}

        if fresh_active:
            effective = ExploitationStatus.ACTIVE
        elif stale_active:
            effective = ExploitationStatus.UNKNOWN
        elif fresh_not_observed:
            effective = ExploitationStatus.NOT_OBSERVED
        else:
            effective = ExploitationStatus.UNKNOWN

        result[vuln_id] = EvidenceSummary(
            vulnerability_id=vuln_id,
            effective_exploitation=effective,
            evidence_ids=tuple(r.evidence_id for r in rows),
            threat_unknown=effective == ExploitationStatus.UNKNOWN,
            threat_stale=bool(stale_rows),
            historical_active=bool(stale_active),
            conflicting_threat_evidence=(
                ExploitationStatus.ACTIVE in all_statuses
                and ExploitationStatus.NOT_OBSERVED in all_statuses
            ),
        )

    return result


# ---------------------------------------------------------------------------
# Rule evaluator
# ---------------------------------------------------------------------------

# Explanation templates — produced from structured facts, not generated prose.
_EXPLANATIONS: dict[str, str] = {
    "EX-01": (
        "Applicability is not_affected per supplied data. "
        "Record retained for analyst validation; do not treat as verified remediation."
    ),
    "P-01": (
        "Active exploitation confirmed with confirmed applicability. "
        "Immediate analyst review of applicability, exposure, and remediation options required."
    ),
    "P-02": (
        "Internet-exposed critical asset with critical or high severity. "
        "Immediate analyst review of applicability, exposure, and remediation options required."
    ),
    "P-03": ("Critical severity or active exploitation present. Expedited investigation required."),
    "P-04": (
        "High severity on an internet-exposed or critical-business asset. "
        "Expedited investigation required."
    ),
    "P-05": "High or medium severity finding. Schedule for planned remediation review.",
    "P-06": (
        "Severity unknown: conservative P2 default applied. "
        "Expedited clarification of severity required."
    ),
    "P-07": "Low severity finding. Routine review.",
}

_NEXT_ACTIONS: dict[str | None, str] = {
    "P1": (
        "Urgent analyst review: confirm applicability, assess exposure, "
        "and evaluate remediation options."
    ),
    "P2": "Expedited investigation required.",
    "P3": "Schedule for planned remediation review.",
    "P4": "Routine review.",
    None: (
        "Retain supplied not_affected assertion for analyst validation. "
        "Do not treat as verified remediation."
    ),
}

_MISSING_OWNER_ACTION = " Assign owner team before scheduling remediation."

_PRIORITY_ORDER: dict[str, int] = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def evaluate(
    findings: list[Finding],
    assets: list[Asset],
    evidence: list[ThreatEvidence],
    policy: PolicyConfig,
    as_of: datetime,
) -> list[Decision]:
    """Evaluate all findings and return decisions sorted by priority and tie-breakers.

    Pure function except for reading policy fields. No I/O, no clock calls.
    as_of must be a timezone-aware datetime; it is normalized to UTC before evaluation.
    Raises TypeError for non-datetime values; ValueError for timezone-naive datetimes.

    Sort order:
    - Actionable (P1→P4) before excluded (not_affected / priority=None).
    - Within each group: detected_at ascending, then asset_id lexicographic,
      then finding_id lexicographic. No hidden tie-breaker.
    """
    as_of = _validate_as_of(as_of)
    asset_map: dict[str, Asset] = {a.asset_id: a for a in assets}
    evidence_summaries = aggregate_evidence(evidence, as_of, policy.evidence_freshness_days)

    decisions = [
        _evaluate_finding(f, asset_map, evidence_summaries, policy, as_of) for f in findings
    ]
    decisions.sort(key=_sort_key)
    return decisions


def _context_age_seconds(asset: Asset, as_of: datetime) -> float:
    return (as_of - asset.context_updated_at).total_seconds()


def _evaluate_finding(
    finding: Finding,
    asset_map: dict[str, Asset],
    evidence_summaries: dict[str, EvidenceSummary],
    policy: PolicyConfig,
    as_of: datetime,
) -> Decision:
    asset = asset_map.get(finding.asset_id)

    # --- Asset context ---
    if asset is None:
        asset_unmatched = True
        context_missing = True
        context_stale = False
        context_age_days: float | None = None
        owner_team: str | None = None
        owner_missing = False
        owner_unverified = False
        original_criticality: BusinessCriticality | None = None
        original_exposure: InternetExposure | None = None
        effective_criticality = BusinessCriticality.UNKNOWN
        effective_exposure = InternetExposure.UNKNOWN
    else:
        asset_unmatched = False
        context_missing = False
        age_s = _context_age_seconds(asset, as_of)
        context_age_days = age_s / (24 * 3600)
        context_stale = not _is_fresh(age_s, policy.context_freshness_days)
        owner_team = asset.owner_team
        owner_missing = asset.owner_missing
        # Stale context means the owner record is unverified, not erased.
        owner_unverified = context_stale
        original_criticality = asset.business_criticality
        original_exposure = asset.internet_exposure
        if context_stale:
            effective_criticality = BusinessCriticality.UNKNOWN
            effective_exposure = InternetExposure.UNKNOWN
        else:
            effective_criticality = asset.business_criticality
            effective_exposure = asset.internet_exposure

    # --- Evidence ---
    # No evidence lookup when vulnerability_id is absent (missing_vulnerability_id).
    if finding.missing_vulnerability_id or finding.vulnerability_id is None:
        evidence_summary: EvidenceSummary | None = None
        evidence_ids: tuple[str, ...] = ()
    else:
        evidence_summary = evidence_summaries.get(finding.vulnerability_id)
        evidence_ids = evidence_summary.evidence_ids if evidence_summary else ()

    effective_exploitation = (
        evidence_summary.effective_exploitation
        if evidence_summary is not None
        else ExploitationStatus.UNKNOWN
    )

    # --- Flags ---
    flags: set[str] = set()
    if owner_missing:
        flags.add("owner_missing")
    if owner_unverified:
        flags.add("owner_unverified")
    if asset_unmatched:
        flags.add("asset_unmatched")
    if context_missing:
        flags.add("context_missing")
    if context_stale:
        flags.add("context_stale")
    if effective_exposure == InternetExposure.UNKNOWN:
        flags.add("exposure_unknown")
    if effective_criticality == BusinessCriticality.UNKNOWN:
        flags.add("criticality_unknown")
    if finding.severity == Severity.UNKNOWN:
        flags.add("severity_unknown")
    if finding.applicability == Applicability.UNCONFIRMED:
        flags.add("applicability_unconfirmed")
    if finding.missing_vulnerability_id:
        flags.add("missing_vulnerability_id")
    if finding.possible_duplicate:
        flags.add("possible_duplicate")

    if evidence_summary is None:
        # No evidence rows found for this vulnerability (or no vuln_id to look up).
        flags.add("threat_unknown")
    else:
        if evidence_summary.threat_unknown:
            flags.add("threat_unknown")
        if evidence_summary.threat_stale:
            flags.add("threat_stale")
        if evidence_summary.historical_active:
            flags.add("historical_active")
        if evidence_summary.conflicting_threat_evidence:
            flags.add("conflicting_threat_evidence")

    # --- Rule evaluation (first match) ---
    rule_id, disposition, priority = _apply_rules(
        finding, effective_criticality, effective_exposure, effective_exploitation
    )

    # --- Next action (template; append owner supplement without reducing urgency) ---
    next_action = _NEXT_ACTIONS[priority]
    if owner_missing or owner_unverified:
        next_action += _MISSING_OWNER_ACTION

    # --- Supporting facts for traceability ---
    supporting_facts: dict[str, Any] = {
        "severity": str(finding.severity),
        "applicability": str(finding.applicability),
        "effective_criticality": str(effective_criticality),
        "effective_exposure": str(effective_exposure),
        "effective_exploitation": str(effective_exploitation),
        "original_criticality": (
            str(original_criticality) if original_criticality is not None else None
        ),
        "original_exposure": str(original_exposure) if original_exposure is not None else None,
        "context_age_days": round(context_age_days, 4) if context_age_days is not None else None,
        "evidence_ids": list(evidence_ids),
    }

    return Decision(
        schema_version=DECISION_SCHEMA_VERSION,
        finding_id=finding.finding_id,
        asset_id=finding.asset_id,
        vulnerability_id=finding.vulnerability_id,
        disposition=disposition,
        priority=priority,
        rule_id=rule_id,
        rule_version=policy.version,
        explanation=_EXPLANATIONS[rule_id],
        supporting_facts=supporting_facts,
        evidence_ids=evidence_ids,
        flags=frozenset(flags),
        owner_team=owner_team,
        next_action=next_action,
        as_of=as_of,
        context_age_days=context_age_days,
        effective_criticality=effective_criticality,
        effective_exposure=effective_exposure,
        effective_exploitation=effective_exploitation,
        original_criticality=original_criticality,
        original_exposure=original_exposure,
        detected_at=finding.detected_at,
    )


def _apply_rules(
    finding: Finding,
    effective_criticality: BusinessCriticality,
    effective_exposure: InternetExposure,
    effective_exploitation: ExploitationStatus,
) -> tuple[str, str, str | None]:
    """Return (rule_id, disposition, priority) for the first matching rule.

    Rules are evaluated in the order mandated by REQUIRED_RULE_SEQUENCE.
    A valid Severity enum guarantees one rule always matches.
    """
    sev = finding.severity
    app = finding.applicability

    # EX-01: not_affected regardless of everything else
    if app == Applicability.NOT_AFFECTED:
        return "EX-01", "not_affected", None

    # P-01: active exploitation + confirmed applicability
    if effective_exploitation == ExploitationStatus.ACTIVE and app == Applicability.CONFIRMED:
        return "P-01", "review_recommended", "P1"

    # P-02: exposed critical asset + critical/high severity
    if (
        effective_exposure == InternetExposure.EXPOSED
        and effective_criticality == BusinessCriticality.CRITICAL
        and sev in (Severity.CRITICAL, Severity.HIGH)
    ):
        return "P-02", "review_recommended", "P1"

    # P-03: critical severity OR active exploitation (catches unconfirmed-applicability active)
    if sev == Severity.CRITICAL or effective_exploitation == ExploitationStatus.ACTIVE:
        return "P-03", "review_recommended", "P2"

    # P-04: high severity on exposed or critical asset
    if sev == Severity.HIGH and (
        effective_exposure == InternetExposure.EXPOSED
        or effective_criticality == BusinessCriticality.CRITICAL
    ):
        return "P-04", "review_recommended", "P2"

    # P-05: high or medium severity
    if sev in (Severity.HIGH, Severity.MEDIUM):
        return "P-05", "review_recommended", "P3"

    # P-06: unknown severity — conservative P2 default
    if sev == Severity.UNKNOWN:
        return "P-06", "review_recommended", "P2"

    # P-07: low severity
    if sev == Severity.LOW:
        return "P-07", "review_recommended", "P4"

    raise ValueError(  # pragma: no cover — all valid Severity values are handled above
        f"No rule matched for finding {finding.finding_id!r} with severity={sev!r}"
    )


def _sort_key(d: Decision) -> tuple:
    """Sort key: actionable (P1..P4) before excluded, then detected_at, asset_id, finding_id."""
    is_excluded = 1 if d.priority is None else 0
    priority_order = _PRIORITY_ORDER.get(d.priority, 0) if d.priority is not None else 0
    return (is_excluded, priority_order, d.detected_at, d.asset_id, d.finding_id)

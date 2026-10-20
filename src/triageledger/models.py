"""Typed dataclasses and enums for TriageLedger v1.

These are pure data containers with field-level validation primitives.
No filesystem, network, or clock calls here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class BusinessCriticality(StrEnum):
    CRITICAL = "critical"
    STANDARD = "standard"
    UNKNOWN = "unknown"


class InternetExposure(StrEnum):
    EXPOSED = "exposed"
    NOT_EXPOSED = "not_exposed"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Applicability(StrEnum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"
    NOT_AFFECTED = "not_affected"


class ExploitationStatus(StrEnum):
    ACTIVE = "active"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Parsed row dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    asset_id: str
    display_name: str
    business_criticality: BusinessCriticality
    internet_exposure: InternetExposure
    owner_team: str | None  # None means blank / owner_missing
    context_updated_at: datetime
    # Diagnostic flags set during ingestion
    owner_missing: bool = False

    def __post_init__(self) -> None:
        if not self.asset_id:
            raise ValueError("asset_id must not be empty")
        if not self.display_name:
            raise ValueError("display_name must not be empty")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    asset_id: str
    vulnerability_id: str | None  # None means blank
    severity: Severity
    applicability: Applicability
    detected_at: datetime
    description: str | None
    # Diagnostic flags set during ingestion
    missing_vulnerability_id: bool = False
    possible_duplicate: bool = False

    def __post_init__(self) -> None:
        if not self.finding_id:
            raise ValueError("finding_id must not be empty")
        if not self.asset_id:
            raise ValueError("asset_id must not be empty")


@dataclass(frozen=True)
class ThreatEvidence:
    evidence_id: str
    vulnerability_id: str
    exploitation_status: ExploitationStatus
    source_label: str
    source_reference: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id must not be empty")
        if not self.vulnerability_id:
            raise ValueError("vulnerability_id must not be empty")
        if not self.source_label:
            raise ValueError("source_label must not be empty")
        if not self.source_reference:
            raise ValueError("source_reference must not be empty")


# ---------------------------------------------------------------------------
# Ingest result container
# ---------------------------------------------------------------------------


@dataclass
class ParseDiagnostic:
    """A single row-level or file-level diagnostic message."""

    level: str  # "fatal", "error", "warning", "info"
    source_file: str
    row_number: int | None  # None for file-level
    field_name: str | None
    message: str
    raw_value: str | None = None


@dataclass
class IngestResult:
    """Outcome of parsing one CSV file."""

    source_file: str
    total_rows_read: int = 0
    accepted: int = 0
    collapsed_duplicates: int = 0  # identical rows merged
    diagnostics: list[ParseDiagnostic] = field(default_factory=list)
    fatal: bool = False

    # Populated for each file type
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    threat_evidence: list[ThreatEvidence] = field(default_factory=list)

    def add_diagnostic(
        self,
        level: str,
        row_number: int | None,
        field_name: str | None,
        message: str,
        raw_value: str | None = None,
    ) -> None:
        self.diagnostics.append(
            ParseDiagnostic(
                level=level,
                source_file=self.source_file,
                row_number=row_number,
                field_name=field_name,
                message=message,
                raw_value=raw_value,
            )
        )


# ---------------------------------------------------------------------------
# Policy configuration
# ---------------------------------------------------------------------------

# Required rule sequence for demo-policy-v1. Validation enforces this exactly.
REQUIRED_RULE_SEQUENCE: tuple[str, ...] = (
    "EX-01",
    "P-01",
    "P-02",
    "P-03",
    "P-04",
    "P-05",
    "P-06",
    "P-07",
)


@dataclass(frozen=True)
class PolicyConfig:
    """Validated policy configuration loaded from JSON.

    Approved interpretations documented here for traceability:
    - context_freshness_days: age > threshold means stale; exactly at threshold is fresh.
    - evidence_freshness_days: same boundary semantics.
    - rules: must match REQUIRED_RULE_SEQUENCE exactly; no substitutions in v1.
    - Freshness thresholds must be positive integers; booleans are rejected.
    """

    policy_id: str
    version: str
    description: str
    context_freshness_days: int
    evidence_freshness_days: int
    rules: tuple[str, ...]


# ---------------------------------------------------------------------------
# Evidence aggregation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceSummary:
    """Aggregated evidence state for a single vulnerability_id.

    Approved exploitation aggregation rules (from M2 approval):
    1. Any fresh active evidence → effective_exploitation = active.
    2. Otherwise any stale active evidence → unknown (even if fresh not_observed exists).
    3. Otherwise any fresh not_observed evidence → not_observed.
    4. Otherwise → unknown.

    Flag semantics (from M2 approval):
    - threat_unknown: effective_exploitation is unknown.
    - threat_stale: any supplied evidence row is stale.
    - historical_active: any supplied active evidence row is stale (coexists with active effective).
    - conflicting_threat_evidence: evidence contains both active and not_observed statuses,
      regardless of freshness. Requests analyst interpretation; not a source-quality judgment.
    """

    vulnerability_id: str
    effective_exploitation: ExploitationStatus
    evidence_ids: tuple[str, ...]  # all evidence IDs for this vulnerability
    threat_unknown: bool
    threat_stale: bool
    historical_active: bool
    conflicting_threat_evidence: bool


# ---------------------------------------------------------------------------
# Decision (structured output per finding)
# ---------------------------------------------------------------------------

DECISION_SCHEMA_VERSION = "1.0"


@dataclass
class Decision:
    """Structured triage decision for a single finding.

    Produced by the policy evaluator. M3 rendering reads these fields directly.
    supporting_facts is a plain dict of string-keyed scalar/list values for
    template-driven explanations; do not execute its contents.
    """

    schema_version: str
    finding_id: str
    asset_id: str
    vulnerability_id: str | None
    disposition: str  # "review_recommended" | "not_affected"
    priority: str | None  # "P1" | "P2" | "P3" | "P4" | None (excluded)
    rule_id: str  # e.g. "EX-01", "P-01" … "P-07"
    rule_version: str  # policy.version
    explanation: str  # template-derived; never generated prose
    supporting_facts: dict[str, Any]
    evidence_ids: tuple[str, ...]
    flags: frozenset[str]
    owner_team: str | None
    next_action: str
    as_of: datetime
    context_age_days: float | None  # None when asset is unmatched
    # Effective values used for rule evaluation
    effective_criticality: BusinessCriticality
    effective_exposure: InternetExposure
    effective_exploitation: ExploitationStatus
    # Original values from the asset row (None when asset is unmatched)
    original_criticality: BusinessCriticality | None
    original_exposure: InternetExposure | None
    detected_at: datetime

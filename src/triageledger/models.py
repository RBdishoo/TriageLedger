"""Typed dataclasses and enums for TriageLedger v1.

These are pure data containers with field-level validation primitives.
No filesystem, network, or clock calls here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

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

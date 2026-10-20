"""Unit tests for triageledger.ingest.

All inputs are constructed in-memory via tmp_path fixtures.
No network access. as_of = 2026-10-19T00:00:00Z throughout unless noted.
"""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime
from pathlib import Path

from triageledger.ingest import (
    MAX_DATA_ROWS,
    MAX_FIELD_BYTES,
    MAX_FILE_BYTES,
    parse_assets,
    parse_findings,
    parse_threat_evidence,
)
from triageledger.models import (
    Applicability,
    BusinessCriticality,
    ExploitationStatus,
    InternetExposure,
    Severity,
)

AS_OF = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# assets — happy path
# ---------------------------------------------------------------------------


def test_parse_assets_valid(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha Server,critical,exposed,team-a,2026-10-01T00:00:00Z
        A-002,Beta DB,standard,not_exposed,,2026-10-10T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 2
    assert result.collapsed_duplicates == 0
    a1, a2 = result.assets
    assert a1.asset_id == "A-001"
    assert a1.business_criticality == BusinessCriticality.CRITICAL
    assert a1.internet_exposure == InternetExposure.EXPOSED
    assert a1.owner_team == "team-a"
    assert not a1.owner_missing
    assert a2.owner_team is None
    assert a2.owner_missing


def test_parse_assets_identical_duplicate_collapsed(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 1
    assert result.collapsed_duplicates == 1
    assert any("collapsed" in d.message for d in result.diagnostics)


def test_parse_assets_conflicting_duplicate_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-001,DIFFERENT,standard,not_exposed,,2026-10-02T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("conflicting" in d.message for d in result.diagnostics)


def test_parse_assets_invalid_enum_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,NOTVALID,exposed,ops,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("business_criticality" in d.message for d in result.diagnostics)


def test_parse_assets_future_timestamp_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2027-01-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("after as-of" in d.message for d in result.diagnostics)


def test_parse_assets_non_utc_timestamp_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("must end with Z" in d.message for d in result.diagnostics)


def test_parse_assets_blank_asset_id_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        ,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal


def test_parse_assets_missing_column_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,context_updated_at
        A-001,Alpha,critical,exposed,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("missing required columns" in d.message for d in result.diagnostics)


def test_parse_assets_unexpected_column_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at,extra_col
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z,oops
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("unexpected columns" in d.message for d in result.diagnostics)


def test_parse_assets_duplicate_header_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("duplicate column" in d.message for d in result.diagnostics)


def test_parse_assets_nul_bytes_fatal(tmp_path: Path) -> None:
    p = tmp_path / "assets.csv"
    cols = (
        "asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at"  # noqa: E501
    )
    header = cols + "\n"
    p.write_bytes((header + "A-001\x00,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z\n").encode())
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("NUL" in d.message for d in result.diagnostics)


def test_parse_assets_file_exactly_at_limit_accepted(tmp_path: Path, monkeypatch) -> None:
    """A file of exactly MAX_FILE_BYTES bytes must be accepted (limit uses >, not >=).

    Uses monkeypatch to set a small, arithmetically convenient limit rather than
    trying to build a 10 MiB valid CSV file in a unit test.
    """
    # Header (92 bytes) + 2 rows (54 bytes each) = 200 bytes exactly.
    cols = (
        "asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at"  # noqa: E501
    )
    header = cols + "\n"
    row = "A-{:03d},Alpha,critical,exposed,ops,2026-10-01T00:00:00Z\n"
    content = (header + row.format(1) + row.format(2)).encode("utf-8")
    small_limit = len(content)  # exactly the real byte count of this valid file
    monkeypatch.setattr("triageledger.ingest.MAX_FILE_BYTES", small_limit)
    p = tmp_path / "assets.csv"
    p.write_bytes(content)
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 2


def test_parse_assets_file_too_large_fatal(tmp_path: Path) -> None:
    """Oversized file is rejected before any CSV parsing; no data records returned."""
    p = tmp_path / "assets.csv"
    p.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("exceeds limit" in d.message for d in result.diagnostics)
    # Rejected at file-read stage: no rows were parsed
    assert result.total_rows_read == 0
    assert result.assets == []
    assert result.accepted == 0


def test_parse_assets_unicode_valid(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Ünïcödé Server,critical,exposed,team,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.assets[0].display_name == "Ünïcödé Server"


# ---------------------------------------------------------------------------
# findings — key paths
# ---------------------------------------------------------------------------


def test_parse_findings_valid(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-001,high,confirmed,2026-10-05T00:00:00Z,RCE vulnerability
        F-002,A-002,,medium,unconfirmed,2026-10-06T00:00:00Z,
        """,
    )
    result = parse_findings(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 2
    f1, f2 = result.findings
    assert f1.severity == Severity.HIGH
    assert f1.applicability == Applicability.CONFIRMED
    assert not f1.missing_vulnerability_id
    assert f2.vulnerability_id is None
    assert f2.missing_vulnerability_id
    assert f2.description is None


def test_parse_findings_possible_duplicate_flagged(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-001,high,confirmed,2026-10-05T00:00:00Z,First
        F-002,A-001,SYN-001,high,confirmed,2026-10-06T00:00:00Z,Second different ID
        """,
    )
    result = parse_findings(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 2
    assert result.findings[1].possible_duplicate
    assert any("possible_duplicate" in d.message for d in result.diagnostics)


def test_parse_findings_not_affected_accepted(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-007,critical,not_affected,2026-10-09T00:00:00Z,Vendor says no
        """,
    )
    result = parse_findings(p, AS_OF)
    assert not result.fatal
    assert result.findings[0].applicability == Applicability.NOT_AFFECTED


def test_parse_findings_conflicting_duplicate_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-001,high,confirmed,2026-10-05T00:00:00Z,First
        F-001,A-001,SYN-001,critical,confirmed,2026-10-05T00:00:00Z,Conflicting severity
        """,
    )
    result = parse_findings(p, AS_OF)
    assert result.fatal


def test_parse_findings_unmatched_asset_retained(tmp_path: Path) -> None:
    """An unknown asset_id is retained, not dropped — matching happens in M2."""
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-016,GHOST-999,SYN-012,high,confirmed,2026-10-17T00:00:00Z,No asset record
        """,
    )
    result = parse_findings(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 1
    assert result.findings[0].asset_id == "GHOST-999"


# ---------------------------------------------------------------------------
# threat_evidence — key paths
# ---------------------------------------------------------------------------


def test_parse_threat_evidence_valid(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "threat_evidence.csv",
        """\
        evidence_id,vulnerability_id,exploitation_status,source_label,source_reference,observed_at
        E-001,SYN-001,active,Synthetic A,synthetic://a/SYN-001,2026-10-17T00:00:00Z
        E-002,SYN-001,not_observed,Synthetic B,synthetic://b/SYN-001,2026-10-18T00:00:00Z
        """,
    )
    result = parse_threat_evidence(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 2
    assert result.threat_evidence[0].exploitation_status == ExploitationStatus.ACTIVE
    assert result.threat_evidence[1].exploitation_status == ExploitationStatus.NOT_OBSERVED


def test_parse_threat_evidence_identical_dup_collapsed(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "threat_evidence.csv",
        """\
        evidence_id,vulnerability_id,exploitation_status,source_label,source_reference,observed_at
        E-001,SYN-001,active,Synthetic A,synthetic://a,2026-10-17T00:00:00Z
        E-001,SYN-001,active,Synthetic A,synthetic://a,2026-10-17T00:00:00Z
        """,
    )
    result = parse_threat_evidence(p, AS_OF)
    assert not result.fatal
    assert result.accepted == 1
    assert result.collapsed_duplicates == 1


def test_parse_threat_evidence_conflicting_dup_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "threat_evidence.csv",
        """\
        evidence_id,vulnerability_id,exploitation_status,source_label,source_reference,observed_at
        E-001,SYN-001,active,Synthetic A,synthetic://a,2026-10-17T00:00:00Z
        E-001,SYN-001,not_observed,Synthetic A,synthetic://a,2026-10-17T00:00:00Z
        """,
    )
    result = parse_threat_evidence(p, AS_OF)
    assert result.fatal


def test_parse_threat_evidence_blank_source_label_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "threat_evidence.csv",
        """\
        evidence_id,vulnerability_id,exploitation_status,source_label,source_reference,observed_at
        E-001,SYN-001,active,,synthetic://a,2026-10-17T00:00:00Z
        """,
    )
    result = parse_threat_evidence(p, AS_OF)
    assert result.fatal
    assert any("source_label" in d.message for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Timestamp boundary: exactly 30-day context freshness boundary
# The freshness evaluation is in policy (M2), but ingestion must accept
# timestamps at or before as-of. These tests confirm as-of boundary.
# ---------------------------------------------------------------------------


def test_timestamp_exactly_at_as_of_accepted(tmp_path: Path) -> None:
    """Timestamp equal to as-of is not after as-of — must be accepted."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-19T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal


def test_timestamp_one_second_after_as_of_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-19T00:00:01Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal


# ---------------------------------------------------------------------------
# Row count limit
# ---------------------------------------------------------------------------


def test_row_count_exactly_at_limit_accepted(tmp_path: Path, monkeypatch) -> None:
    """Exactly the configured row limit is accepted (check uses >, not >=)."""
    small_limit = 3
    monkeypatch.setattr("triageledger.ingest.MAX_DATA_ROWS", small_limit)
    cols = (
        "asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at"  # noqa: E501
    )
    lines = [cols]
    for i in range(small_limit):  # exactly 3 data rows
        lines.append(f"A-{i:03d},Name {i},standard,not_exposed,team,2026-10-01T00:00:00Z")
    p = tmp_path / "assets.csv"
    p.write_text("\n".join(lines), encoding="utf-8")
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.total_rows_read == small_limit
    assert result.accepted == small_limit


def test_row_count_limit(tmp_path: Path) -> None:
    cols = (
        "asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at"  # noqa: E501
    )
    lines = [cols]
    for i in range(MAX_DATA_ROWS + 1):
        lines.append(f"A-{i:06d},Name {i},standard,not_exposed,team,2026-10-01T00:00:00Z")
    p = tmp_path / "assets.csv"
    p.write_text("\n".join(lines), encoding="utf-8")
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any(str(MAX_DATA_ROWS) in d.message for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Short row (fewer fields than header) — strict structural width check
# ---------------------------------------------------------------------------


def test_parse_assets_short_row_fatal(tmp_path: Path) -> None:
    """A data row with fewer fields than the header is fatal even if the
    missing column is optional (owner_team). Present-but-empty is allowed;
    structurally absent is not."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    # No records must be accessible after a fatal result
    assert result.assets == []
    assert result.accepted == 0


def test_parse_assets_optional_field_present_but_empty_accepted(tmp_path: Path) -> None:
    """owner_team present-but-empty (adjacent commas) must be accepted as owner_missing."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.assets[0].owner_missing


def test_parse_assets_extra_wide_row_fatal(tmp_path: Path) -> None:
    """A row with more fields than the header is fatal."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z,extra_field
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("more fields" in d.message for d in result.diagnostics)
    assert result.assets == []


def test_parse_findings_short_row_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001
        """,
    )
    result = parse_findings(p, AS_OF)
    assert result.fatal
    assert result.findings == []
    assert result.accepted == 0


# ---------------------------------------------------------------------------
# Blank required timestamp fields
# ---------------------------------------------------------------------------


def test_parse_findings_blank_detected_at_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-001,high,confirmed,,RCE
        """,
    )
    result = parse_findings(p, AS_OF)
    assert result.fatal
    assert any("detected_at" in d.field_name for d in result.diagnostics if d.field_name)


def test_parse_threat_evidence_blank_observed_at_fatal(tmp_path: Path) -> None:
    p = write(
        tmp_path,
        "threat_evidence.csv",
        """\
        evidence_id,vulnerability_id,exploitation_status,source_label,source_reference,observed_at
        E-001,SYN-001,active,Synthetic A,synthetic://a,
        """,
    )
    result = parse_threat_evidence(p, AS_OF)
    assert result.fatal
    assert any("observed_at" in d.field_name for d in result.diagnostics if d.field_name)


# ---------------------------------------------------------------------------
# Field length limit — at-limit accepted, over-limit fatal
# ---------------------------------------------------------------------------


def test_field_length_at_limit_accepted(tmp_path: Path) -> None:
    """A field of exactly MAX_FIELD_BYTES bytes must be accepted (boundary: > not >=)."""
    exact_name = "X" * MAX_FIELD_BYTES  # each char is 1 UTF-8 byte
    p = write(
        tmp_path,
        "assets.csv",
        f"asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at\n"
        f"A-001,{exact_name},critical,exposed,ops,2026-10-01T00:00:00Z\n",
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal


def test_field_length_limit_fatal(tmp_path: Path) -> None:
    long_name = "X" * (MAX_FIELD_BYTES + 1)
    p = write(
        tmp_path,
        "assets.csv",
        f"asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at\n"
        f"A-001,{long_name},critical,exposed,ops,2026-10-01T00:00:00Z\n",
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert any("byte limit" in d.message for d in result.diagnostics)


# ---------------------------------------------------------------------------
# Fatal-boundary: records must not be accessible after a fatal result
# ---------------------------------------------------------------------------


def test_fatal_mid_parse_clears_prior_records(tmp_path: Path) -> None:
    """Two valid rows followed by a conflicting duplicate (row 3).

    _fail() clears records and sets accepted=0. The count semantics are:
    - accepted = 0 (cleared; NOT the count of rows before the error)
    - total_rows_read = 3 (rows the loop reached before failing; not cleared)
    - collapsed_duplicates = 0 (no identical duplicates were seen)
    The successful-load invariant (accepted == len(assets)) does NOT apply to
    fatal results; callers must check result.fatal first.
    """
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-002,Beta,standard,not_exposed,ops,2026-10-01T00:00:00Z
        A-001,CONFLICT,standard,not_exposed,,2026-10-02T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    # Records cleared — cannot be consumed via normal successful-load path
    assert result.assets == []
    assert result.accepted == 0
    # total_rows_read reflects how far parsing reached (3 data rows touched)
    assert result.total_rows_read == 3
    # Diagnostics still accessible for reporting
    assert any("conflicting" in d.message for d in result.diagnostics)


def test_fatal_findings_mid_parse_clears_records(tmp_path: Path) -> None:
    """Same contract for findings: conflicting ID on row 3 clears rows 1–2."""
    p = write(
        tmp_path,
        "findings.csv",
        """\
        finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description
        F-001,A-001,SYN-001,high,confirmed,2026-10-05T00:00:00Z,row one
        F-002,A-001,SYN-002,medium,confirmed,2026-10-06T00:00:00Z,row two
        F-002,A-001,SYN-002,critical,confirmed,2026-10-06T00:00:00Z,conflicting row
        """,
    )
    result = parse_findings(p, AS_OF)
    assert result.fatal
    assert result.findings == []
    assert result.accepted == 0


# ---------------------------------------------------------------------------
# Reconciliation count invariants
# ---------------------------------------------------------------------------


def test_reconciliation_valid_rows(tmp_path: Path) -> None:
    """accepted == len(assets) and collapsed_duplicates == 0 for a clean file."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-002,Beta,standard,not_exposed,,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.total_rows_read == 2
    assert result.accepted == 2
    assert result.collapsed_duplicates == 0
    assert result.accepted == len(result.assets)


def test_reconciliation_with_identical_duplicate(tmp_path: Path) -> None:
    """total_rows_read == accepted + collapsed_duplicates for non-fatal file."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-002,Beta,standard,not_exposed,,2026-10-01T00:00:00Z
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert not result.fatal
    assert result.total_rows_read == 3
    assert result.accepted == 2
    assert result.collapsed_duplicates == 1
    assert result.total_rows_read == result.accepted + result.collapsed_duplicates
    assert result.accepted == len(result.assets)


def test_reconciliation_fatal_conflicting_id(tmp_path: Path) -> None:
    """On a conflicting-ID fatal, accepted and records are cleared;
    total_rows_read reflects how far parsing reached."""
    p = write(
        tmp_path,
        "assets.csv",
        """\
        asset_id,display_name,business_criticality,internet_exposure,owner_team,context_updated_at
        A-001,Alpha,critical,exposed,ops,2026-10-01T00:00:00Z
        A-001,CONFLICT,standard,not_exposed,,2026-10-02T00:00:00Z
        """,
    )
    result = parse_assets(p, AS_OF)
    assert result.fatal
    assert result.accepted == 0
    assert result.assets == []
    # total_rows_read counts rows the loop touched before failing (2 here)
    assert result.total_rows_read == 2

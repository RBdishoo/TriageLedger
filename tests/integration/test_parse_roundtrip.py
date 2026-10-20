"""Integration tests: load all three sample CSV files and check reconciliation counts.

These tests use the committed synthetic samples and a fixed as-of time.
They verify row counts, accepted counts, and that no fatal errors occur on
well-formed sample data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from triageledger.ingest import parse_assets, parse_findings, parse_threat_evidence

SAMPLES = Path(__file__).parent.parent.parent / "samples"
AS_OF = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)


def test_assets_loads_cleanly() -> None:
    result = parse_assets(SAMPLES / "assets.csv", AS_OF)
    fatal_msgs = [d.message for d in result.diagnostics if d.level == "fatal"]
    assert not result.fatal, f"Unexpected fatal: {fatal_msgs}"
    # 12 rows in the sample, no duplicates
    assert result.total_rows_read == 12
    assert result.accepted == 12
    assert result.collapsed_duplicates == 0


def test_assets_owner_missing_flagged() -> None:
    result = parse_assets(SAMPLES / "assets.csv", AS_OF)
    missing_owner = [a for a in result.assets if a.owner_missing]
    # A-006 and A-009 have blank owner_team
    assert len(missing_owner) == 2
    ids = {a.asset_id for a in missing_owner}
    assert ids == {"A-006", "A-009"}


def test_findings_loads_cleanly() -> None:
    result = parse_findings(SAMPLES / "findings.csv", AS_OF)
    fatal_msgs = [d.message for d in result.diagnostics if d.level == "fatal"]
    assert not result.fatal, f"Unexpected fatal: {fatal_msgs}"
    # 16 rows; F-007 is an identical duplicate of F-006 — NOT identical (different finding_id),
    # so both are accepted but possible_duplicate flagged
    assert result.total_rows_read == 16
    assert result.accepted == 16
    assert result.collapsed_duplicates == 0


def test_findings_possible_duplicate_flagged() -> None:
    result = parse_findings(SAMPLES / "findings.csv", AS_OF)
    possible_dups = [f for f in result.findings if f.possible_duplicate]
    # F-006 and F-007 share asset_id=A-005 + vulnerability_id=SYN-001
    assert len(possible_dups) == 1
    assert possible_dups[0].finding_id == "F-007"


def test_findings_blank_vuln_id_flagged() -> None:
    result = parse_findings(SAMPLES / "findings.csv", AS_OF)
    no_vuln = [f for f in result.findings if f.missing_vulnerability_id]
    # F-009 has blank vulnerability_id
    assert len(no_vuln) == 1
    assert no_vuln[0].finding_id == "F-009"


def test_findings_unmatched_asset_retained() -> None:
    result = parse_findings(SAMPLES / "findings.csv", AS_OF)
    unmatched = [f for f in result.findings if f.asset_id == "UNMATCHED-999"]
    assert len(unmatched) == 1


def test_threat_evidence_loads_cleanly() -> None:
    result = parse_threat_evidence(SAMPLES / "threat_evidence.csv", AS_OF)
    fatal_msgs = [d.message for d in result.diagnostics if d.level == "fatal"]
    assert not result.fatal, f"Unexpected fatal: {fatal_msgs}"
    assert result.total_rows_read == 9
    assert result.accepted == 9
    assert result.collapsed_duplicates == 0


def test_row_counts_reconcile() -> None:
    """Every accepted row must appear in the corresponding records list."""
    ar = parse_assets(SAMPLES / "assets.csv", AS_OF)
    fr = parse_findings(SAMPLES / "findings.csv", AS_OF)
    er = parse_threat_evidence(SAMPLES / "threat_evidence.csv", AS_OF)

    assert ar.accepted == len(ar.assets)
    assert fr.accepted == len(fr.findings)
    assert er.accepted == len(er.threat_evidence)

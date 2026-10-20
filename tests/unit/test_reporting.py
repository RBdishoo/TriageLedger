"""Unit tests for src/triageledger/reporting.py.

Coverage targets:
- CSV formula injection mitigation: all formula-trigger characters, leading whitespace,
  control characters, None values.
- Markdown injection mitigation: pipes, backslashes, HTML tags, links, backticks,
  embedded newlines, None.
- Decision serialization: sorted flags and evidence_ids, sorted supporting_facts
  evidence_ids, fixed field presence.
- Artifact writers: deterministic JSON, queue.csv, review.csv (flagged subset only),
  briefing.md (zero-count empty case, no fabricated entries, P1 table present when
  P1 decisions exist).
- Hashing: sha256_bytes correctness, compute_run_id changes when policy content
  changes even with the same policy_id/version.
- Manifest: artifact_hashes match actual written bytes.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from triageledger.models import (
    DECISION_SCHEMA_VERSION,
    REQUIRED_RULE_SEQUENCE,
    Applicability,
    Asset,
    BusinessCriticality,
    Decision,
    ExploitationStatus,
    Finding,
    IngestResult,
    InternetExposure,
    PolicyConfig,
    Severity,
)
from triageledger.reporting import (
    _cell,
    _escape_md,
    _sanitize_csv_cell,
    compute_run_id,
    sha256_bytes,
    sha256_file,
    write_briefing_md,
    write_decisions_json,
    write_diagnostics_json,
    write_manifest,
    write_queue_csv,
    write_review_csv,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AS_OF = datetime(2026, 10, 19, 0, 0, 0, tzinfo=UTC)

POLICY = PolicyConfig(
    policy_id="test-policy",
    version="0.1.0",
    description="Unit test policy",
    context_freshness_days=30,
    evidence_freshness_days=7,
    rules=REQUIRED_RULE_SEQUENCE,
)


def _asset(asset_id: str = "A-001") -> Asset:
    return Asset(
        asset_id=asset_id,
        display_name="Test Asset",
        business_criticality=BusinessCriticality.STANDARD,
        internet_exposure=InternetExposure.NOT_EXPOSED,
        owner_team="test-team",
        context_updated_at=AS_OF,
    )


def _finding(finding_id: str = "F-001", severity: Severity = Severity.LOW) -> Finding:
    return Finding(
        finding_id=finding_id,
        asset_id="A-001",
        vulnerability_id="SYN-001",
        severity=severity,
        applicability=Applicability.CONFIRMED,
        detected_at=AS_OF - timedelta(days=1),
        description=None,
    )


def _decision(
    finding_id: str = "F-001",
    priority: str | None = "P4",
    flags: frozenset[str] = frozenset(),
    owner_team: str | None = "test-team",
    evidence_ids: tuple[str, ...] = (),
) -> Decision:
    return Decision(
        schema_version=DECISION_SCHEMA_VERSION,
        finding_id=finding_id,
        asset_id="A-001",
        vulnerability_id="SYN-001",
        disposition="review_recommended" if priority else "not_affected",
        priority=priority,
        rule_id="P-07" if priority == "P4" else "EX-01",
        rule_version="0.1.0",
        explanation="Low severity finding. Routine review.",
        supporting_facts={
            "severity": "low",
            "applicability": "confirmed",
            "effective_criticality": "standard",
            "effective_exposure": "not_exposed",
            "effective_exploitation": "unknown",
            "original_criticality": "standard",
            "original_exposure": "not_exposed",
            "context_age_days": 0.0,
            "evidence_ids": list(evidence_ids),
        },
        evidence_ids=evidence_ids,
        flags=flags,
        owner_team=owner_team,
        next_action="Routine review.",
        as_of=AS_OF,
        context_age_days=0.0,
        effective_criticality=BusinessCriticality.STANDARD,
        effective_exposure=InternetExposure.NOT_EXPOSED,
        effective_exploitation=ExploitationStatus.UNKNOWN,
        original_criticality=BusinessCriticality.STANDARD,
        original_exposure=InternetExposure.NOT_EXPOSED,
        detected_at=AS_OF - timedelta(days=1),
    )


# ---------------------------------------------------------------------------
# _sanitize_csv_cell
# ---------------------------------------------------------------------------


class TestSanitizeCsvCell:
    def test_normal_text_unchanged(self) -> None:
        assert _sanitize_csv_cell("hello world") == "hello world"

    def test_equals_prefix_triggers_apostrophe(self) -> None:
        assert _sanitize_csv_cell("=SUM(A1:A10)") == "'=SUM(A1:A10)"

    def test_plus_prefix(self) -> None:
        assert _sanitize_csv_cell("+1") == "'+1"

    def test_minus_prefix(self) -> None:
        assert _sanitize_csv_cell("-1") == "'-1"

    def test_at_prefix(self) -> None:
        assert _sanitize_csv_cell("@SUM") == "'@SUM"

    def test_leading_whitespace_before_formula_char(self) -> None:
        # Leading whitespace followed by formula char must be mitigated.
        result = _sanitize_csv_cell("  =formula")
        assert result.startswith("'"), f"Expected apostrophe prefix, got: {result!r}"

    def test_leading_tab_before_formula_char(self) -> None:
        result = _sanitize_csv_cell("\t=formula")
        assert result.startswith("'")

    def test_plain_minus_in_middle_unchanged(self) -> None:
        assert _sanitize_csv_cell("a-b") == "a-b"

    def test_control_chars_replaced(self) -> None:
        # \x01 is a non-printable control char
        result = _sanitize_csv_cell("hello\x01world")
        assert "\x01" not in result
        assert "\ufffd" in result

    def test_null_byte_replaced(self) -> None:
        result = _sanitize_csv_cell("hello\x00world")
        assert "\x00" not in result
        assert "\ufffd" in result

    def test_tab_preserved(self) -> None:
        # Tab is a valid whitespace character; not replaced with replacement char.
        result = _sanitize_csv_cell("col1\tcol2")
        assert "\t" in result

    def test_newline_preserved(self) -> None:
        # Newlines are kept for csv module to handle via quoting.
        result = _sanitize_csv_cell("line1\nline2")
        assert "\n" in result

    def test_empty_string(self) -> None:
        assert _sanitize_csv_cell("") == ""

    def test_whitespace_only_no_prefix(self) -> None:
        assert _sanitize_csv_cell("   ") == "   "


class TestCell:
    def test_none_becomes_empty(self) -> None:
        assert _cell(None) == ""

    def test_integer_converted(self) -> None:
        assert _cell(42) == "42"

    def test_formula_string_prefixed(self) -> None:
        assert _cell('=HYPERLINK("evil")') == '\'=HYPERLINK("evil")'


# ---------------------------------------------------------------------------
# _escape_md
# ---------------------------------------------------------------------------


class TestEscapeMd:
    def test_none_returns_empty(self) -> None:
        assert _escape_md(None) == ""

    def test_pipe_escaped(self) -> None:
        result = _escape_md("col1|col2")
        assert r"\|" in result
        # No bare pipe remains (only the backslash-escaped form).
        assert "col1|col2" not in result

    def test_backslash_escaped(self) -> None:
        result = _escape_md("path\\to\\file")
        assert "\\\\" in result

    def test_backtick_escaped(self) -> None:
        result = _escape_md("`code`")
        assert r"\`" in result

    def test_html_open_tag_escaped(self) -> None:
        result = _escape_md("<script>alert(1)</script>")
        assert "<" not in result
        assert "&lt;" in result

    def test_html_close_tag_escaped(self) -> None:
        result = _escape_md("<b>bold</b>")
        assert ">" not in result
        assert "&gt;" in result

    def test_ampersand_escaped(self) -> None:
        result = _escape_md("R&D")
        assert "&amp;" in result

    def test_open_bracket_escaped_prevents_link(self) -> None:
        # [text](url) pattern would render as a link in Markdown.
        # Escaping [ as \[ prevents Markdown from treating it as a link.
        result = _escape_md("[click me](http://evil.example)")
        assert result.startswith(r"\["), f"Expected escaped bracket at start: {result!r}"

    def test_embedded_newline_normalized(self) -> None:
        result = _escape_md("line1\nline2")
        assert "\n" not in result
        assert "line1 line2" in result

    def test_embedded_crlf_normalized(self) -> None:
        result = _escape_md("line1\r\nline2")
        assert "\r" not in result
        assert "\n" not in result

    def test_embedded_cr_normalized(self) -> None:
        result = _escape_md("line1\rline2")
        assert "\r" not in result

    def test_plain_text_unchanged(self) -> None:
        result = _escape_md("plain text")
        assert result == "plain text"

    def test_combined_pipe_and_newline(self) -> None:
        # A pipe followed by a newline could inject a new table row.
        result = _escape_md("col1|col2\nnew row")
        # Pipe must be escaped (as \|).
        assert r"\|" in result
        # Newline must be removed (normalized to space).
        assert "\n" not in result


# ---------------------------------------------------------------------------
# Decision serialization
# ---------------------------------------------------------------------------


class TestDecisionToDict:
    """Test _decision_to_dict indirectly via write_decisions_json."""

    def test_flags_are_sorted(self, tmp_path: Path) -> None:
        d = _decision(flags=frozenset({"threat_unknown", "owner_missing", "context_stale"}))
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        doc = json.loads(p.read_text())
        flags = doc["decisions"][0]["flags"]
        assert flags == sorted(flags)

    def test_evidence_ids_are_sorted(self, tmp_path: Path) -> None:
        d = _decision(evidence_ids=("E-003", "E-001", "E-002"))
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        doc = json.loads(p.read_text())
        ev = doc["decisions"][0]["evidence_ids"]
        assert ev == ["E-001", "E-002", "E-003"]

    def test_supporting_facts_evidence_ids_sorted(self, tmp_path: Path) -> None:
        d = _decision(evidence_ids=("E-003", "E-001", "E-002"))
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        doc = json.loads(p.read_text())
        sf_ev = doc["decisions"][0]["supporting_facts"]["evidence_ids"]
        assert sf_ev == ["E-001", "E-002", "E-003"]

    def test_datetimes_are_iso_strings(self, tmp_path: Path) -> None:
        d = _decision()
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        doc = json.loads(p.read_text())
        dec = doc["decisions"][0]
        # Must be strings, not numeric timestamps.
        assert isinstance(dec["as_of"], str)
        assert isinstance(dec["detected_at"], str)
        # Must include timezone offset.
        assert "+00:00" in dec["as_of"]

    def test_none_fields_are_null(self, tmp_path: Path) -> None:
        d = _decision(owner_team=None)
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        doc = json.loads(p.read_text())
        assert doc["decisions"][0]["owner_team"] is None

    def test_file_ends_with_newline(self, tmp_path: Path) -> None:
        p = tmp_path / "decisions.json"
        write_decisions_json([], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        assert p.read_bytes().endswith(b"\n")

    def test_utf8_encoding(self, tmp_path: Path) -> None:
        d = _decision(owner_team="Ré\u00e9l")
        p = tmp_path / "decisions.json"
        write_decisions_json([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        raw = p.read_bytes()
        # Must decode as UTF-8 without error.
        decoded = raw.decode("utf-8")
        assert "Ré\u00e9l" in decoded


# ---------------------------------------------------------------------------
# write_queue_csv and write_review_csv
# ---------------------------------------------------------------------------


class TestQueueCsv:
    def test_all_decisions_present(self, tmp_path: Path) -> None:
        decisions = [_decision("F-001"), _decision("F-002"), _decision("F-003")]
        p = tmp_path / "queue.csv"
        write_queue_csv(decisions, p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        ids = [r["finding_id"] for r in rows]
        assert ids == ["F-001", "F-002", "F-003"]

    def test_formula_injection_in_owner_team(self, tmp_path: Path) -> None:
        d = _decision(owner_team="=SUM(A1)")
        p = tmp_path / "queue.csv"
        write_queue_csv([d], p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        cell = rows[0]["owner_team"]
        assert not cell.startswith("="), f"Formula not mitigated: {cell!r}"
        assert cell.startswith("'"), f"Expected apostrophe prefix: {cell!r}"

    def test_formula_injection_leading_whitespace(self, tmp_path: Path) -> None:
        d = _decision(owner_team="  -formula")
        p = tmp_path / "queue.csv"
        write_queue_csv([d], p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        cell = rows[0]["owner_team"]
        assert cell.startswith("'"), f"Expected apostrophe prefix: {cell!r}"

    def test_flags_column_is_sorted_space_separated(self, tmp_path: Path) -> None:
        d = _decision(flags=frozenset({"z_flag", "a_flag", "m_flag"}))
        p = tmp_path / "queue.csv"
        write_queue_csv([d], p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        assert rows[0]["flags"] == "a_flag m_flag z_flag"

    def test_empty_decisions_produces_header_only(self, tmp_path: Path) -> None:
        p = tmp_path / "queue.csv"
        write_queue_csv([], p)
        lines = p.read_text().strip().splitlines()
        assert len(lines) == 1  # header only
        assert "finding_id" in lines[0]

    def test_utf8_encoding(self, tmp_path: Path) -> None:
        p = tmp_path / "queue.csv"
        write_queue_csv([], p)
        p.read_bytes().decode("utf-8")  # must not raise

    def test_newline_is_lf(self, tmp_path: Path) -> None:
        p = tmp_path / "queue.csv"
        write_queue_csv([], p)
        assert b"\r\n" not in p.read_bytes()


class TestReviewCsv:
    def test_only_flagged_decisions_included(self, tmp_path: Path) -> None:
        clean = _decision("F-001", flags=frozenset())
        flagged = _decision("F-002", flags=frozenset({"threat_unknown"}))
        excluded_flagged = _decision("F-003", priority=None, flags=frozenset({"owner_missing"}))
        p = tmp_path / "review.csv"
        write_review_csv([clean, flagged, excluded_flagged], p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        ids = {r["finding_id"] for r in rows}
        assert "F-001" not in ids
        assert "F-002" in ids
        assert "F-003" in ids

    def test_excluded_with_no_flags_excluded_from_review(self, tmp_path: Path) -> None:
        excluded_clean = _decision("F-EX", priority=None, flags=frozenset())
        p = tmp_path / "review.csv"
        write_review_csv([excluded_clean], p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        assert len(rows) == 0

    def test_empty_when_no_flags(self, tmp_path: Path) -> None:
        decisions = [_decision("F-001"), _decision("F-002")]
        p = tmp_path / "review.csv"
        write_review_csv(decisions, p)
        rows = list(csv.DictReader(p.read_text().splitlines()))
        assert len(rows) == 0


# ---------------------------------------------------------------------------
# write_briefing_md
# ---------------------------------------------------------------------------


class TestBriefingMd:
    def test_empty_decisions_zero_count_no_fabricated_entries(self, tmp_path: Path) -> None:
        p = tmp_path / "briefing.md"
        write_briefing_md([], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        text = p.read_text()
        assert "| **Total** | **0** |" in text
        # No P1 table should appear when there are no P1 decisions.
        assert "## Top Actions" not in text
        # No fabricated finding IDs.
        assert "F-" not in text

    def test_p1_table_appears_with_p1_decisions(self, tmp_path: Path) -> None:
        d = Decision(
            schema_version=DECISION_SCHEMA_VERSION,
            finding_id="F-001",
            asset_id="A-001",
            vulnerability_id="SYN-001",
            disposition="review_recommended",
            priority="P1",
            rule_id="P-01",
            rule_version="0.1.0",
            explanation="Active exploitation.",
            supporting_facts={},
            evidence_ids=(),
            flags=frozenset(),
            owner_team="ops-team",
            next_action="Urgent review.",
            as_of=AS_OF,
            context_age_days=0.0,
            effective_criticality=BusinessCriticality.CRITICAL,
            effective_exposure=InternetExposure.EXPOSED,
            effective_exploitation=ExploitationStatus.ACTIVE,
            original_criticality=BusinessCriticality.CRITICAL,
            original_exposure=InternetExposure.EXPOSED,
            detected_at=AS_OF - timedelta(days=1),
        )
        p = tmp_path / "briefing.md"
        write_briefing_md([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        text = p.read_text()
        assert "## Top Actions (P1)" in text
        assert "F-001" in text

    def test_pipe_in_owner_team_escaped(self, tmp_path: Path) -> None:
        d = Decision(
            schema_version=DECISION_SCHEMA_VERSION,
            finding_id="F-001",
            asset_id="A-001",
            vulnerability_id="SYN-001",
            disposition="review_recommended",
            priority="P1",
            rule_id="P-01",
            rule_version="0.1.0",
            explanation="Active exploitation.",
            supporting_facts={},
            evidence_ids=(),
            flags=frozenset(),
            owner_team="team|admin",
            next_action="Urgent review.",
            as_of=AS_OF,
            context_age_days=0.0,
            effective_criticality=BusinessCriticality.CRITICAL,
            effective_exposure=InternetExposure.EXPOSED,
            effective_exploitation=ExploitationStatus.ACTIVE,
            original_criticality=BusinessCriticality.CRITICAL,
            original_exposure=InternetExposure.EXPOSED,
            detected_at=AS_OF - timedelta(days=1),
        )
        p = tmp_path / "briefing.md"
        write_briefing_md([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        text = p.read_text()
        # Raw pipe must not appear unescaped in the owner column value.
        # The table structure uses | as delimiters; count must not increase by 1
        # relative to expected. Simpler check: the raw string "team|admin" is not present.
        assert "team|admin" not in text
        assert r"team\|admin" in text

    def test_newline_in_owner_team_normalized(self, tmp_path: Path) -> None:
        d = Decision(
            schema_version=DECISION_SCHEMA_VERSION,
            finding_id="F-001",
            asset_id="A-001",
            vulnerability_id="SYN-001",
            disposition="review_recommended",
            priority="P1",
            rule_id="P-01",
            rule_version="0.1.0",
            explanation="Active exploitation.",
            supporting_facts={},
            evidence_ids=(),
            flags=frozenset(),
            owner_team="line1\nline2",
            next_action="Urgent review.",
            as_of=AS_OF,
            context_age_days=0.0,
            effective_criticality=BusinessCriticality.CRITICAL,
            effective_exposure=InternetExposure.EXPOSED,
            effective_exploitation=ExploitationStatus.ACTIVE,
            original_criticality=BusinessCriticality.CRITICAL,
            original_exposure=InternetExposure.EXPOSED,
            detected_at=AS_OF - timedelta(days=1),
        )
        p = tmp_path / "briefing.md"
        write_briefing_md([d], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        text = p.read_text()
        # "line1 line2" should appear (newline normalized to space).
        assert "line1 line2" in text

    def test_limitations_section_present(self, tmp_path: Path) -> None:
        p = tmp_path / "briefing.md"
        write_briefing_md([], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        assert "## Limitations" in p.read_text()

    def test_utf8_encoding(self, tmp_path: Path) -> None:
        p = tmp_path / "briefing.md"
        write_briefing_md([], run_id="rid", as_of=AS_OF, policy=POLICY, path=p)
        p.read_bytes().decode("utf-8")  # must not raise


# ---------------------------------------------------------------------------
# write_diagnostics_json
# ---------------------------------------------------------------------------


class TestDiagnosticsJson:
    def test_raw_value_not_present(self, tmp_path: Path) -> None:
        r = IngestResult(source_file="assets.csv")
        r.add_diagnostic("fatal", 2, "severity", "bad value", raw_value="--evil--")
        p = tmp_path / "diagnostics.json"
        write_diagnostics_json([r], run_id=None, as_of=AS_OF, path=p)
        text = p.read_text()
        assert "--evil--" not in text

    def test_fatal_flag_preserved(self, tmp_path: Path) -> None:
        r = IngestResult(source_file="assets.csv", fatal=True)
        p = tmp_path / "diagnostics.json"
        write_diagnostics_json([r], run_id=None, as_of=AS_OF, path=p)
        doc = json.loads(p.read_text())
        assert doc["files"][0]["fatal"] is True

    def test_run_id_none_when_fatal(self, tmp_path: Path) -> None:
        r = IngestResult(source_file="assets.csv")
        p = tmp_path / "diagnostics.json"
        write_diagnostics_json([r], run_id=None, as_of=AS_OF, path=p)
        doc = json.loads(p.read_text())
        assert doc["run_id"] is None

    def test_file_ends_with_newline(self, tmp_path: Path) -> None:
        r = IngestResult(source_file="assets.csv")
        p = tmp_path / "diagnostics.json"
        write_diagnostics_json([r], run_id=None, as_of=AS_OF, path=p)
        assert p.read_bytes().endswith(b"\n")


# ---------------------------------------------------------------------------
# Hashing and run identity
# ---------------------------------------------------------------------------


class TestHashing:
    def test_sha256_bytes_known_value(self) -> None:
        # SHA-256 of empty bytes is known.
        expected = hashlib.sha256(b"").hexdigest()
        assert sha256_bytes(b"") == expected

    def test_sha256_bytes_non_empty(self) -> None:
        data = b"hello"
        assert sha256_bytes(data) == hashlib.sha256(data).hexdigest()

    def test_sha256_file(self, tmp_path: Path) -> None:
        p = tmp_path / "f.bin"
        p.write_bytes(b"test content")
        assert sha256_file(p) == sha256_bytes(b"test content")

    def test_compute_run_id_deterministic(self) -> None:
        kwargs = dict(
            as_of=AS_OF,
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            policy_bytes=b"p",
            policy=POLICY,
        )
        r1 = compute_run_id(**kwargs)
        r2 = compute_run_id(**kwargs)
        assert r1 == r2

    def test_compute_run_id_changes_with_policy_content(self) -> None:
        """Changing policy_bytes with same policy_id/version must change run_id."""
        base = dict(
            as_of=AS_OF,
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            policy=POLICY,
        )
        r1 = compute_run_id(**base, policy_bytes=b"original policy content")
        r2 = compute_run_id(**base, policy_bytes=b"modified policy content")
        assert r1 != r2, "Policy content change must change run_id"

    def test_compute_run_id_changes_with_assets(self) -> None:
        base = dict(
            as_of=AS_OF,
            findings_bytes=b"f",
            evidence_bytes=b"e",
            policy_bytes=b"p",
            policy=POLICY,
        )
        r1 = compute_run_id(**base, assets_bytes=b"assets_v1")
        r2 = compute_run_id(**base, assets_bytes=b"assets_v2")
        assert r1 != r2

    def test_compute_run_id_changes_with_as_of(self) -> None:
        base = dict(
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            policy_bytes=b"p",
            policy=POLICY,
        )
        r1 = compute_run_id(**base, as_of=AS_OF)
        r2 = compute_run_id(**base, as_of=AS_OF + timedelta(seconds=1))
        assert r1 != r2

    def test_compute_run_id_is_hex_string(self) -> None:
        r = compute_run_id(
            as_of=AS_OF,
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            policy_bytes=b"p",
            policy=POLICY,
        )
        assert isinstance(r, str)
        int(r, 16)  # must be valid hex


# ---------------------------------------------------------------------------
# write_manifest
# ---------------------------------------------------------------------------


class TestWriteManifest:
    def test_artifact_hashes_match_actual_bytes(self, tmp_path: Path) -> None:
        # Write two small artifact files and check manifest hashes.
        dec_path = tmp_path / "decisions.json"
        diag_path = tmp_path / "diagnostics.json"
        dec_path.write_bytes(b'{"decisions": []}')
        diag_path.write_bytes(b'{"files": []}')

        artifact_paths = {
            "decisions.json": dec_path,
            "diagnostics.json": diag_path,
        }
        manifest_path = tmp_path / "manifest.json"
        write_manifest(
            run_id="test-run",
            as_of=AS_OF,
            policy=POLICY,
            policy_bytes=b"policy content",
            assets_bytes=b"assets content",
            findings_bytes=b"findings content",
            evidence_bytes=b"evidence content",
            counts={"findings_evaluated": 0},
            artifact_paths=artifact_paths,
            path=manifest_path,
        )

        doc = json.loads(manifest_path.read_text())
        for name, path in artifact_paths.items():
            expected = sha256_bytes(path.read_bytes())
            assert doc["artifact_hashes"][name] == expected, f"Hash mismatch for {name}"

    def test_manifest_not_self_hashed(self, tmp_path: Path) -> None:
        # manifest.json must NOT appear in artifact_hashes.
        manifest_path = tmp_path / "manifest.json"
        write_manifest(
            run_id="rid",
            as_of=AS_OF,
            policy=POLICY,
            policy_bytes=b"p",
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            counts={},
            artifact_paths={},
            path=manifest_path,
        )
        doc = json.loads(manifest_path.read_text())
        assert "manifest.json" not in doc["artifact_hashes"]

    def test_manifest_contains_required_fields(self, tmp_path: Path) -> None:
        manifest_path = tmp_path / "manifest.json"
        write_manifest(
            run_id="rid",
            as_of=AS_OF,
            policy=POLICY,
            policy_bytes=b"p",
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            counts={"findings_evaluated": 5},
            artifact_paths={},
            path=manifest_path,
        )
        doc = json.loads(manifest_path.read_text())
        for key in (
            "schema_version",
            "run_id",
            "as_of",
            "tool_version",
            "decision_schema_version",
            "policy_id",
            "policy_version",
            "counts",
            "input_hashes",
            "policy_sha256",
            "artifact_hashes",
        ):
            assert key in doc, f"Missing field: {key}"

    def test_manifest_file_ends_with_newline(self, tmp_path: Path) -> None:
        manifest_path = tmp_path / "manifest.json"
        write_manifest(
            run_id="rid",
            as_of=AS_OF,
            policy=POLICY,
            policy_bytes=b"p",
            assets_bytes=b"a",
            findings_bytes=b"f",
            evidence_bytes=b"e",
            counts={},
            artifact_paths={},
            path=manifest_path,
        )
        assert manifest_path.read_bytes().endswith(b"\n")

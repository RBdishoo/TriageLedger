"""Deterministic rendering and manifest generation for TriageLedger v1.

Responsibilities:
- Serialize Decision records to canonical JSON (fixed field order, sorted collections).
- Render spreadsheet-safe CSV with formula injection mitigation.
- Render Markdown briefing with injection escaping.
- Write structured diagnostics JSON (raw input values excluded from output).
- Compute SHA-256 hashes for artifact integrity and run identity.
- Generate manifest.json (written last; not hashed into itself).

No decision logic here. All policy decisions live in policy.py.

Injection-mitigation limitations:
- CSV: a leading-apostrophe prefix is applied to cells whose stripped content begins
  with a formula-trigger character (=, +, -, @). This reduces formula injection risk
  in common spreadsheet applications but is not a universal safety guarantee.
- Markdown: pipe, backslash, backtick, HTML angle brackets, ampersand, and opening
  bracket are escaped in untrusted text fields placed in table cells. Embedded
  newlines are normalized to a single space. This prevents table-row and heading
  injection but does not harden against all Markdown rendering environments.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

try:
    from importlib.metadata import version as _pkg_version

    TOOL_VERSION: str = _pkg_version("triageledger")
except Exception:
    TOOL_VERSION = "unknown"

from triageledger.models import DECISION_SCHEMA_VERSION, Decision, IngestResult, PolicyConfig

# ---------------------------------------------------------------------------
# CSV injection mitigation
# ---------------------------------------------------------------------------

# Characters that trigger formula evaluation in common spreadsheet applications
# when they appear as the first non-whitespace character in a cell.
_FORMULA_PREFIXES: frozenset[str] = frozenset({"=", "+", "-", "@"})

# Non-printable control characters to replace (keep \x09 tab, \x0a LF, \x0d CR
# since the csv module uses and quotes them normally).
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_csv_cell(value: str) -> str:
    """Mitigate formula injection and remove non-printable control characters.

    Steps:
    1. Replace non-printable control characters (excluding tab, LF, CR) with U+FFFD.
    2. Strip the cleaned value to check whether the meaningful content starts with
       a formula-trigger character, including cases with leading whitespace.
    3. If so, prefix the original cleaned value (with leading whitespace preserved)
       with a single apostrophe to force text interpretation.

    This mitigation is applied per cell before the csv module adds quoting.
    It is not a universal spreadsheet-safety guarantee; document accordingly.
    """
    cleaned = _CONTROL_CHAR_RE.sub("\ufffd", value)
    stripped = cleaned.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        cleaned = "'" + cleaned
    return cleaned


def _cell(value: Any) -> str:
    """Convert a value to a sanitized CSV cell string. None becomes empty string."""
    if value is None:
        return ""
    return _sanitize_csv_cell(str(value))


# ---------------------------------------------------------------------------
# Markdown injection mitigation
# ---------------------------------------------------------------------------

_MD_TABLE_ESCAPE = str.maketrans(
    {
        "\\": "\\\\",
        "|": r"\|",
        "`": r"\`",
        "<": "&lt;",
        ">": "&gt;",
        "&": "&amp;",
        "[": r"\[",
    }
)


def _escape_md(value: str | None) -> str:
    """Escape Markdown-active and HTML-active characters for use in table cells.

    Normalizes embedded newlines (CR, LF, CRLF) to a single space so they cannot
    inject table rows or headings. Escapes: backslash, pipe, backtick, <, >, &, [.
    """
    if value is None:
        return ""
    normalized = re.sub(r"\r\n|\r|\n", " ", value)
    return normalized.translate(_MD_TABLE_ESCAPE)


# ---------------------------------------------------------------------------
# Decision serialization helpers
# ---------------------------------------------------------------------------


def _decision_to_dict(d: Decision) -> dict[str, Any]:
    """Serialize a Decision to a plain dict with fixed field order.

    Collections are explicitly ordered for determinism across Python processes:
    - flags: sorted list of strings (frozenset iteration is hash-randomized).
    - evidence_ids: sorted list of strings.
    - supporting_facts["evidence_ids"]: sorted for the same reason.
    """
    sf: dict[str, Any] = dict(d.supporting_facts)
    if "evidence_ids" in sf and isinstance(sf["evidence_ids"], list):
        sf["evidence_ids"] = sorted(sf["evidence_ids"])

    return {
        "schema_version": d.schema_version,
        "finding_id": d.finding_id,
        "asset_id": d.asset_id,
        "vulnerability_id": d.vulnerability_id,
        "disposition": d.disposition,
        "priority": d.priority,
        "rule_id": d.rule_id,
        "rule_version": d.rule_version,
        "explanation": d.explanation,
        "supporting_facts": sf,
        "evidence_ids": sorted(d.evidence_ids),
        "flags": sorted(d.flags),
        "owner_team": d.owner_team,
        "next_action": d.next_action,
        "as_of": d.as_of.isoformat(),
        "context_age_days": d.context_age_days,
        "effective_criticality": str(d.effective_criticality),
        "effective_exposure": str(d.effective_exposure),
        "effective_exploitation": str(d.effective_exploitation),
        "original_criticality": (
            str(d.original_criticality) if d.original_criticality is not None else None
        ),
        "original_exposure": (
            str(d.original_exposure) if d.original_exposure is not None else None
        ),
        "detected_at": d.detected_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Artifact writers
# ---------------------------------------------------------------------------


def write_decisions_json(
    decisions: list[Decision],
    run_id: str,
    as_of: datetime,
    policy: PolicyConfig,
    path: Path,
) -> None:
    """Write canonical decisions.json with fixed field order and UTF-8 encoding."""
    doc = {
        "run_id": run_id,
        "as_of": as_of.isoformat(),
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "decision_count": len(decisions),
        "decisions": [_decision_to_dict(d) for d in decisions],
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


_QUEUE_CSV_COLUMNS: list[str] = [
    "finding_id",
    "asset_id",
    "vulnerability_id",
    "priority",
    "disposition",
    "rule_id",
    "rule_version",
    "owner_team",
    "flags",
    "as_of",
    "context_age_days",
    "detected_at",
    "effective_criticality",
    "effective_exposure",
    "effective_exploitation",
    "next_action",
]


def _decision_to_csv_row(d: Decision) -> dict[str, str]:
    return {
        "finding_id": _cell(d.finding_id),
        "asset_id": _cell(d.asset_id),
        "vulnerability_id": _cell(d.vulnerability_id),
        "priority": _cell(d.priority),
        "disposition": _cell(d.disposition),
        "rule_id": _cell(d.rule_id),
        "rule_version": _cell(d.rule_version),
        "owner_team": _cell(d.owner_team),
        "flags": _cell(" ".join(sorted(d.flags))),
        "as_of": _cell(d.as_of.isoformat()),
        "context_age_days": _cell(
            f"{d.context_age_days:.4f}" if d.context_age_days is not None else None
        ),
        "detected_at": _cell(d.detected_at.isoformat()),
        "effective_criticality": _cell(str(d.effective_criticality)),
        "effective_exposure": _cell(str(d.effective_exposure)),
        "effective_exploitation": _cell(str(d.effective_exploitation)),
        "next_action": _cell(d.next_action),
    }


def _write_csv(rows: list[dict[str, str]], columns: list[str], path: Path) -> None:
    buf = StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=columns,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def write_queue_csv(decisions: list[Decision], path: Path) -> None:
    """Write spreadsheet-safe queue.csv for all decisions."""
    _write_csv([_decision_to_csv_row(d) for d in decisions], _QUEUE_CSV_COLUMNS, path)


def write_review_csv(decisions: list[Decision], path: Path) -> None:
    """Write review.csv: decisions with non-empty flags, including excluded findings.

    This is the overlapping subset of flagged decisions that require data or analyst
    investigation. Excluded (not_affected) findings appear here when they carry flags.
    """
    flagged = [d for d in decisions if d.flags]
    _write_csv([_decision_to_csv_row(d) for d in flagged], _QUEUE_CSV_COLUMNS, path)


def write_briefing_md(
    decisions: list[Decision],
    run_id: str,
    as_of: datetime,
    policy: PolicyConfig,
    path: Path,
) -> None:
    """Write concise briefing.md from decision records.

    Untrusted text fields (owner_team) are escaped. No remediation guidance is
    generated. Empty decision lists produce a zero-count briefing with no fabricated
    entries.
    """
    priority_counts: Counter[str] = Counter()
    flagged_count = 0
    for d in decisions:
        priority_counts[d.priority or "excluded"] += 1
        if d.flags:
            flagged_count += 1

    lines: list[str] = []
    lines.append("# TriageLedger Briefing\n")
    lines.append(f"**Run ID:** `{run_id}`  ")
    lines.append(f"**As of:** {as_of.isoformat()}  ")
    lines.append(f"**Policy:** {_escape_md(policy.policy_id)} v{_escape_md(policy.version)}  ")
    lines.append("")
    lines.append("## Summary\n")
    lines.append("| Priority | Count |")
    lines.append("|---|---|")
    for p in ("P1", "P2", "P3", "P4"):
        lines.append(f"| {p} | {priority_counts[p]} |")
    lines.append(f"| Excluded (not\\_affected) | {priority_counts['excluded']} |")
    lines.append(f"| **Total** | **{len(decisions)}** |")
    lines.append("")
    lines.append(f"Decisions requiring review: {flagged_count}.")
    lines.append("")

    p1_decisions = [d for d in decisions if d.priority == "P1"]
    if p1_decisions:
        lines.append("## Top Actions (P1)\n")
        lines.append("| Finding | Asset | Vulnerability | Rule | Owner |")
        lines.append("|---|---|---|---|---|")
        for d in p1_decisions:
            lines.append(
                f"| {_escape_md(d.finding_id)}"
                f" | {_escape_md(d.asset_id)}"
                f" | {_escape_md(d.vulnerability_id)}"
                f" | {_escape_md(d.rule_id)}"
                f" | {_escape_md(d.owner_team)} |"
            )
        lines.append("")

    all_flags: Counter[str] = Counter()
    for d in decisions:
        for f in d.flags:
            all_flags[f] += 1
    if all_flags:
        lines.append("## Uncertainty Flags\n")
        lines.append("| Flag | Count |")
        lines.append("|---|---|")
        for flag, count in sorted(all_flags.items()):
            lines.append(f"| {_escape_md(flag)} | {count} |")
        lines.append("")

    lines.append("## Limitations\n")
    lines.append(
        "Decisions are recommendations requiring analyst review. "
        "Policy thresholds are illustrative, not NIST/CISA mandates or IEX requirements. "
        "Inputs are synthetic; this is a portfolio prototype, not a production service."
    )
    lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_diagnostics_json(
    ingest_results: list[IngestResult],
    run_id: str | None,
    as_of: datetime | None,
    path: Path,
) -> None:
    """Write structured diagnostics.json.

    Raw input values are deliberately excluded from output to avoid exposing
    untrusted data. Tracebacks are not included.
    """
    files = []
    for r in ingest_results:
        files.append(
            {
                "source_file": r.source_file,
                "total_rows_read": r.total_rows_read,
                "accepted": r.accepted,
                "collapsed_duplicates": r.collapsed_duplicates,
                "fatal": r.fatal,
                "diagnostics": [
                    {
                        "level": d.level,
                        "source_file": d.source_file,
                        "row_number": d.row_number,
                        "field_name": d.field_name,
                        "message": d.message,
                        # raw_value excluded: may contain untrusted input data
                    }
                    for d in r.diagnostics
                ],
            }
        )
    doc = {
        "run_id": run_id,
        "as_of": as_of.isoformat() if as_of is not None else None,
        "files": files,
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Hashing and run identity
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    """Return lowercase SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return lowercase SHA-256 hex digest of a file's bytes."""
    return sha256_bytes(path.read_bytes())


def compute_run_id(
    as_of: datetime,
    assets_bytes: bytes,
    findings_bytes: bytes,
    evidence_bytes: bytes,
    policy_bytes: bytes,
    policy: PolicyConfig,
) -> str:
    """Derive a deterministic run identity from canonical inputs.

    Constructs an unambiguous identity document as a canonical JSON string
    containing: normalized as_of, named input-content hashes, actual policy-content
    hash, tool version, and schema version. The run_id is the SHA-256 of that
    document encoded as UTF-8.

    The input bytes passed here must be the same snapshots that were actually parsed
    (read once, reused). Files are not re-read to compute provenance.
    """
    identity_doc = json.dumps(
        {
            "schema_version": DECISION_SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "as_of": as_of.isoformat(),
            "assets_sha256": sha256_bytes(assets_bytes),
            "findings_sha256": sha256_bytes(findings_bytes),
            "evidence_sha256": sha256_bytes(evidence_bytes),
            "policy_sha256": sha256_bytes(policy_bytes),
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
        },
        sort_keys=True,
    )
    return sha256_bytes(identity_doc.encode("utf-8"))


def write_manifest(
    run_id: str,
    as_of: datetime,
    policy: PolicyConfig,
    policy_bytes: bytes,
    assets_bytes: bytes,
    findings_bytes: bytes,
    evidence_bytes: bytes,
    counts: dict[str, int],
    artifact_paths: dict[str, Path],
    path: Path,
) -> None:
    """Write manifest.json.

    Must be called after all five other artifacts have been written, since it
    records their SHA-256 hashes. manifest.json is not hashed into itself.
    """
    doc = {
        "schema_version": "1.0",
        "run_id": run_id,
        "as_of": as_of.isoformat(),
        "tool_version": TOOL_VERSION,
        "decision_schema_version": DECISION_SCHEMA_VERSION,
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "counts": counts,
        "input_hashes": {
            "assets_sha256": sha256_bytes(assets_bytes),
            "findings_sha256": sha256_bytes(findings_bytes),
            "evidence_sha256": sha256_bytes(evidence_bytes),
        },
        "policy_sha256": sha256_bytes(policy_bytes),
        "artifact_hashes": {name: sha256_file(p) for name, p in sorted(artifact_paths.items())},
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

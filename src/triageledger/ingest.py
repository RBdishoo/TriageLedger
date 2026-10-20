"""CSV ingestion, validation, and normalization for TriageLedger v1.

Responsibilities:
- Bounded file reads (size, row count, field length)
- Header validation: required columns, no duplicates, no unexpected columns
- Enum and ISO-8601 UTC timestamp parsing
- Duplicate semantics: identical rows collapse; conflicting same-ID rows are fatal
- Diagnostics collected for every anomaly
- No network calls, no fuzzy matching, no NUL bytes tolerated

Exit behavior (surfaced by the caller, not raised here):
  fatal=True  -> caller must exit 2, publish no decision artifacts
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

from triageledger.models import (
    Applicability,
    Asset,
    BusinessCriticality,
    ExploitationStatus,
    Finding,
    IngestResult,
    InternetExposure,
    Severity,
    ThreatEvidence,
)

# ---------------------------------------------------------------------------
# Limits (illustrative prototype values, not benchmarks)
# ---------------------------------------------------------------------------
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_DATA_ROWS = 50_000
MAX_FIELD_BYTES = 8 * 1024  # 8 KiB

# ---------------------------------------------------------------------------
# Expected columns per file type
# ---------------------------------------------------------------------------
ASSET_COLUMNS = frozenset(
    {
        "asset_id",
        "display_name",
        "business_criticality",
        "internet_exposure",
        "owner_team",
        "context_updated_at",
    }
)
FINDING_COLUMNS = frozenset(
    {
        "finding_id",
        "asset_id",
        "vulnerability_id",
        "severity",
        "applicability",
        "detected_at",
        "description",
    }
)
EVIDENCE_COLUMNS = frozenset(
    {
        "evidence_id",
        "vulnerability_id",
        "exploitation_status",
        "source_label",
        "source_reference",
        "observed_at",
    }
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _check_nul(text: str) -> bool:
    return "\x00" in text


def _trim_id(value: str) -> str:
    """Strip surrounding whitespace from identifier/enum fields."""
    return value.strip()


def _parse_utc_timestamp(
    raw: str, as_of: datetime | None = None
) -> tuple[datetime | None, str | None]:
    """Parse ISO-8601 UTC timestamp ending in Z.

    Returns (datetime, None) on success, (None, error_message) on failure.
    Rejects timestamps after as_of when as_of is provided.
    """
    raw = raw.strip()
    if not raw:
        return None, "timestamp is blank"
    if not raw.endswith("Z"):
        return None, f"timestamp must end with Z (UTC), got: {raw!r}"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None, f"invalid ISO-8601 timestamp: {raw!r}"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if as_of is not None and dt > as_of:
        return None, f"timestamp {raw!r} is after as-of {as_of.isoformat()}"
    return dt, None


def _parse_enum(raw: str, enum_cls: type, field_name: str) -> tuple[object | None, str | None]:
    value = _trim_id(raw)
    try:
        return enum_cls(value), None
    except ValueError:
        allowed = ", ".join(e.value for e in enum_cls)
        return None, f"{field_name} {value!r} is not one of: {allowed}"


def _validate_headers(
    actual: list[str],
    expected: frozenset[str],
    result: IngestResult,
) -> bool:
    """Validate header row. Returns True if headers are usable, False if fatal."""
    # Check for duplicate headers
    seen: dict[str, int] = {}
    for col in actual:
        seen[col] = seen.get(col, 0) + 1
    duplicates = [c for c, n in seen.items() if n > 1]
    if duplicates:
        result.add_diagnostic(
            "fatal",
            None,
            None,
            f"duplicate column headers: {duplicates}",
        )
        result.fatal = True
        return False

    actual_set = frozenset(actual)
    missing = expected - actual_set
    unexpected = actual_set - expected
    if missing:
        result.add_diagnostic(
            "fatal",
            None,
            None,
            f"missing required columns: {sorted(missing)}",
        )
        result.fatal = True
        return False
    if unexpected:
        result.add_diagnostic(
            "fatal",
            None,
            None,
            f"unexpected columns (schema v1 rejects unknown columns): {sorted(unexpected)}",
        )
        result.fatal = True
        return False
    return True


def _read_raw_csv(path: Path, result: IngestResult) -> list[dict[str, str]] | None:
    """Read and decode the file, check size limits, return list of row dicts or None on fatal."""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        result.add_diagnostic("fatal", None, None, f"cannot read file: {exc}")
        result.fatal = True
        return None

    if len(raw_bytes) > MAX_FILE_BYTES:
        result.add_diagnostic(
            "fatal",
            None,
            None,
            f"file size {len(raw_bytes)} bytes exceeds limit {MAX_FILE_BYTES} bytes",
        )
        result.fatal = True
        return None

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.add_diagnostic("fatal", None, None, f"file is not valid UTF-8: {exc}")
        result.fatal = True
        return None

    if _check_nul(text):
        result.add_diagnostic("fatal", None, None, "file contains embedded NUL bytes")
        result.fatal = True
        return None

    # restval=None (default) means absent fields are None — distinguishable from present-but-empty.
    # restkey=None (default) means extra fields accumulate under key None.
    reader = csv.DictReader(io.StringIO(text))
    try:
        fieldnames = reader.fieldnames or []
    except csv.Error as exc:
        result.add_diagnostic("fatal", None, None, f"CSV parse error on header: {exc}")
        result.fatal = True
        return None

    if not _validate_headers(list(fieldnames), _expected_columns(path.name), result):
        return None

    expected_width = len(fieldnames)
    rows: list[dict[str, str]] = []
    for i, row in enumerate(reader, start=2):  # row 1 = header
        result.total_rows_read += 1
        if result.total_rows_read > MAX_DATA_ROWS:
            result.add_diagnostic(
                "fatal",
                i,
                None,
                f"data row count exceeds limit {MAX_DATA_ROWS}",
            )
            result.fatal = True
            return None

        # Extra-wide row: DictReader puts overflow values under key None.
        if row.get(None) is not None:  # type: ignore[call-overload]
            result.add_diagnostic(
                "fatal",
                i,
                None,
                f"row has more fields than the {expected_width}-column header",
            )
            result.fatal = True
            return None

        # Short row: absent fields have value None (restval default).
        absent = [k for k, v in row.items() if k is not None and v is None]
        if absent:
            result.add_diagnostic(
                "fatal",
                i,
                str(absent),
                f"row is missing field(s): {absent}; "
                "use an empty field (two adjacent commas) for optional absent values",
            )
            result.fatal = True
            return None

        # Check field lengths on the now-guaranteed str values.
        oversized = [k for k, v in row.items() if v and len(v.encode("utf-8")) > MAX_FIELD_BYTES]
        if oversized:
            result.add_diagnostic(
                "fatal",
                i,
                str(oversized),
                f"field(s) exceed {MAX_FIELD_BYTES}-byte limit",
            )
            result.fatal = True
            return None

        # Safe: all values are str, None key excluded.
        rows.append({k: v for k, v in row.items() if k is not None})
    return rows


def _expected_columns(filename: str) -> frozenset[str]:
    name = Path(filename).name.lower()
    if "asset" in name:
        return ASSET_COLUMNS
    if "finding" in name:
        return FINDING_COLUMNS
    if "threat" in name or "evidence" in name:
        return EVIDENCE_COLUMNS
    # Fallback: caller should pass explicit type; this path shouldn't be reached
    return frozenset()


# ---------------------------------------------------------------------------
# Public parse functions
# ---------------------------------------------------------------------------


def _fail(result: IngestResult) -> IngestResult:
    """Mark result fatal and clear all accumulated records.

    Callers must check result.fatal before reading result.assets / .findings /
    .threat_evidence. This helper enforces that partial records are never
    silently accessible after a fatal error: it zeros accepted and empties all
    record lists so that iterating the lists on a failed parse yields nothing.

    Count semantics on a fatal result:
    - accepted = 0 (cleared; does not reflect rows processed before the error)
    - collapsed_duplicates = unchanged (reflects processing up to the fatal row)
    - total_rows_read = unchanged (reflects processing up to the fatal row)
    - The successful-load invariant (accepted == len(records)) does not apply
      to fatal results; check result.fatal first.
    """
    result.fatal = True
    result.accepted = 0
    result.assets.clear()
    result.findings.clear()
    result.threat_evidence.clear()
    return result


def parse_assets(path: Path, as_of: datetime) -> IngestResult:
    result = IngestResult(source_file=str(path))
    rows = _read_raw_csv(path, result)
    if rows is None:
        return result  # result.fatal already set; record lists are empty

    # Duplicate tracking: asset_id -> canonical row dict for conflict detection
    seen_full: dict[str, dict] = {}

    for i, row in enumerate(rows, start=2):
        asset_id = _trim_id(row.get("asset_id", ""))
        if not asset_id:
            result.add_diagnostic("fatal", i, "asset_id", "asset_id is blank")
            return _fail(result)

        display_name = row.get("display_name", "").strip()
        if not display_name:
            result.add_diagnostic("fatal", i, "display_name", "display_name is blank")
            return _fail(result)

        crit_raw = _trim_id(row.get("business_criticality", ""))
        criticality, err = _parse_enum(crit_raw, BusinessCriticality, "business_criticality")
        if err:
            result.add_diagnostic("fatal", i, "business_criticality", err, crit_raw)
            return _fail(result)

        exp_raw = _trim_id(row.get("internet_exposure", ""))
        exposure, err = _parse_enum(exp_raw, InternetExposure, "internet_exposure")
        if err:
            result.add_diagnostic("fatal", i, "internet_exposure", err, exp_raw)
            return _fail(result)

        owner_raw = row.get("owner_team", "").strip()
        owner_team: str | None = owner_raw if owner_raw else None
        owner_missing = owner_team is None

        ts_raw = row.get("context_updated_at", "")
        context_updated_at, err = _parse_utc_timestamp(ts_raw, as_of)
        if err:
            result.add_diagnostic("fatal", i, "context_updated_at", err, ts_raw)
            return _fail(result)

        # Canonical row dict for duplicate comparison (trimmed values)
        canonical = {
            "asset_id": asset_id,
            "display_name": display_name,
            "business_criticality": crit_raw,
            "internet_exposure": exp_raw,
            "owner_team": owner_raw,
            "context_updated_at": ts_raw.strip(),
        }

        if asset_id in seen_full:
            if seen_full[asset_id] == canonical:
                # Identical duplicate — collapse
                result.collapsed_duplicates += 1
                result.add_diagnostic(
                    "info",
                    i,
                    "asset_id",
                    f"identical duplicate of asset_id {asset_id!r}; collapsed",
                )
                continue
            else:
                # Conflicting duplicate — fatal
                result.add_diagnostic(
                    "fatal",
                    i,
                    "asset_id",
                    f"conflicting duplicate asset_id {asset_id!r}; matching is ambiguous",
                )
                return _fail(result)

        seen_full[asset_id] = canonical
        result.assets.append(
            Asset(
                asset_id=asset_id,
                display_name=display_name,
                business_criticality=criticality,  # type: ignore[arg-type]
                internet_exposure=exposure,  # type: ignore[arg-type]
                owner_team=owner_team,
                context_updated_at=context_updated_at,  # type: ignore[arg-type]
                owner_missing=owner_missing,
            )
        )
        result.accepted += 1

    return result


def parse_findings(path: Path, as_of: datetime) -> IngestResult:
    result = IngestResult(source_file=str(path))
    rows = _read_raw_csv(path, result)
    if rows is None:
        return result  # result.fatal already set; record lists are empty

    seen_full: dict[str, dict] = {}  # finding_id -> canonical row

    # Track (asset_id, vulnerability_id) pairs for possible_duplicate flagging
    seen_asset_vuln: dict[tuple[str, str], str] = {}  # (asset_id, vuln_id) -> finding_id

    for i, row in enumerate(rows, start=2):
        finding_id = _trim_id(row.get("finding_id", ""))
        if not finding_id:
            result.add_diagnostic("fatal", i, "finding_id", "finding_id is blank")
            return _fail(result)

        asset_id = _trim_id(row.get("asset_id", ""))
        if not asset_id:
            result.add_diagnostic("fatal", i, "asset_id", "asset_id is blank")
            return _fail(result)

        vuln_raw = row.get("vulnerability_id", "").strip()
        vulnerability_id: str | None = vuln_raw if vuln_raw else None
        missing_vuln_id = vulnerability_id is None

        sev_raw = _trim_id(row.get("severity", ""))
        severity, err = _parse_enum(sev_raw, Severity, "severity")
        if err:
            result.add_diagnostic("fatal", i, "severity", err, sev_raw)
            return _fail(result)

        app_raw = _trim_id(row.get("applicability", ""))
        applicability, err = _parse_enum(app_raw, Applicability, "applicability")
        if err:
            result.add_diagnostic("fatal", i, "applicability", err, app_raw)
            return _fail(result)

        ts_raw = row.get("detected_at", "")
        detected_at, err = _parse_utc_timestamp(ts_raw, as_of)
        if err:
            result.add_diagnostic("fatal", i, "detected_at", err, ts_raw)
            return _fail(result)

        desc_raw = row.get("description", "").strip()
        description: str | None = desc_raw if desc_raw else None

        canonical = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "vulnerability_id": vuln_raw,
            "severity": sev_raw,
            "applicability": app_raw,
            "detected_at": ts_raw.strip(),
            "description": desc_raw,
        }

        if finding_id in seen_full:
            if seen_full[finding_id] == canonical:
                result.collapsed_duplicates += 1
                result.add_diagnostic(
                    "info",
                    i,
                    "finding_id",
                    f"identical duplicate of finding_id {finding_id!r}; collapsed",
                )
                continue
            else:
                result.add_diagnostic(
                    "fatal",
                    i,
                    "finding_id",
                    f"conflicting duplicate finding_id {finding_id!r}",
                )
                return _fail(result)

        seen_full[finding_id] = canonical

        # Possible duplicate: same asset + same vulnerability, different finding_id
        possible_dup = False
        if vulnerability_id:
            key = (asset_id, vulnerability_id)
            if key in seen_asset_vuln:
                possible_dup = True
                result.add_diagnostic(
                    "info",
                    i,
                    "finding_id",
                    f"possible_duplicate: asset_id {asset_id!r} + vulnerability_id "
                    f"{vulnerability_id!r} also appears in finding_id "
                    f"{seen_asset_vuln[key]!r}",
                )
            else:
                seen_asset_vuln[key] = finding_id

        result.findings.append(
            Finding(
                finding_id=finding_id,
                asset_id=asset_id,
                vulnerability_id=vulnerability_id,
                severity=severity,  # type: ignore[arg-type]
                applicability=applicability,  # type: ignore[arg-type]
                detected_at=detected_at,  # type: ignore[arg-type]
                description=description,
                missing_vulnerability_id=missing_vuln_id,
                possible_duplicate=possible_dup,
            )
        )
        result.accepted += 1

    return result


def parse_threat_evidence(path: Path, as_of: datetime) -> IngestResult:
    result = IngestResult(source_file=str(path))
    rows = _read_raw_csv(path, result)
    if rows is None:
        return result  # result.fatal already set; record lists are empty

    seen_full: dict[str, dict] = {}

    for i, row in enumerate(rows, start=2):
        evidence_id = _trim_id(row.get("evidence_id", ""))
        if not evidence_id:
            result.add_diagnostic("fatal", i, "evidence_id", "evidence_id is blank")
            return _fail(result)

        vuln_id = _trim_id(row.get("vulnerability_id", ""))
        if not vuln_id:
            result.add_diagnostic("fatal", i, "vulnerability_id", "vulnerability_id is blank")
            return _fail(result)

        status_raw = _trim_id(row.get("exploitation_status", ""))
        status, err = _parse_enum(status_raw, ExploitationStatus, "exploitation_status")
        if err:
            result.add_diagnostic("fatal", i, "exploitation_status", err, status_raw)
            return _fail(result)

        source_label = row.get("source_label", "").strip()
        if not source_label:
            result.add_diagnostic("fatal", i, "source_label", "source_label is blank")
            return _fail(result)

        source_ref = row.get("source_reference", "").strip()
        if not source_ref:
            result.add_diagnostic("fatal", i, "source_reference", "source_reference is blank")
            return _fail(result)

        ts_raw = row.get("observed_at", "")
        observed_at, err = _parse_utc_timestamp(ts_raw, as_of)
        if err:
            result.add_diagnostic("fatal", i, "observed_at", err, ts_raw)
            return _fail(result)

        canonical = {
            "evidence_id": evidence_id,
            "vulnerability_id": vuln_id,
            "exploitation_status": status_raw,
            "source_label": source_label,
            "source_reference": source_ref,
            "observed_at": ts_raw.strip(),
        }

        if evidence_id in seen_full:
            if seen_full[evidence_id] == canonical:
                result.collapsed_duplicates += 1
                result.add_diagnostic(
                    "info",
                    i,
                    "evidence_id",
                    f"identical duplicate of evidence_id {evidence_id!r}; collapsed",
                )
                continue
            else:
                result.add_diagnostic(
                    "fatal",
                    i,
                    "evidence_id",
                    f"conflicting duplicate evidence_id {evidence_id!r}",
                )
                return _fail(result)

        seen_full[evidence_id] = canonical
        result.threat_evidence.append(
            ThreatEvidence(
                evidence_id=evidence_id,
                vulnerability_id=vuln_id,
                exploitation_status=status,  # type: ignore[arg-type]
                source_label=source_label,
                source_reference=source_ref,
                observed_at=observed_at,  # type: ignore[arg-type]
            )
        )
        result.accepted += 1

    return result

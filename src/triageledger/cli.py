"""CLI orchestration for TriageLedger v1.

Entry point: python -m triageledger.cli evaluate [args]

Exit codes:
  0  Completed successfully; no decision carries any review flag.
  1  Operational or publication failure; unexpected internal error.
  2  Invalid arguments, inputs, or policy (bad CLI args, fatal ingestion, bad policy).
  3  Completed successfully; at least one decision carries a review flag.

Publication semantics:
  All artifacts — including the diagnostics-only output produced on fatal ingestion —
  are staged in a uniquely created temporary sibling directory. The destination is
  checked for conflicts before any write begins. On success, the temporary directory
  is published by renaming it to the destination. On failure, the temporary directory
  is removed and no partial artifacts reach the destination.

  --overwrite is not supported in v1. A fresh output directory is always required.
  Existing destinations (directory, regular file, or symlink) are rejected.
  This prevents unintended overwrites of prior run artifacts.

  The rename-based publication reduces the chance of partial writes reaching the
  destination but is not crash-safe or concurrency-safe. If the process is killed
  after the rename, the destination may contain a complete or partial artifact set.
  If the process is killed before the rename, the temporary directory may remain and
  must be cleaned up manually. Cross-device renames fail; the temporary directory is
  preserved and its path is reported to stderr.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from triageledger.ingest import MAX_FILE_BYTES, parse_assets, parse_findings, parse_threat_evidence
from triageledger.models import IngestResult
from triageledger.policy import evaluate, load_policy
from triageledger.reporting import (
    compute_run_id,
    write_briefing_md,
    write_decisions_json,
    write_diagnostics_json,
    write_manifest,
    write_queue_csv,
    write_review_csv,
)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _parse_as_of(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a UTC-normalized datetime.

    Requires an explicit timezone offset. Naive timestamps are rejected.
    The trailing 'Z' shorthand is accepted and treated as UTC (+00:00).
    """
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid --as-of value {value!r}. "
            "Expected ISO-8601 with timezone, e.g. 2026-10-19T00:00:00Z"
        )
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise argparse.ArgumentTypeError(
            f"--as-of must include a timezone offset (e.g. Z for UTC): {value!r}"
        )
    return dt.astimezone(UTC)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triageledger",
        description="Explainable vulnerability triage tool (portfolio prototype).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser(
        "evaluate",
        help="Run triage evaluation and write artifacts to the output directory.",
    )
    ev.add_argument("--assets", required=True, metavar="PATH", help="Assets CSV file.")
    ev.add_argument("--findings", required=True, metavar="PATH", help="Findings CSV file.")
    ev.add_argument(
        "--threat-evidence",
        required=True,
        metavar="PATH",
        help="Threat evidence CSV file.",
    )
    ev.add_argument("--policy", required=True, metavar="PATH", help="Policy JSON file.")
    ev.add_argument(
        "--as-of",
        required=True,
        metavar="TIMESTAMP",
        type=_parse_as_of,
        help="Evaluation timestamp (ISO-8601 with timezone, e.g. 2026-10-19T00:00:00Z).",
    )
    ev.add_argument(
        "--output-dir",
        required=True,
        metavar="DIR",
        help=(
            "Destination directory for artifacts. "
            "Must not already exist; --overwrite is not supported in v1."
        ),
    )
    ev.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        # Hidden from help text; rejected at runtime with a clear message.
        help=argparse.SUPPRESS,
    )
    return parser


# ---------------------------------------------------------------------------
# Destination safety
# ---------------------------------------------------------------------------


def _check_destination(dest: Path) -> str | None:
    """Return an error string if dest is unsafe to use as output, or None if safe.

    Rejects symlinks (regardless of target), regular files, and existing directories.
    This check must be applied before any write to the destination or its siblings.
    """
    if dest.is_symlink():
        return f"Output target is a symlink: {dest}. Use a fresh path."
    if dest.is_file():
        return f"Output target is a regular file: {dest}. Use a fresh directory path."
    if dest.is_dir():
        return (
            f"Output directory already exists: {dest}\n"
            "--overwrite is not supported in v1. Use a fresh output directory."
        )
    return None


# ---------------------------------------------------------------------------
# Bounded input read
# ---------------------------------------------------------------------------


def _read_bounded_input(path: Path) -> bytes:
    """Read a CLI input file with a size limit.

    Reads at most MAX_FILE_BYTES + 1 bytes. Raises ValueError if the file
    exceeds MAX_FILE_BYTES bytes, or OSError if the file cannot be read.

    The returned bytes are the same snapshot that should be passed to the
    parse/load functions so that parsing and provenance hashing use identical
    content.
    """
    with path.open("rb") as f:
        data = f.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"input file exceeds {MAX_FILE_BYTES}-byte limit: {path}")
    return data


# ---------------------------------------------------------------------------
# Evaluate subcommand
# ---------------------------------------------------------------------------


def _run_evaluate(args: argparse.Namespace) -> int:  # noqa: C901  (branchy by design)
    """Execute the evaluate subcommand. Returns the exit code."""
    assets_path = Path(args.assets)
    findings_path = Path(args.findings)
    evidence_path = Path(args.threat_evidence)
    policy_path = Path(args.policy)
    as_of: datetime = args.as_of
    dest = Path(args.output_dir)

    # --overwrite is not supported in v1.
    if args.overwrite:
        print(
            "Error: --overwrite is not supported in v1. Use a fresh output directory.",
            file=sys.stderr,
        )
        return 2

    # Destination safety check applied before any modification.
    collision_msg = _check_destination(dest)
    if collision_msg:
        print(f"Error: {collision_msg}", file=sys.stderr)
        return 1

    # Read all input files once with a bounded read; reuse the captured bytes
    # for both parsing and provenance hashing. This guarantees that the hash
    # reflects the actual parsed content.
    try:
        assets_bytes = _read_bounded_input(assets_path)
        findings_bytes = _read_bounded_input(findings_path)
        evidence_bytes = _read_bounded_input(evidence_path)
        policy_bytes = _read_bounded_input(policy_path)
    except (OSError, ValueError) as exc:
        print(f"Error: Cannot read input file: {exc}", file=sys.stderr)
        return 2

    # Parse all three CSVs using the pre-captured bytes (no re-read).
    assets_result = parse_assets(assets_path, as_of, assets_bytes)
    findings_result = parse_findings(findings_path, as_of, findings_bytes)
    evidence_result = parse_threat_evidence(evidence_path, as_of, evidence_bytes)
    ingest_results: list[IngestResult] = [assets_result, findings_result, evidence_result]

    # Load and validate policy using the pre-captured bytes (no re-read).
    policy = None
    policy_error: str | None = None
    policy_result = IngestResult(source_file=str(policy_path))
    try:
        policy = load_policy(policy_path, policy_bytes)
    except ValueError as exc:
        policy_error = str(exc)
        policy_result.add_diagnostic("fatal", None, None, policy_error)
        policy_result.fatal = True

    fatal = any(r.fatal for r in ingest_results) or policy_error is not None

    # Results passed to write_diagnostics_json include policy failures so that
    # structured output captures all fatal errors, not only CSV parse errors.
    results_for_diag = [*ingest_results, policy_result]

    if fatal:
        # Stage diagnostics-only output in a temp sibling, then publish by rename.
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"Error: Cannot create parent directory for output: {exc}", file=sys.stderr)
            return 1

        try:
            tmp_dir = Path(tempfile.mkdtemp(dir=dest.parent, prefix=dest.name + "_tmp_"))
        except OSError as exc:
            print(f"Error: Cannot create staging directory: {exc}", file=sys.stderr)
            return 1

        try:
            write_diagnostics_json(
                results_for_diag,
                run_id=None,
                as_of=as_of,
                path=tmp_dir / "diagnostics.json",
            )
        except OSError as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            print(f"Error: Could not write diagnostics: {exc}", file=sys.stderr)
            return 1

        # Re-check destination before rename (narrow TOCTOU window).
        collision_msg = _check_destination(dest)
        if collision_msg:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            print(f"Error: {collision_msg}", file=sys.stderr)
            return 1

        try:
            os.rename(tmp_dir, dest)
        except OSError as exc:
            print(
                f"Error: Cannot publish diagnostics to {dest}: {exc}\n"
                f"Staged diagnostics preserved at: {tmp_dir}",
                file=sys.stderr,
            )
            return 1

        # Print fatal messages to stderr after successful publication.
        if policy_error:
            print(f"Fatal: {policy_error}", file=sys.stderr)
        for r in ingest_results:
            if r.fatal:
                for d in r.diagnostics:
                    if d.level == "fatal":
                        print(f"Fatal ({r.source_file}): {d.message}", file=sys.stderr)
        return 2

    # Evaluate findings.
    assert policy is not None  # guaranteed: fatal is False and policy_error is None
    try:
        decisions = evaluate(
            findings=findings_result.findings,
            assets=assets_result.assets,
            evidence=evidence_result.threat_evidence,
            policy=policy,
            as_of=as_of,
        )
    except Exception as exc:
        print(f"Error: Unexpected evaluation failure: {exc}", file=sys.stderr)
        return 1

    run_id = compute_run_id(
        as_of=as_of,
        assets_bytes=assets_bytes,
        findings_bytes=findings_bytes,
        evidence_bytes=evidence_bytes,
        policy_bytes=policy_bytes,
        policy=policy,
    )

    counts = {
        "findings_evaluated": len(decisions),
        "decisions_review_recommended": sum(
            1 for d in decisions if d.disposition == "review_recommended"
        ),
        "decisions_not_affected": sum(1 for d in decisions if d.disposition == "not_affected"),
        "flagged_decisions": sum(1 for d in decisions if d.flags),
        "assets_ingested": assets_result.accepted,
        "findings_ingested": findings_result.accepted,
        "evidence_ingested": evidence_result.accepted,
    }

    # Ensure the parent directory exists before staging (e.g. artifacts/ may not exist).
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Error: Cannot create parent directory for output: {exc}", file=sys.stderr)
        return 1

    # Stage in a uniquely named temporary sibling directory.
    try:
        tmp_dir = Path(tempfile.mkdtemp(dir=dest.parent, prefix=dest.name + "_tmp_"))
    except OSError as exc:
        print(f"Error: Cannot create staging directory: {exc}", file=sys.stderr)
        return 1

    try:
        decisions_path = tmp_dir / "decisions.json"
        queue_path = tmp_dir / "queue.csv"
        review_path = tmp_dir / "review.csv"
        briefing_path = tmp_dir / "briefing.md"
        diagnostics_path = tmp_dir / "diagnostics.json"
        manifest_path = tmp_dir / "manifest.json"

        write_decisions_json(decisions, run_id, as_of, policy, decisions_path)
        write_queue_csv(decisions, queue_path)
        write_review_csv(decisions, review_path)
        write_briefing_md(decisions, run_id, as_of, policy, briefing_path)
        write_diagnostics_json(results_for_diag, run_id, as_of, diagnostics_path)

        artifact_paths = {
            "decisions.json": decisions_path,
            "queue.csv": queue_path,
            "review.csv": review_path,
            "briefing.md": briefing_path,
            "diagnostics.json": diagnostics_path,
        }

        # Manifest is written last; its hashes cover the five artifacts above.
        write_manifest(
            run_id=run_id,
            as_of=as_of,
            policy=policy,
            policy_bytes=policy_bytes,
            assets_bytes=assets_bytes,
            findings_bytes=findings_bytes,
            evidence_bytes=evidence_bytes,
            counts=counts,
            artifact_paths=artifact_paths,
            path=manifest_path,
        )
    except OSError as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"Error: Failed to write artifacts: {exc}", file=sys.stderr)
        return 1
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print("Error: Unexpected failure during artifact generation.", file=sys.stderr)
        return 1

    # Re-check destination before rename (narrow TOCTOU window).
    collision_msg = _check_destination(dest)
    if collision_msg:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"Error: {collision_msg}", file=sys.stderr)
        return 1

    try:
        os.rename(tmp_dir, dest)
    except OSError as exc:
        print(
            f"Error: Cannot publish artifacts to {dest}: {exc}\n"
            f"Staged artifacts preserved at: {tmp_dir}",
            file=sys.stderr,
        )
        return 1

    has_flags = any(d.flags for d in decisions)
    return 3 if has_flags else 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "evaluate":
        sys.exit(_run_evaluate(args))
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

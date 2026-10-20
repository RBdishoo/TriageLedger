"""CLI orchestration for TriageLedger v1.

Entry point: python -m triageledger.cli evaluate [args]

Exit codes:
  0  Completed successfully; no decision carries any review flag.
  1  Operational or publication failure; unexpected internal error.
  2  Invalid arguments, inputs, or policy (bad CLI args, fatal ingestion, bad policy).
  3  Completed successfully; at least one decision carries a review flag.

Publication semantics:
  All artifacts are staged in a uniquely created temporary sibling directory. The
  destination is checked for conflicts before any write begins. On success, the
  temporary directory is published by renaming it to the destination. On failure,
  the temporary directory is removed and no partial artifacts reach the destination.

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

from triageledger.ingest import parse_assets, parse_findings, parse_threat_evidence
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

    # Read input bytes once; reuse for parsing and provenance hashing.
    # Do not re-read files later so provenance reflects the actual parsed snapshot.
    try:
        assets_bytes = assets_path.read_bytes()
        findings_bytes = findings_path.read_bytes()
        evidence_bytes = evidence_path.read_bytes()
        policy_bytes = policy_path.read_bytes()
    except OSError as exc:
        print(f"Error: Cannot read input file: {exc}", file=sys.stderr)
        return 2

    # Parse all three CSVs.
    assets_result = parse_assets(assets_path, as_of)
    findings_result = parse_findings(findings_path, as_of)
    evidence_result = parse_threat_evidence(evidence_path, as_of)
    ingest_results: list[IngestResult] = [assets_result, findings_result, evidence_result]

    # Load and validate policy.
    policy = None
    policy_error: str | None = None
    try:
        policy = load_policy(policy_path)
    except ValueError as exc:
        policy_error = str(exc)

    fatal = any(r.fatal for r in ingest_results) or policy_error is not None

    if fatal:
        # Publish diagnostics-only output and exit 2.
        # The destination check above already confirmed dest does not exist.
        try:
            dest.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            # Narrow TOCTOU race: another process created dest between check and mkdir.
            print(
                f"Error: Output directory was created by another process: {dest}",
                file=sys.stderr,
            )
            return 1
        except OSError as exc:
            print(f"Error: Cannot create output directory: {exc}", file=sys.stderr)
            return 1

        try:
            write_diagnostics_json(
                ingest_results,
                run_id=None,
                as_of=as_of,
                path=dest / "diagnostics.json",
            )
        except OSError as exc:
            # Operational failure: diagnostics could not be written.
            print(f"Error: Could not write diagnostics: {exc}", file=sys.stderr)
            return 1

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
        write_diagnostics_json(ingest_results, run_id, as_of, diagnostics_path)

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

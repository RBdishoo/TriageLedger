"""Integration tests for src/triageledger/cli.py.

All tests invoke the CLI as a subprocess to validate the full pipeline including
argument parsing, ingestion, evaluation, artifact writing, and publication.

Exit code contract:
  0  Completed; no review flags.
  1  Operational or publication failure.
  2  Invalid arguments, inputs, or policy.
  3  Completed; at least one review flag.

Cross-process replay tests use different PYTHONHASHSEED values to verify that
frozenset/set iteration order does not affect artifact bytes.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent
_SAMPLES = _REPO_ROOT / "samples"
_POLICY = _REPO_ROOT / "policies" / "demo-policy-v1.json"
_AS_OF = "2026-10-19T00:00:00Z"


def _run(
    args: list[str],
    *,
    pythonhashseed: str = "0",
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = pythonhashseed
    return subprocess.run(
        [sys.executable, "-m", "triageledger.cli"] + args,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd or _REPO_ROOT),
    )


def _demo_args(output_dir: str | Path) -> list[str]:
    return [
        "evaluate",
        "--assets",
        str(_SAMPLES / "assets.csv"),
        "--findings",
        str(_SAMPLES / "findings.csv"),
        "--threat-evidence",
        str(_SAMPLES / "threat_evidence.csv"),
        "--policy",
        str(_POLICY),
        "--as-of",
        _AS_OF,
        "--output-dir",
        str(output_dir),
    ]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_exit_3_demo_run(self, tmp_path: Path) -> None:
        """Demo dataset has review flags; must exit 3 with all six artifacts."""
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3, f"stderr: {r.stderr}"
        for fname in (
            "decisions.json",
            "queue.csv",
            "review.csv",
            "briefing.md",
            "diagnostics.json",
            "manifest.json",
        ):
            assert (out / fname).exists(), f"{fname} missing from output"

    def test_exit_2_bad_enum_in_findings(self, tmp_path: Path) -> None:
        """A row with an invalid severity enum causes fatal ingestion and exit 2."""
        assets = _SAMPLES / "assets.csv"
        findings = tmp_path / "findings_bad.csv"
        findings.write_text(
            "finding_id,asset_id,vulnerability_id,severity,applicability,detected_at,description\n"
            "F-BAD,A-001,SYN-001,NOTAVALUE,confirmed,2026-10-01T00:00:00Z,\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(assets),
                "--findings",
                str(findings),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(_POLICY),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 2, f"Expected 2, got {r.returncode}; stderr: {r.stderr}"

    def test_exit_2_bad_policy(self, tmp_path: Path) -> None:
        """A policy file with a missing required key causes exit 2."""
        bad_policy = tmp_path / "bad_policy.json"
        bad_policy.write_text('{"policy_id": "x"}', encoding="utf-8")
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--findings",
                str(_SAMPLES / "findings.csv"),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(bad_policy),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 2, f"Expected 2, got {r.returncode}; stderr: {r.stderr}"

    def test_exit_2_overwrite_flag_rejected(self, tmp_path: Path) -> None:
        """--overwrite is not supported in v1; passing it produces exit 2."""
        out = tmp_path / "out"
        r = _run(_demo_args(out) + ["--overwrite"])
        assert r.returncode == 2, f"Expected 2, got {r.returncode}"
        assert "overwrite" in r.stderr.lower() or "v1" in r.stderr.lower()

    def test_exit_2_invalid_as_of_no_timezone(self, tmp_path: Path) -> None:
        """A naive (no timezone) --as-of is rejected by argparse with exit 2."""
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--findings",
                str(_SAMPLES / "findings.csv"),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(_POLICY),
                "--as-of",
                "2026-10-19T00:00:00",  # no Z, no offset
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 2, f"Expected 2, got {r.returncode}; stderr: {r.stderr}"

    def test_exit_2_invalid_as_of_format(self, tmp_path: Path) -> None:
        """A malformed --as-of string causes exit 2."""
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--findings",
                str(_SAMPLES / "findings.csv"),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(_POLICY),
                "--as-of",
                "not-a-date",
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 2, f"Expected 2, got {r.returncode}"

    def test_exit_0_no_flags(self, tmp_path: Path) -> None:
        """A dataset where no decision has flags must exit 0."""
        assets = tmp_path / "assets.csv"
        findings = tmp_path / "findings.csv"
        evidence = tmp_path / "evidence.csv"
        policy = tmp_path / "policy.json"

        assets.write_text(
            "asset_id,display_name,business_criticality,internet_exposure,"
            "owner_team,context_updated_at\n"
            "CLEAN-A1,Clean Asset,standard,not_exposed,clean-team,"
            "2026-10-19T00:00:00Z\n",
            encoding="utf-8",
        )
        findings.write_text(
            "finding_id,asset_id,vulnerability_id,severity,applicability,"
            "detected_at,description\n"
            "CLEAN-F1,CLEAN-A1,CLEAN-V1,low,confirmed,2026-10-18T00:00:00Z,\n",
            encoding="utf-8",
        )
        evidence.write_text(
            "evidence_id,vulnerability_id,exploitation_status,source_label,"
            "source_reference,observed_at\n"
            "CLEAN-E1,CLEAN-V1,not_observed,clean-source,"
            "synthetic://clean/CLEAN-V1,2026-10-19T00:00:00Z\n",
            encoding="utf-8",
        )
        policy.write_text(
            json.dumps(
                {
                    "policy_id": "clean-policy",
                    "version": "0.1.0",
                    "description": "Clean policy",
                    "context_freshness_days": 30,
                    "evidence_freshness_days": 7,
                    "rules": list(
                        ["EX-01", "P-01", "P-02", "P-03", "P-04", "P-05", "P-06", "P-07"]
                    ),
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(assets),
                "--findings",
                str(findings),
                "--threat-evidence",
                str(evidence),
                "--policy",
                str(policy),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 0, f"Expected 0, got {r.returncode}; stderr: {r.stderr}"


# ---------------------------------------------------------------------------
# Help and invalid arguments
# ---------------------------------------------------------------------------


class TestHelpAndArguments:
    def test_help_exits_0(self) -> None:
        r = _run(["--help"])
        assert r.returncode == 0

    def test_evaluate_help_exits_0(self) -> None:
        r = _run(["evaluate", "--help"])
        assert r.returncode == 0

    def test_no_subcommand_exits_nonzero(self) -> None:
        r = _run([])
        assert r.returncode != 0

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        r = _run(["notacommand"])
        assert r.returncode != 0

    def test_missing_required_arg_exits_nonzero(self, tmp_path: Path) -> None:
        # Missing --findings.
        r = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--policy",
                str(_POLICY),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# Destination collision and safety
# ---------------------------------------------------------------------------


class TestDestinationSafety:
    def test_existing_directory_rejected(self, tmp_path: Path) -> None:
        """An existing output directory causes exit 1 and leaves it unchanged."""
        out = tmp_path / "existing_run"
        out.mkdir()
        sentinel = out / "sentinel.txt"
        sentinel.write_text("original", encoding="utf-8")

        r = _run(_demo_args(out))
        assert r.returncode == 1, f"Expected 1, got {r.returncode}"
        # Existing artifacts must be unchanged.
        assert sentinel.read_text() == "original"

    def test_existing_regular_file_rejected(self, tmp_path: Path) -> None:
        """An existing regular file at the output path causes exit 1."""
        out = tmp_path / "not_a_dir.txt"
        out.write_text("I am a file", encoding="utf-8")

        r = _run(_demo_args(out))
        assert r.returncode == 1, f"Expected 1, got {r.returncode}"
        # File must be unchanged.
        assert out.read_text() == "I am a file"

    def test_existing_symlink_rejected(self, tmp_path: Path) -> None:
        """An existing symlink at the output path causes exit 1."""
        target = tmp_path / "real_dir"
        target.mkdir()
        link = tmp_path / "link_to_dir"
        link.symlink_to(target)

        r = _run(_demo_args(link))
        assert r.returncode == 1, f"Expected 1, got {r.returncode}"
        # Symlink must still exist and point to the same target.
        assert link.is_symlink()
        assert link.resolve() == target.resolve()

    def test_successful_run_existing_dest_leaves_unchanged(self, tmp_path: Path) -> None:
        """A prior successful run directory is never overwritten; subsequent run exits 1."""
        out = tmp_path / "run"
        first = _run(_demo_args(out))
        assert first.returncode == 3, f"First run failed: {first.stderr}"

        original_content = (out / "decisions.json").read_bytes()
        second = _run(_demo_args(out))
        assert second.returncode == 1
        # Original decisions must be preserved.
        assert (out / "decisions.json").read_bytes() == original_content


# ---------------------------------------------------------------------------
# Fatal run artifact isolation
# ---------------------------------------------------------------------------


class TestFatalRunArtifacts:
    def test_no_decisions_json_on_fatal(self, tmp_path: Path) -> None:
        """Fatal ingestion must not produce decisions.json."""
        bad_findings = tmp_path / "bad.csv"
        bad_findings.write_text(
            "finding_id,asset_id,vulnerability_id,severity,applicability,"
            "detected_at,description\n"
            "F-BAD,A-001,SYN-001,INVALID_SEVERITY,confirmed,"
            "2026-10-01T00:00:00Z,\n",
            encoding="utf-8",
        )
        out = tmp_path / "out"
        r = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--findings",
                str(bad_findings),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(_POLICY),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(out),
            ]
        )
        assert r.returncode == 2
        assert not (out / "decisions.json").exists()
        assert (out / "diagnostics.json").exists()

    def test_write_failure_no_partial_output_at_dest(self, tmp_path: Path) -> None:
        """If staging fails due to an unwritable parent, dest must not be created."""
        # Make a file at dest.parent so tempfile.mkdtemp cannot create files there.
        parent_as_file = tmp_path / "parent_file"
        parent_as_file.write_text("I am a file, not a directory", encoding="utf-8")
        out = parent_as_file / "out"  # dest.parent is a file, not a directory

        r = _run(_demo_args(out))
        # mkdtemp(dir=<file>) raises NotADirectoryError → exit 1 or 2
        assert r.returncode in (1, 2)
        assert not out.exists()


# ---------------------------------------------------------------------------
# review.csv subset
# ---------------------------------------------------------------------------


class TestReviewCsvSubset:
    # Findings with flags in the demo dataset at 2026-10-19T00:00:00Z.
    # Derived from test_evaluate.py golden data and the evidence/asset freshness
    # analysis in the test suite comments.
    _FLAGGED_FINDING_IDS = frozenset(
        {
            "F-001",  # conflicting_threat_evidence (SYN-001 has both active + not_observed)
            "F-004",  # threat_unknown, threat_stale, historical_active (SYN-004 stale active)
            "F-005",  # context_stale (A-004), multiple context/evidence flags
            "F-006",  # conflicting_threat_evidence, possible_duplicate
            "F-007",  # conflicting_threat_evidence, possible_duplicate
            "F-008",  # owner_missing (A-006 has no owner), threat_unknown (SYN-006 no evidence)
            "F-009",  # missing_vulnerability_id, owner_missing, threat_unknown
            "F-011",  # severity_unknown
            "F-012",  # context_stale (A-009), multiple context flags
            "F-013",  # threat_unknown (SYN-010 no evidence)
            "F-014",  # threat_unknown, threat_stale, historical_active (SYN-004 stale active)
            "F-015",  # applicability_unconfirmed, threat_unknown (SYN-011 no evidence)
            "F-016",  # asset_unmatched (UNMATCHED-999 not in assets)
        }
    )
    _UNFLAGGED_FINDING_IDS = frozenset({"F-002", "F-003", "F-010"})

    def test_review_csv_contains_exactly_flagged_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3

        review_path = out / "review.csv"
        rows = list(csv.DictReader(review_path.read_text(encoding="utf-8").splitlines()))
        review_ids = {row["finding_id"] for row in rows}

        assert review_ids == self._FLAGGED_FINDING_IDS, (
            f"review.csv mismatch.\n"
            f"  Extra (unexpected): {review_ids - self._FLAGGED_FINDING_IDS}\n"
            f"  Missing (expected): {self._FLAGGED_FINDING_IDS - review_ids}"
        )

    def test_unflagged_findings_absent_from_review_csv(self, tmp_path: Path) -> None:
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3

        review_path = out / "review.csv"
        rows = list(csv.DictReader(review_path.read_text(encoding="utf-8").splitlines()))
        review_ids = {row["finding_id"] for row in rows}

        for fid in self._UNFLAGGED_FINDING_IDS:
            assert fid not in review_ids, f"{fid} should not appear in review.csv"


# ---------------------------------------------------------------------------
# Manifest hash verification
# ---------------------------------------------------------------------------


class TestManifestHashes:
    def test_artifact_hashes_match_written_bytes(self, tmp_path: Path) -> None:
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3

        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        artifact_hashes = manifest["artifact_hashes"]

        for name, expected_hash in artifact_hashes.items():
            actual_hash = _sha256_file(out / name)
            assert actual_hash == expected_hash, (
                f"Hash mismatch for {name}: manifest says {expected_hash}, file is {actual_hash}"
            )

    def test_manifest_not_in_artifact_hashes(self, tmp_path: Path) -> None:
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3

        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert "manifest.json" not in manifest["artifact_hashes"]

    def test_five_artifact_hashes_present(self, tmp_path: Path) -> None:
        out = tmp_path / "run"
        r = _run(_demo_args(out))
        assert r.returncode == 3

        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        expected_names = {
            "decisions.json",
            "queue.csv",
            "review.csv",
            "briefing.md",
            "diagnostics.json",
        }
        assert set(manifest["artifact_hashes"].keys()) == expected_names


# ---------------------------------------------------------------------------
# Cross-process byte-identical replay
# ---------------------------------------------------------------------------


class TestByteIdenticalReplay:
    _ALL_SIX = [
        "decisions.json",
        "queue.csv",
        "review.csv",
        "briefing.md",
        "diagnostics.json",
        "manifest.json",
    ]

    def test_all_six_artifacts_identical_different_pythonhashseed(self, tmp_path: Path) -> None:
        """Two separate subprocess runs with different PYTHONHASHSEED values must
        produce byte-identical artifacts. This guards against hash-randomized
        collection iteration (frozenset, set) affecting serialization order.
        """
        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"

        r1 = _run(_demo_args(out1), pythonhashseed="12345")
        r2 = _run(_demo_args(out2), pythonhashseed="99999")

        assert r1.returncode == 3, f"Run 1 failed: {r1.stderr}"
        assert r2.returncode == 3, f"Run 2 failed: {r2.stderr}"

        for fname in self._ALL_SIX:
            b1 = (out1 / fname).read_bytes()
            b2 = (out2 / fname).read_bytes()
            assert b1 == b2, (
                f"{fname} differs between runs with different PYTHONHASHSEED.\n"
                f"  SHA-256 run1: {hashlib.sha256(b1).hexdigest()}\n"
                f"  SHA-256 run2: {hashlib.sha256(b2).hexdigest()}"
            )

    def test_policy_content_change_changes_run_id(self, tmp_path: Path) -> None:
        """Changing policy file content (same policy_id/version) must change the run_id."""
        # Build a modified policy with the same id/version but different description.
        original_policy = json.loads(_POLICY.read_text(encoding="utf-8"))

        modified_policy = dict(original_policy)
        modified_policy["description"] = "Modified description — different content"
        modified_policy_path = tmp_path / "modified_policy.json"
        modified_policy_path.write_text(json.dumps(modified_policy), encoding="utf-8")

        out1 = tmp_path / "run_original"
        out2 = tmp_path / "run_modified"

        r1 = _run(_demo_args(out1))
        r2 = _run(
            [
                "evaluate",
                "--assets",
                str(_SAMPLES / "assets.csv"),
                "--findings",
                str(_SAMPLES / "findings.csv"),
                "--threat-evidence",
                str(_SAMPLES / "threat_evidence.csv"),
                "--policy",
                str(modified_policy_path),
                "--as-of",
                _AS_OF,
                "--output-dir",
                str(out2),
            ]
        )

        assert r1.returncode == 3
        assert r2.returncode == 3

        m1 = json.loads((out1 / "manifest.json").read_text(encoding="utf-8"))
        m2 = json.loads((out2 / "manifest.json").read_text(encoding="utf-8"))

        assert m1["run_id"] != m2["run_id"], "Policy content change must produce a different run_id"

    def test_readme_command_succeeds(self, tmp_path: Path) -> None:
        """The documented demo command from CLAUDE.md must succeed (exit 3).

        This verifies the README command works from the repository root.
        """
        out = tmp_path / "demo"
        r = _run(
            [
                "evaluate",
                "--assets",
                "samples/assets.csv",
                "--findings",
                "samples/findings.csv",
                "--threat-evidence",
                "samples/threat_evidence.csv",
                "--policy",
                "policies/demo-policy-v1.json",
                "--as-of",
                "2026-10-19T00:00:00Z",
                "--output-dir",
                str(out),
            ],
            cwd=_REPO_ROOT,
        )
        assert r.returncode == 3, f"Demo command exited {r.returncode}; stderr: {r.stderr}"
        assert (out / "decisions.json").exists()

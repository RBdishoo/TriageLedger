# CTO demonstration and hiring narrative

## Accurate positioning
An independent, explainable vulnerability-triage prototype built for analyst workflow relevance. Not an IEX audit, production deployment, autonomous defense tool or replacement for scanners. Say SaaS prototype only after the service phase exists; local CLI is not SaaS.

## Three-minute demonstration

### Script (with concrete examples from samples/demo/)

**0:00–0:25 — Problem**
"A vulnerability scanner gives you a severity column. But the second-ranked critical finding here
(F-004, synthetic SQL injection SYN-004) is on an unexposed internal reporting database, while
the fourth-ranked high finding (F-001, RCE SYN-001) is on the order router — a critical exposed
service with active exploitation confirmed in threat evidence. Sorting by severity alone puts the
internal database ahead of the active threat. This tool applies an explicit policy to reorder
that queue based on what we actually know."

**0:25–0:50 — Show the inputs**
Open `samples/assets.csv` and point to A-001 (critical, exposed) and A-003 (standard, not_exposed).
Open `samples/findings.csv` and point to F-001 (high, confirmed) and F-004 (critical, confirmed).
Open `samples/threat_evidence.csv` and point to E-001 (SYN-001, active, Oct 17).
Identify an explicit unknown: F-011 has severity=unknown — vendor response pending.

**0:50–1:30 — Run the CLI and show three changed decisions**
```bash
python -m triageledger.cli evaluate \
  --assets samples/assets.csv \
  --findings samples/findings.csv \
  --threat-evidence samples/threat_evidence.csv \
  --policy policies/demo-policy-v1.json \
  --as-of 2026-10-19T00:00:00Z \
  --output-dir artifacts/demo
# exit 3 = completed with review flags (not a failure)
```

If the live run fails, use `samples/demo/` and say: "These are the pre-generated reference
artifacts from the same command. The exit code was 3."

Show the three changed positions from `docs/comparison.md`:

| Finding | Severity-only position | Context-aware position | What changed |
|---|---|---|---|
| F-001 | 4 | 1 | Confirmed active exploitation → P1 (rule P-01) |
| F-004 | 2 | 7 | EX-01/P-01/P-02 do not match; critical severity triggers P-03 → P2; 6 P1 findings precede it |
| F-011 | 15 | 8 | Illustrative unknown-severity rule assigns P2 for expedited clarification (rule P-06) |

Say: "A changed rank is not automatically a better answer. These reflect the assumptions in the
policy. The flags next to each decision tell an analyst where the uncertainty is."

**1:30–2:10 — Trace one rule to its evidence**
Open `samples/demo/decisions.json`, find F-001:
- rule_id: P-01
- effective_exploitation: active
- evidence_ids: ["E-001", "E-009"]
- flags: ["conflicting_threat_evidence"]

"P-01 fires because applicability is confirmed and E-001 shows active exploitation — observed
2 days before as-of, within the 7-day freshness window. E-009 disagrees (not_observed), so the
tool flags the contradiction instead of silently resolving it. The analyst sees both facts."

Show F-012 (A-009, Config Store): context_stale, criticality_unknown, exposure_unknown,
owner_missing — a high-severity finding on an asset whose last inventory update was July 2026.
The finding was not dropped; it carries all its uncertainty flags into the queue.

**2:10–2:40 — Show a regression test and fixed-time replay**
```bash
python -m pytest tests/unit/test_policy.py::test_spec_1_confirmed_fresh_active_is_p1 -v
python -m pytest tests/unit/test_policy.py::test_spec_3_critical_severity_standard_internal_is_p2_p03 -v
python -m pytest tests/integration/test_cli.py::TestReproducibility::test_all_six_artifacts_identical_different_pythonhashseed -v
```

"Each specified scenario has a test written before implementation. The replay test runs the
same command in two processes with different PYTHONHASHSEED values and checks that all six
artifacts are byte-identical."

**2:40–3:00 — State boundaries and next step**
"This is a local CLI prototype on synthetic data. The policy thresholds are illustrative —
the 7-day evidence window and 30-day context window would need calibration against actual
analyst decisions before production use. Ownership is recorded but not verified.

The natural next step would be to collect feedback from a real analyst doing the same triage
task with and without the queue, then adjust rules based on disagreements — not assumptions."

## Questions Ruben should answer without AI
- Why are these priority rules reasonable and where could they fail?
- What does unknown mean and why is it not false?
- What is the difference between severity, exploitation likelihood and business impact?
- Why does the tool not automatically patch?
- What does its explanation establish, and what does it not explain?
- How can an analyst dispute a result?
- Which tests protect the most consequential decisions?
- What would change before hosting real customer data?
- Why is Jev optional and what independent evidence would justify it?

## README top section specification
One sentence problem; short demo image only if real; reproducible command; three before/after decisions; architecture; verified setup/test commands; limitations; explicit synthetic-data disclaimer. Explain claimed metrics with method and sample size. No invented customer logos, SOC 2 claims or enterprise-ready badge.

## Outreach draft to personalize, not send automatically
Subject: Small vulnerability-triage prototype aligned with the IEX security internship

Hi [verified name],
I built a small prototype aligned with the vulnerability-management and risk-assessment work in IEX's Cyber Security Analyst Intern posting. It turns synthetic findings and asset context into a reviewable queue, with evidence, missing-data flags and regression tests.
The short demo shows [actual implemented example]. I deliberately kept the decision policy explicit rather than adding an AI dependency without demonstrated value.
[Repository link] | [Demo link]
I'd welcome your perspective on whether the workflow reflects the kinds of triage decisions an intern could help your team with.
Ruben

Replace every placeholder and verify all claims before use. Do not imply familiarity with internal systems. Sending requires separately resolved recipient and user approval.

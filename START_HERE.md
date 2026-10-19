# Build pack: start here

These are implementation specifications and maintenance instructions, not an implemented application. Place CLAUDE.md at the repository root and the docs directory beside it. Keep these documents in version control. They contain no credentials or real organizational findings.

## First Claude prompt
Read CLAUDE.md and the referenced specifications. Inspect the repository without modifying it. Summarize the proposed CLI architecture, ambiguous requirements, milestone 1 acceptance criteria, and a minimal file-by-file implementation plan. Do not build SaaS, add AI integrations, or claim production readiness. After I approve the plan, implement milestone 1 only, run its tests, and report results honestly.

## Follow-up milestone prompt
Read the current implementation plan and inspect existing code/tests. Identify the next incomplete acceptance gate. Propose one bounded change, implement only after approval, run relevant checks, and update the milestone status. Explain security tradeoffs and any untested assumptions.

## Review prompt
Act as a skeptical security analyst and code reviewer. Trace three decisions from original evidence to output. Check unknown handling, duplicates, staleness, deterministic replay, tenant assumptions, output injection, and misleading claims. Give file/line references for actual defects. Do not invent test results or rewrite the entire codebase.

## Contents
- CLAUDE.md: persistent build instructions.
- docs/01_PRODUCT_AND_ROLE.md: hiring alignment and product boundaries.
- docs/02_ARCHITECTURE.md: modules, flow and service boundary.
- docs/03_DATA_CONTRACTS.md: schemas and failure semantics.
- docs/04_DECISION_POLICY.md: precise illustrative rule specification.
- docs/05_TEST_AND_EVALUATION.md: acceptance gates and evaluation.
- docs/06_SECURITY_AND_SAAS.md: threat model and SaaS release gate.
- docs/07_IMPLEMENTATION_PLAN.md: milestones and exit criteria.
- docs/08_MAINTENANCE.md: versioning, incident and change discipline.
- docs/09_CTO_DEMO.md: reproducible demo and hiring presentation.
- docs/10_SOURCES_AND_DECISIONS.md: evidence and design decisions.

The ZIP preserves the root/docs layout. Individual Markdown files are also supplied. Read the full pack before asking Claude to start coding; the policy is intentionally a demo policy, not validated organizational risk management.

# Maintenance and change control

## Change checklist
1. Identify affected contract, rule, output or security boundary.
2. Add a failing regression test or a clearly specified new acceptance test.
3. Implement the smallest change.
4. Run relevant suite and full checks before release.
5. Compare golden decisions; explain every changed rule/priority/flag.
6. Update policy/schema/tool versions as appropriate, changelog and limitations.
7. Review for sensitive data and unsubstantiated claims before publishing.

Policy behavior changes require policy version changes. Breaking schema changes require schema version changes and migration guidance. Tool implementation fixes may also change outputs; document the impact and never silently relabel historical decisions. Preserve original run artifacts and create a new run for re-evaluation.

## Dependency routine
Review dependency updates periodically and when advisories arise. Keep runtime dependencies minimal. Validate updates through tests and document why new packages are necessary. Do not auto-merge security-sensitive/auth dependencies solely because CI is green.

## Bug report template
Summary; expected/actual behavior; tool/policy/schema versions; synthetic minimal reproduction; exact command and exit code; redacted diagnostics; impact; proposed regression test. Never request production exports through public issues.

## Decision ADR template
Context; options; chosen option; security/analyst tradeoffs; rejected complexity; verification; rollback; date/status. Record choices around scoring, frameworks, tenant isolation and external intelligence.

## Incident routine for later service
Contain access; preserve restricted evidence; identify affected tenants/data; revoke exposed credentials; communicate through defined channels; remediate; validate recovery; record postmortem and regression tests. Notification duties depend on actual obligations, not this document. Do not perform destructive cleanup before evidence is assessed.

## Claude maintenance prompt
Inspect the reported issue and relevant contracts. Reproduce using synthetic data. Propose a minimal fix and regression test. State whether decisions, schemas or security boundaries change. After approval implement, execute tests, report exact results and update version/changelog documents. Do not infer success or rewrite unrelated modules.

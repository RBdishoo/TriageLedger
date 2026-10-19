# Illustrative decision policy v1

This is a transparent portfolio policy, NOT validated organizational policy, SSVC compliance, a CISA mandate, or IEX requirements. Priorities mean analyst-review urgency, not permission to patch automatically. No universal remediation deadlines are asserted.

## Inputs and freshness
Evaluate at explicit UTC as_of. Context is stale when age > 30 * 24 hours; exactly 30 days is fresh. Threat evidence is stale when age > 7 * 24 hours. Future records are input errors. These thresholds are illustrative and stored in validated policy JSON.

Stale criticality/exposure become effective unknown for ranking; retain original values as evidence. A stale owner is unverified, not erased. Fresh active evidence makes effective exploitation active. Stale active evidence produces historical_active flag and effective unknown if no fresh active exists. Fresh not_observed produces not_observed only if no active evidence exists; any stale active history keeps a review flag. Missing/fresh unknown evidence gives unknown. Preserve all references and contradictions.

Missing asset => effective exposure/criticality unknown; flag asset_unmatched and context_missing. Applicability unconfirmed always adds applicability_unconfirmed. A confirmed finding means the supplied data asserts applicability, not that this tool verified it.

## First matching rule wins
| Order / ID | Condition | Output |
|---|---|---|
| 0 / EX-01 | applicability = not_affected | disposition not_affected, priority null; retain record and evidence |
| 1 / P-01 | effective exploitation active AND applicability confirmed | P1: urgent analyst review |
| 2 / P-02 | effective exposure exposed AND effective criticality critical AND severity critical/high | P1: urgent analyst review |
| 3 / P-03 | severity critical OR effective exploitation active | P2: expedited review |
| 4 / P-04 | severity high AND (effective exposure exposed OR effective criticality critical) | P2: expedited review |
| 5 / P-05 | severity high/medium | P3: planned review |
| 6 / P-06 | severity unknown | P2: clarify severity; conservative demo default |
| 7 / P-07 | severity low | P4: routine review |

Unknown context never receives an automatic safe label. These rules may still rank a finding with missing context below another finding; show review flags prominently and state this limitation. Do not claim monotonic safety or validated risk reduction.

## Independent flags
owner_missing, owner_unverified, asset_unmatched, context_missing, context_stale, exposure_unknown, criticality_unknown, severity_unknown, applicability_unconfirmed, threat_unknown, threat_stale, historical_active, conflicting_threat_evidence, missing_vulnerability_id, possible_duplicate.

Absent threat rows -> threat_unknown. Stale evidence -> threat_stale even if fresh evidence also exists. Active and not_observed evidence together -> conflicting_threat_evidence for analyst interpretation, not proof of bad sources. Unknown business/exposure values set their flags. All flags mean review required in v1, including excluded findings, to keep diagnostics visible.

## Actions and explanations
Generate from templates and structured facts. P1: urgent analyst review of applicability, exposure and remediation options; P2: expedited investigation; P3: planned remediation review; P4: routine review. If not_affected: retain the supplied assertion for analyst validation; do not call verified remediated. Append missing-owner/context actions without reducing urgency. Do not generate vendor commands or promise a patch exists.

## Sorting
Actionable rows first by P1..P4, then detected_at ascending, asset_id lexicographically, finding_id lexicographically. Excluded rows follow. No hidden tie-breaker. review.csv uses the same order and includes every flagged decision, including excluded records.

## Change discipline
Policy JSON contains policy_id, semantic version, freshness thresholds and supported rule identifiers; evaluate conditions in tested Python rather than a general expression interpreter. Reject unknown config keys/rules. Changing thresholds, rule order or conditions requires version change, regression fixture diff and rationale. Never silently change prior saved decisions.

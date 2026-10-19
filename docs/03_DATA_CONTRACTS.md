# Data contracts v1

All inputs: UTF-8 CSV with header, bounded file/row/field sizes, explicit supported columns. Reject duplicate headers and unexpected columns to catch typos; a future schema version can add columns. Trim surrounding whitespace on identifiers/enums, not arbitrary descriptions. Reject embedded NULs. No fuzzy asset matching. Use UTC ISO-8601 timestamps ending Z. Non-empty required identifiers; optional blank means unknown, never false.

Default safety limits: 10 MiB/file, 50,000 data rows/file, 8 KiB/field. These are prototype limits, not benchmark results. Return a clear limit error. No IP/domain resolution or URL fetching.

## assets.csv
| Field | Type / semantics |
|---|---|
| asset_id | Required unique opaque ID |
| display_name | Required synthetic label |
| business_criticality | critical, standard, unknown |
| internet_exposure | exposed, not_exposed, unknown |
| owner_team | Optional text; blank produces owner_missing |
| context_updated_at | Required timestamp; may be stale |

Conflicting duplicate asset IDs are fatal because matching becomes ambiguous. Identical duplicates collapse with a diagnostic and count.

## findings.csv
| Field | Type / semantics |
|---|---|
| finding_id | Required unique source identifier |
| asset_id | Required exact reference; unknown ID is retained as unmatched |
| vulnerability_id | Optional identifier; fixture IDs SYN-001 etc. are synthetic, not real CVEs |
| severity | critical, high, medium, low, unknown |
| applicability | confirmed, unconfirmed, not_affected |
| detected_at | Required timestamp, not after as-of |
| description | Optional untrusted text |

Identical repeated finding IDs collapse and are counted. Conflicting records sharing a finding ID are fatal. Different IDs with the same asset/vulnerability are retained and flagged possible_duplicate, not silently merged. A blank vulnerability ID is retained with missing_vulnerability_id; no threat match is attempted.

## threat_evidence.csv
| Field | Type / semantics |
|---|---|
| evidence_id | Required unique ID |
| vulnerability_id | Required exact match key |
| exploitation_status | active, not_observed, unknown |
| source_label | Required e.g. synthetic scenario |
| source_reference | Required opaque reference, not executable/link-fetch instructions |
| observed_at | Required timestamp, not after as-of |

Evidence IDs follow the same identical/conflicting duplicate rule. Preserve multiple evidence records per vulnerability; active evidence is not erased by a later not_observed record. Freshness rules are in policy. not_observed means the supplied source did not observe exploitation; it does not prove absence.

## Structured decision fields
schema_version, run_id, finding_id, asset_id, vulnerability_id, disposition, priority, rule_id, rule_version, explanation, supporting_facts, evidence_ids, flags, owner_team, next_action, as_of, context_age_days, source_row_refs.

priority: P1, P2, P3, P4, or null for excluded/not_affected. disposition: review_recommended or not_affected. P1 is highest. Review flags are independent of priority.

## Error behavior
- Invalid encoding/header, invalid enum/timestamp, conflicting IDs, unreadable file or invalid policy: fatal; no decision artifacts; CLI exit 2.
- Structurally readable but invalid row: retain diagnostic, fail the run in v1 rather than silently using a partial dataset. Diagnostic-only error output is allowed and clearly separate from decisions.
- Unmatched asset, unknown values, missing owner or stale context: valid data, decision plus flags.
- Successful evaluation with at least one review flag: exit 3, complete artifacts. Success without flags: exit 0. Unexpected internal error: exit 1 with safe error message.

Documentation, shell examples and CI must account for exit 3 as a completed run with review required, not an infrastructure failure.

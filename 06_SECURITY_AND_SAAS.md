# Security design and SaaS gate

## Threat model
Protected data: vulnerability details, asset inventory, owners, audit events, identity tokens and threat evidence. Actors: authorized analyst, tenant administrator, malicious authenticated user, compromised integration, accidental operator. CLI trusts the local operator but not file content. SaaS must not trust client-supplied tenant identifiers or object IDs.

| Threat | Required approach | Verification |
|---|---|---|
| CSV/spreadsheet formula execution | Preserve canonical raw text in JSON; prefix dangerous CSV text cells beginning after leading whitespace with =,+,-,@ or control characters with apostrophe; proper CSV quoting | Test malicious cells and target spreadsheet behavior; document compatibility limits |
| Markdown/HTML injection | Escape untrusted Markdown syntax and raw HTML; no active embedded content | Malicious descriptions rendered as text |
| Path traversal/overwrite | Output files use fixed names; no paths derived from input fields; explicit overwrite | Traversal and existing-output tests |
| Resource exhaustion | File, field, row and later request/job limits | Boundary/oversize tests |
| Secrets/data in logs | No raw findings/tokens in routine logs; structured safe diagnostics | Log inspection tests |
| Supply-chain compromise | Minimal dependencies, lock service dependencies, CI checks | Inventory and review results |
| Cross-tenant access | Server-derived tenant scope for every lookup/export/job | Two-tenant negative test suite |
| Unauthorized policy changes | Role-based permissions and audit | Analyst cannot perform admin operation |

## SaaS entry gate
Do not start this phase before CLI acceptance and user approval. Select one deployment architecture in an ADR. Use a single application and database unless measured needs require more. Prefer managed authentication; never write custom password crypto. Separate analyst/read-only/tenant-admin roles. Global platform administration must be separate from tenant administration.

Tenant scope must cover object lookups, search, imports, reports, jobs, object storage, caches, audit events and deletion. Derive scope from verified identity membership; ignore untrusted tenant headers as authority. Authentication alone is insufficient. Test tenant A against B's IDs, exports, job status, batch routes and signed links. If row-level security is used, test connection-pool tenant-context reset; application tests remain required.

## Before accepting real data
- Authorization/tenant-isolation tests pass, including asynchronous paths if present.
- TLS, secret handling, secure cookies/session settings and CSRF protections appropriate to chosen auth design.
- Parameterized database access, reviewed migrations and least-privileged service credentials.
- Retention/deletion policy including backup implications and customer export handling.
- Encrypted storage/backups configured; actual restore exercise recorded.
- Dependency scan findings triaged, not just a green badge.
- Rate/size quotas, timeouts, retry semantics and idempotent imports tested.
- Audit event access restricted; actor, tenant, event, object and time recorded. Append-only application behavior is not tamper-proof evidence.
- Incident runbook, monitoring and rollback tested.
- Explicit approval to handle the proposed data and an honest security review; no compliance claims based on this checklist.

No real IEX data, scanning, integrations or implied authorization. Demo tenant identities and fixtures must be fictional. The product name must not use IEX branding or imply endorsement.

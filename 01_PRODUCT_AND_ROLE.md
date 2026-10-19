# Product and role alignment

## User and job to be done
Primary user: a security analyst who receives scanner findings and imperfect asset inventory. Help them create a defensible, owner-addressable remediation-review queue and a concise briefing. Buyers and production integrations are hypotheses, not validated customer demand.

## Target role evidence
The matching IEX Greenhouse posting, job 8173713, lists risk assessment and management, threat-intelligence monitoring, incident response, vulnerability management, business continuity/disaster recovery, and policy/procedure review. It also asks for scripting familiarity, Excel/tool comfort, analytical thinking, collaboration and written/verbal communication. See source register for the direct posting URL.

| Role requirement | Project evidence | Boundary |
|---|---|---|
| Vulnerability management | Matched findings, context-aware queue, next actions | No scanner or patch installer |
| Risk assessment | Documented rules, uncertainty, decision records | Not a quantitative enterprise risk model |
| Threat intelligence | Dated synthetic evidence with explicit provenance | No claim of a live threat-intelligence operation |
| Policy review | Versioned decision table and change diff | Not IEX policy or full SSVC implementation |
| Python and spreadsheet workflows | CLI, typed parsing, safe CSV export | No need for complex UI |
| Communication and teamwork | Briefing, reviewer feedback and decisions | No fabricated stakeholder endorsement |
| Incident response | Escalation recommendation only | Not an incident detection/response platform |
| Continuity and recovery | Critical-service context; later restore exercise | Not a business continuity program |

## Product promise
Every actionable finding has a priority recommendation, supporting evidence, uncertainty flags, ownership state, next action, and a reproducible policy version.

## Success criteria
- Reviewer can trace each showcased recommendation to data and a rule.
- Input rows are accounted for as accepted, duplicate, quarantined or invalid.
- Same inputs, policy and as-of time give the same substantive output.
- Tests exercise missing/stale/conflicting context rather than only happy paths.
- Three-minute demo shows a real decision change and an honest limitation.

## Non-goals
Do not build a SIEM, scanner, full ticketing system, autonomous remediation, chatbot, risk-probability model, exchange simulator, or claimed enterprise platform. SaaS phase follows validated workflow usefulness. No real target systems or company names in fixtures.

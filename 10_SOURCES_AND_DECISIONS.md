# Sources, assumptions and architectural decisions

## Verified role source
IEX Group (Interns), Cyber Security Analyst Intern, Greenhouse job 8173713:
https://job-boards.greenhouse.io/iex-interns/jobs/8173713
User-provided embed:
https://job-boards.greenhouse.io/embed/job_app?for=iex-interns&token=8173713&jr_id=6aafc305de327d3e210d6f23

Research note, 2026-10-19: the embed could not be fetched; the search-indexed matching direct posting supplied the role text. It lists risk assessment/management, threat intelligence, incident response, vulnerability management, continuity/recovery, policy review, scripting, Excel/security tools and analytical/communication skills. Availability and wording can change; this is not a guarantee of an open role or interview. No private IEX architecture was consulted.

## Public technical references
- NIST SP 800-40r4, Guide to Enterprise Patch Management Planning: https://csrc.nist.gov/pubs/sp/800/40/r4/final
  Basis: patch management includes identification, prioritization, installation and verification; this tool covers a subset.
- CISA SSVC guide: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf
  Basis: contextual decision-tree prioritization. Our illustrative policy is not full SSVC.
- FIRST EPSS FAQ: https://www.first.org/epss/faq
  Basis: exploitation prediction has a defined target and is not complete organizational risk.
- NIST AI RMF 1.0: https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
  Basis: intended-use validation and interpretation; not model-specific endorsement.
- AWS SaaS tenant isolation: https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/tenant-isolation.html
  Basis: authentication alone does not establish isolation.

## Chosen design decisions
ADR-001: CLI first. Reason: demonstrate analyst value before hosting complexity. Revisit after acceptance and user approval.
ADR-002: deterministic demo rules. Reason: inspection, regression testing and replay. Limitation: policy remains unvalidated for a real organization.
ADR-003: no AI runtime dependency. Reason: no demonstrated need; Jev identity, prediction target and validation are unverified. Revisit only with model documentation, permitted data and independent evaluation.
ADR-004: synthetic inputs and no network. Reason: safe, reproducible hiring artifact without unauthorized collection.
ADR-005: SaaS security separate from policy validity. Reason: a secure service can still make poor recommendations and a good evaluator can still leak tenant data.

## Assumptions requiring validation
Scanner-export mapping, inventory quality, reviewer agreement, customer demand, acceptable false negatives, actual organization response policy, deployment requirements, Jev capabilities, and performance under real workloads are unknown. Do not turn them into facts in generated code, README or outreach.

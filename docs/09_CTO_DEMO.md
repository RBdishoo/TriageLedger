# CTO demonstration and hiring narrative

## Accurate positioning
An independent, explainable vulnerability-triage prototype built for analyst workflow relevance. Not an IEX audit, production deployment, autonomous defense tool or replacement for scanners. Say SaaS prototype only after the service phase exists; local CLI is not SaaS.

## Three-minute demonstration
0:00-0:25 Problem: severity alone misses context, while inventory and ownership can be incomplete.
0:25-0:50 Show small synthetic scanner and inventory inputs; identify an explicit unknown.
0:50-1:30 Run the verified CLI and compare severity-only/context-aware ordering. Show three changed decisions, not a wall of charts.
1:30-2:10 Trace one rule to its evidence; show an unmatched asset or stale record that did not disappear.
2:10-2:40 Show a regression test and fixed-time replay. If live demo fails, use honestly labeled pre-generated artifacts and explain the failure.
2:40-3:00 State boundaries, reviewer feedback if real, and the next evidence-driven improvement.

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

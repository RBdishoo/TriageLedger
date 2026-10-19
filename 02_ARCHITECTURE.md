# Architecture

## v1 flow
CSV files -> strict parsers -> validation/reconciliation -> normalized records -> pure policy evaluator -> decision records -> CSV/JSON/Markdown outputs.

## Module responsibilities
- models.py: typed dataclasses/enums and field validation primitives.
- ingest.py: bounded local file reads, schema checks, normalization, reconciliation, diagnostics. No network.
- policy.py: load validated policy config; evaluate one finding against context; return structured decision. No filesystem, clock or network calls in evaluator.
- reporting.py: deterministic rendering, escaping, summaries and manifest. No decision logic.
- cli.py: argument handling, UTC as-of injection, orchestration, exit codes, safe output publication.

CLI imports the library; the library never imports CLI. Keep matching, policy and rendering separately testable. Do not hide logic in Markdown templates or endpoint handlers.

## Run artifacts
- decisions.json: canonical structured decisions and provenance.
- queue.csv: spreadsheet-friendly queue, including unknown-owner cases.
- review.csv: overlapping subset requiring data/analyst investigation, not a separate lower priority.
- diagnostics.json: row-level errors, duplicate decisions and reconciliation counts.
- briefing.md: top actions, uncertainty counts, limitations, no invented remediation guidance.
- manifest.json: schema/policy/tool versions, as-of, input hashes, row counts and artifact hashes. Store manifest hash externally if needed; do not hash manifest into itself.

Hashes support replay/integrity checks, not authentication or tamper-proof audit. Raw timestamps and random IDs must not break fixed-time reproducibility. Derive run identity from canonical inputs/policy/as-of; keep optional wall-clock telemetry outside deterministic artifacts.

## Publication semantics
Validate all files and policy before generating recommendations. Write artifacts to a temporary sibling directory and publish only after success. Existing destination requires explicit overwrite flag. A fatal run publishes no partial decision set. Fail clearly if atomic replacement is unsupported; do not promise crash-safe storage without testing.

## Service evolution
Only after CLI gates pass, wrap the same domain evaluator in a thin authenticated application. A proposed minimal stack is FastAPI + PostgreSQL with migrations and managed identity integration; adoption requires an architecture decision. A background queue is deferred until actual processing duration/reliability needs justify it. The service adds tenant-scoped persistence and audit events; it must not fork decision logic.

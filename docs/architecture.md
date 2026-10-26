# Architecture and Phase 0 Boundaries

## Product boundary

The initial product is a local-first static analysis tool for Windows PE files.
It does not execute samples, detonate malware, or automatically submit data
to external services.

## Planned data flow

1. CLI accepts an explicit input path and optional report destination.
2. Input gate validates the path, file size, extension, and basic file format.
3. Static analyzers extract bounded observations from the file.
4. Evidence normalization gives observations stable identifiers and consistent
   fields.
5. Deterministic rules derive explainable findings from the evidence.
6. A versioned report object is validated.
7. JSON is written as the canonical report; Markdown can be derived from it.

This describes the intended architecture. It is not a claim that these
components have already been implemented.

## Component responsibilities

- CLI: arguments, user-facing errors, and exit status.
- Input gate: path, size, format, and read-safety checks.
- Analyzers: read-only extraction of structural observations.
- Evidence layer: normalized, traceable observations.
- Detection layer: deterministic rules and cautious hypotheses.
- Reporting: schema-valid JSON and derived Markdown.
- Optional future AI layer: explain existing evidence without inventing
  observations or overriding deterministic results.

## Safety boundary

Submitted files are data, never programs to run. No execution, dynamic loading,
shell invocation, or automatic upload is permitted in the initial release.

## Evidence contract

Each evidence item should have:
- A stable identifier within the report.
- A category and concise description.
- A source identifying the analyzer or rule.
- A value or summary appropriate to the evidence type.
- A rationale or explanation.
- A confidence value where meaningful.
- Caveats where interpretation is uncertain.

Observed facts must be distinguishable from derived hypotheses.

## Report contract

The JSON report must:
- Identify its schema version.
- Record file metadata and a cryptographic hash when available.
- Separate evidence from findings.
- Include warnings and analysis status.
- Avoid claiming that an analysis result proves a file is safe.
- Validate against the committed JSON Schema.

## Evaluation plan

Use harmless synthetic fixtures for:
- Valid minimal PE structure.
- Invalid and truncated inputs.
- Unsupported formats.
- Oversized files.
- Path and report-writing edge cases.
- Schema validation and required report fields.

Tests must not execute sample files or depend on live malware.

## Phase 0 exit criteria

- Setup instructions can recreate the environment.
- Safety and scope are documented.
- Report schema is versioned and committed.
- Acceptance tests pass locally.
- The no-execution policy is explicit and tested.

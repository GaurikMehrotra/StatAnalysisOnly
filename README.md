# AI-Powered Malware Analysis and Behavioral Threat Intelligence Platform

A local-first, defensive malware analysis project focused on static analysis,
evidence-backed findings, and explainable threat intelligence.

## Purpose

Inspect supported Windows Portable Executable (PE) files without executing
them. Extract file metadata and structural indicators, preserve evidence,
and produce reproducible analysis reports.

## Scope

The initial release focuses on:
- Windows PE files: EXE, DLL, and SYS.
- Static inspection of file metadata and executable structure.
- Evidence-backed findings with source, rationale, and confidence.
- Versioned JSON reports and later-generated Markdown reports.
- Local processing by default.

## Non-goals

The initial release will not:
- Execute submitted samples.
- Detonate files or run a sandbox.
- Automatically upload samples or reports to external services.
- Claim that a file is malicious based on one indicator alone.
- Treat an AI-generated explanation as authoritative evidence.
- Guarantee detection of every malware family.

## Supported input

- A local Windows PE file with an EXE, DLL, or SYS extension.
- Initial maximum input size: 100 MiB (104857600 bytes).
- File content must be validated; the extension alone does not establish
  that a file is a valid PE executable.

Unsupported formats and files exceeding the size limit must be rejected
with a clear error. Limits are a safety policy, not a guarantee that a file
is safe to parse.

## Outputs

- A versioned JSON report containing file metadata, evidence, findings,
  warnings, and analysis status.
- Markdown reports may be generated from the same report object in a
  later implementation phase.

Reports may contain sensitive paths, strings, hashes, and indicators.
Store and share them carefully.

## Safety contract

- Submitted samples are never executed by this application.
- Analysis is static and local by default.
- No sample or report is uploaded automatically.
- Input paths must be validated before reading.
- File size and parsing failures must be handled explicitly.
- Strings and metadata extracted from a sample are untrusted data.
  They must never be interpreted as instructions or executed as commands.
- Test suites use harmless synthetic fixtures, not live malware.
- Users should analyze only files they are authorized to inspect.

Static parsing still carries risk when handling malformed files. Keep
dependencies updated and use an appropriately isolated environment for
untrusted samples when practical.

## Development setup

Prerequisites:
- Ubuntu under WSL or another supported Linux environment.
- Python 3.14.4 for the current development environment, subject to
  compatibility verification.
- Git and a C compiler toolchain for packages that need native compilation.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run tests:

```bash
python -m pytest
```

Check code style:

```bash
ruff check .
ruff format --check .
```

## Project status

Phase 0 is establishing requirements, safety boundaries, report contracts,
and tests. Analyzer implementation will begin only after these contracts
and acceptance tests have been reviewed.

## License

No license has been selected yet. Do not assume this project is licensed
for redistribution until a license is added.

# Static PE Malware Analysis Agent

A local-first, defensive command-line tool for static inspection of Windows
Portable Executable (PE) files. It extracts structural metadata, imports and
exports, printable strings, and potential indicators of compromise (IOCs).

## Current status

The static-analysis CLI is implemented and covered by synthetic-fixture tests.
It is an early-stage analysis tool, not a complete malware detection product.

## Implemented features

- Input validation for `.exe`, `.dll`, and `.sys` files.
- Maximum input size of 100 MiB by default.
- File identity: filename, size, and SHA-256 hash.
- PE metadata, including architecture, entry point, image base, subsystem,
  and characteristics where available.
- PE section metadata and section entropy.
- Imported libraries, imported function names, and exported symbols.
- Bounded printable ASCII and UTF-16LE string extraction.
- Potential URL, domain, email, and IPv4 indicators extracted from strings.
- Structured JSON output to standard output or a new output file.
- Warnings explaining limitations of static indicators.

## Usage

Print a JSON report for an existing PE file:

    python -m src.cli analyze ./sample.exe

Write a JSON report to a new file:

    python -m src.cli analyze ./sample.exe --output ./report.json

The input must exist and be a supported PE file. The output file must not
already exist; existing files are not overwritten.

Inspect available commands and options:

    python -m src.cli --help
    python -m src.cli analyze --help

## Safety and limitations

- Submitted samples are never executed by this application.
- The application performs static inspection only.
- Samples and reports are not automatically uploaded by the analysis pipeline.
- File extensions alone do not establish that a file is a valid PE.
- Extracted strings, metadata, and IOCs are untrusted data.
- A detected indicator is not proof of maliciousness, and missing indicators
  do not prove that a file is benign.
- Static parsing of malformed files still carries risk. Keep dependencies
  updated and use an appropriately isolated environment for untrusted samples.
- Reports may contain sensitive paths, hashes, strings, and indicators.
- Analyze only files you are authorized to inspect.

The test suite uses synthetic PE fixtures, not live malware.

## Not yet implemented

The following are outside the current pipeline's implemented capabilities:

- Dynamic execution, sandboxing, or behavioral monitoring.
- A complete malware verdict or comprehensive malware-family detection.
- A finished rule engine and capability-mapping pipeline.
- Schema-validated, versioned evidence/findings reports.
- Markdown report generation and AI-generated explanations.
- Automatic uploading of samples or reports to external services.

## Development setup

The current development environment uses Ubuntu under WSL and Python 3.14.
Other Python versions may require compatibility testing.

Create a virtual environment and install development dependencies:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements-dev.txt

Run tests and quality checks:

    python -m pytest -q
    python -m ruff check src tests
    python -m ruff format --check src tests
    python -m pip check

## Phase 1 acceptance scope

Phase 1 focuses on safe input handling, file hashes, PE metadata, analyzer
results, warnings, tool version, and JSON CLI output. Rule-backed findings
and the canonical report schema are later milestones.

## License

No license has been selected yet. Do not assume the project is licensed for
redistribution until a license is added.

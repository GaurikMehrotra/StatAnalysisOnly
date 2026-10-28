# Static PE Malware Analysis Agent

A local-first, defensive command-line tool for static inspection of Windows
Portable Executable (PE) files. It extracts structural metadata, imports and
exports, printable strings, potential indicators of compromise (IOCs), and
evidence-backed rule findings.

## Current status

This is an early-stage static-analysis and triage tool, not a complete malware
detection product. Its results are evidence-based leads for analyst review,
not definitive malware verdicts.

## Implemented features

- Input validation for `.exe`, `.dll`, and `.sys` files.
- Configurable maximum input size, defaulting to 100 MiB.
- File identity, including filename, size, and SHA-256 hash.
- PE metadata, including architecture, entry point, image base, subsystem,
  and characteristics where available.
- PE section metadata, permissions, and section entropy.
- Imported libraries, imported function names, and exported symbols.
- Bounded printable ASCII and UTF-16LE string extraction.
- Potential URL, domain, email, and IPv4 indicators extracted from strings.
- Structured evidence records with stable identifiers, caveats, and provenance.
- Versioned JSON reports validated against the canonical JSON Schema.
- Markdown reports rendered from the same report object as JSON.
- Rule-backed capability findings with linked evidence and triage warnings.
- Conservative MITRE ATT&CK candidate mapping from explicitly configured
  mappings; the default mapping catalog is empty.
- A JSON report-validation CLI command.
- A synthetic-fixture evaluation harness with report validity, repeatability,
  runtime, and regression metrics.
- An optional local AI explanation mode with bounded structural context,
  evidence-ID validation, and graceful fallback when the model is unavailable.

## Usage

Print a JSON report:

    python -m src.cli analyze ./sample.exe

Render a Markdown report:

    python -m src.cli analyze ./sample.exe --format markdown

Write a JSON report to a new file:

    python -m src.cli analyze ./sample.exe --output ./report.json

Write a Markdown report to a new file:

    python -m src.cli analyze ./sample.exe --format markdown --output ./report.md

Validate an existing JSON report:

    python -m src.cli validate-report ./report.json

Inspect commands and options:

    python -m src.cli --help
    python -m src.cli analyze --help

The input must exist and pass the input and PE validation checks. Output files
are created exclusively; existing files are not overwritten.

### Optional local AI explanations

AI explanations are disabled by default. Deterministic findings and triage remain
the primary analysis results; the optional model does not set or change the
deterministic findings or triage score.

To use the feature, install and start [Ollama](https://ollama.com/download)
separately, then obtain the default model:

    ollama pull llama3.2:3b

With Ollama serving locally at `http://127.0.0.1:11434`, request an explanation:

    python -m src.cli analyze ./sample.exe --explain
    python -m src.cli analyze ./sample.exe --explain --model llama3.2:3b --format markdown

The adapter accepts loopback endpoints only. Use `--model-url` to select a
supported local loopback endpoint and `--ai-timeout` to set the request timeout.
The default model is `llama3.2:3b`; see the command help for all options.

The adapter sends bounded structural metadata and evidence identifiers to the
local model, not raw file bytes, raw IOC values, file hashes, or free-text
evidence descriptions. The application does not upload the sample or report
through this feature. Installing or obtaining a model through Ollama may require
network access.

If the local service is unavailable, times out, or returns invalid output, the
analysis report is still produced with an AI-explanation status or fallback
reason. Accepted AI claims must reference evidence identifiers already present
in the report. This provides traceability, not proof that an explanation is
correct. AI-generated text is clearly labeled and must not be treated as a
verified detection or as a replacement for analyst review.

## Evaluation

Run the synthetic end-to-end evaluation:

    python scripts/evaluate.py
    python scripts/evaluate.py --repeat-runs 5
    python scripts/evaluate.py --output evaluation-results/metrics.json

The evaluation generates fixtures in a temporary directory. It does not execute
the fixtures or upload samples or reports. See [docs/evaluation.md](docs/evaluation.md)
for the fixture matrix, metric definitions, and limitations.

The fixtures are synthetic regression cases, not a representative malware or
benign-software corpus. They cannot establish production detection accuracy,
precision, recall, or a meaningful real-world false-positive rate.

## Safety and limitations

- Submitted samples are never executed by this application.
- The application performs static inspection only.
- Samples and reports are not automatically uploaded by the analysis pipeline.
- Optional AI explanations require a separately running local Ollama service;
  model output is untrusted, may be incorrect, and does not establish maliciousness.
- File extensions alone do not establish that a file is a valid PE.
- Extracted strings, metadata, imports, and IOCs are untrusted evidence.
- An imported function does not prove that the function is called at runtime.
- A detected indicator is not proof of maliciousness, and missing indicators
  do not prove that a file is benign.
- ATT&CK mappings are candidates, not confirmed behavior. The default mapping
  catalog is empty until an analyst explicitly configures supported mappings.
- Static parsing of malformed files still carries risk. Keep dependencies
  updated and use an appropriately isolated environment for untrusted samples.
- Reports may contain sensitive paths, hashes, strings, and indicators.
- Analyze only files you are authorized to inspect.

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
    python -m ruff check src tests scripts
    python -m ruff format --check scripts/evaluate.py tests/test_evaluation_harness.py
    python -m pip check

## Project boundaries

The project focuses on defensive static PE analysis and evidence-backed triage.
Dynamic execution, sandboxing, behavioral monitoring, comprehensive malware
family detection, and definitive malware verdicts are outside the current scope.

No license has been selected yet. Do not assume the project is licensed for
redistribution until a license is added.

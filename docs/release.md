# Phase 5 — Hardening, Documentation and Release

## Supported Python versions

The project declares Python 3.11 or later. CI checks Python 3.11 and 3.14.

## Verification

Run dependency checks, tests, lint, deterministic evaluation, and distribution builds before release. Verify every supported Python version in CI.

## Safety limitations

Synthetic fixtures do not establish real-world detection accuracy. Input and report size limits are safeguards, not guarantees against every parser vulnerability.

## Release checklist

- [ ] Tests, lint, dependency checks, and evaluation pass.
- [ ] Python 3.11 and 3.14 checks pass.
- [ ] Distribution artifacts build successfully.
- [ ] Documentation and version information are reviewed.
- [ ] Artifacts are inspected before publication.

## Clean-environment verification

Install the project and development tools in a clean virtual environment:

    python -m pip install -e ".[dev]"
    python -m pip check
    python -m pytest --cov=src --cov-report=term-missing
    python -m ruff check src tests scripts
    python scripts/evaluate.py --repeat-runs 3
    python -m build

Inspect the generated wheel and source archive before publication. Do not
publish until the CI matrix passes and the release checklist is reviewed.

## Scope

This release provides static PE triage, not dynamic analysis or a definitive
malware verdict. Evaluation uses synthetic fixtures and does not establish
real-world detection accuracy. No license has been selected; do not assume
redistribution permissions.

# Phase 3 Evaluation

## Purpose

This evaluation checks the static-analysis pipeline against a small, repeatable
set of synthetic PE fixtures. It is a regression check, not a malware-detection
benchmark.

## Run

From the project root, with the development environment activated:

    python scripts/evaluate.py
    python scripts/evaluate.py --repeat-runs 5
    python scripts/evaluate.py --output evaluation-results/metrics.json

The fixtures are generated in a temporary directory. The evaluation does not
execute them, contact external services, or upload samples or reports.

## Fixture matrix

| Fixture | Expected behavior |
| --- | --- |
| `benign_no_indicators` | Analysis succeeds, the JSON report validates, and no rule-backed findings are emitted |
| `indicator_strings` | Analysis succeeds, the report validates, and IOC-category evidence is emitted |
| `malformed_pe` | The CLI rejects the input rather than producing a successful report |

The synthetic no-indicator fixture is a limited control, not a claim that the
file represents the diversity of legitimate Windows software.

## Metrics

- `valid_fixture_analysis_success_rate`: successful analyses divided by all
  attempts on the two valid synthetic fixtures.
- `json_report_validity_rate`: schema-valid JSON reports divided by successful
  valid-fixture analyses.
- `repeatable_valid_case_rate`: valid fixtures whose JSON output is identical
  across repeated runs, divided by the number of valid fixtures.
- `median_runtime_ms`: median wall-clock time for the case in this environment.
  This is descriptive and is not a cross-machine performance guarantee.
- `benign_control_finding_count`: number of findings on the synthetic
  no-indicator control.
- `observed_false_positive_rate`: intentionally `null`; this fixture set is too
  small and unrepresentative to estimate a meaningful false-positive rate.

A passing evaluation means only that these defined checks passed on these
fixtures. It does not establish that the tool detects all malware, that a file
is safe, or that the observed false-positive rate is low in production.

## Limitations and next additions

The initial set does not measure malware-family detection, recall, precision,
or real-world false-positive rates. It does not include a broad corpus of
benign applications or labeled malware. Future fixture additions should remain
synthetic or otherwise safely controlled, document expected results, and avoid
committing executable samples.

"""Regression tests for the synthetic end-to-end evaluation harness."""

import pytest

from scripts.evaluate import make_synthetic_pe, run_evaluation


def test_synthetic_pe_fixtures_have_expected_signatures():
    plain = make_synthetic_pe()
    indicators = make_synthetic_pe(include_indicators=True)

    assert plain.startswith(b"MZ")
    assert b"PE\x00\x00" in plain
    assert b"https://updates.example.org/check" not in plain

    assert indicators.startswith(b"MZ")
    assert b"https://updates.example.org/check" in indicators
    assert b"analyst@example.net" in indicators


def test_evaluation_passes_all_cases_and_reports_core_metrics():
    result = run_evaluation(repeat_runs=2)

    assert result["passed"] is True
    assert result["evaluation_version"] == "1.0.0"
    assert {case["case_id"] for case in result["cases"]} == {
        "benign_no_indicators",
        "indicator_strings",
        "malformed_pe",
    }
    assert all(case["passed"] for case in result["cases"])
    assert all(not case["errors"] for case in result["cases"])

    metrics = result["metrics"]
    assert metrics["valid_fixture_analysis_success_rate"] == 1.0
    assert metrics["json_report_validity_rate"] == 1.0
    assert metrics["repeatable_valid_case_rate"] == 1.0
    assert metrics["valid_report_runs"] == 4
    assert metrics["observed_false_positive_rate"] is None


def test_no_indicator_control_has_no_findings():
    result = run_evaluation(repeat_runs=2)
    case = next(
        case for case in result["cases"] if case["case_id"] == "benign_no_indicators"
    )

    assert case["benign_control_no_findings"] is True
    assert case["finding_count"] == 0


def test_indicator_fixture_emits_ioc_evidence():
    result = run_evaluation(repeat_runs=2)
    case = next(
        case for case in result["cases"] if case["case_id"] == "indicator_strings"
    )

    assert case["ioc_evidence_count"] > 0


def test_malformed_fixture_is_rejected():
    result = run_evaluation(repeat_runs=2)
    case = next(case for case in result["cases"] if case["case_id"] == "malformed_pe")

    assert case["rejected_runs"] == 1
    assert case["valid_report_runs"] == 0


def test_repeat_runs_must_be_at_least_two():
    with pytest.raises(ValueError, match="at least 2"):
        run_evaluation(repeat_runs=1)

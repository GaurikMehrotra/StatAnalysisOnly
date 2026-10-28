"""Repeatable, synthetic-fixture evaluation of the static PE analysis CLI."""

from __future__ import annotations

import argparse
import json
import statistics
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def make_synthetic_pe(*, include_indicators: bool = False) -> bytes:
    """Build a minimal PE32 fixture; this function never executes it."""
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # x86
        0,  # sections
        0x12345678,
        0,
        0,
        224,  # optional-header size
        0x0102,
    )

    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x010B)  # PE32
    struct.pack_into("<I", optional, 16, 0x1000)  # entry point
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x1000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)

    content = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional)
    if include_indicators:
        content += b"\x00https://updates.example.org/check\x00analyst@example.net\x00"
    return content


def run_evaluation(repeat_runs: int = 3) -> dict[str, Any]:
    if repeat_runs < 2:
        raise ValueError("repeat_runs must be at least 2")

    from typer.testing import CliRunner

    from src.cli import app
    from src.reporting import ReportValidationError, validate_report

    runner = CliRunner()
    case_results: list[dict[str, Any]] = []
    successful_valid_runs = 0
    valid_report_runs = 0
    expected_valid_runs = 2 * repeat_runs
    repeatable_valid_cases = 0
    benign_control_findings = 0
    all_expectations_passed = True

    with tempfile.TemporaryDirectory(prefix="malware-agent-eval-") as tmp:
        fixture_dir = Path(tmp)

        cases = [
            {
                "id": "benign_no_indicators",
                "path": fixture_dir / "benign-no-indicators.exe",
                "content": make_synthetic_pe(),
                "expected_valid_pe": True,
            },
            {
                "id": "indicator_strings",
                "path": fixture_dir / "indicator-strings.exe",
                "content": make_synthetic_pe(include_indicators=True),
                "expected_valid_pe": True,
            },
            {
                "id": "malformed_pe",
                "path": fixture_dir / "malformed.exe",
                "content": b"MZ" + b"\x00" * 30,
                "expected_valid_pe": False,
            },
        ]

        for case in cases:
            case["path"].write_bytes(case["content"])
            durations_ms: list[float] = []
            outputs: list[str] = []
            valid_reports: list[dict[str, Any]] = []
            rejected_runs = 0
            successful_analysis_runs = 0
            errors: list[str] = []

            runs = repeat_runs if case["expected_valid_pe"] else 1
            for _ in range(runs):
                started = time.perf_counter()
                result = runner.invoke(app, ["analyze", str(case["path"])])
                durations_ms.append((time.perf_counter() - started) * 1000)

                if not case["expected_valid_pe"]:
                    if result.exit_code != 0 and "rejected" in result.output.lower():
                        rejected_runs += 1
                    else:
                        errors.append("Malformed fixture was not rejected as expected.")
                    continue

                if result.exit_code != 0:
                    errors.append(
                        f"CLI exited with {result.exit_code}: {result.output[-500:]}"
                    )
                    continue

                successful_valid_runs += 1
                successful_analysis_runs += 1
                outputs.append(result.output)

                try:
                    report = json.loads(result.output)
                    validate_report(report)
                except (json.JSONDecodeError, ReportValidationError) as exc:
                    errors.append(f"Invalid JSON report: {exc}")
                    continue

                valid_report_runs += 1
                valid_reports.append(report)

            repeatable = (
                (len(outputs) == repeat_runs and len(set(outputs)) == 1)
                if case["expected_valid_pe"]
                else None
            )

            if case["expected_valid_pe"] and repeatable:
                repeatable_valid_cases += 1
            elif case["expected_valid_pe"]:
                errors.append("Repeated JSON output was not byte-for-byte identical.")

            ioc_evidence_count = 0
            finding_count = 0
            no_findings = None

            if valid_reports:
                report = valid_reports[0]
                finding_count = len(report["findings"])
                ioc_evidence_count = sum(
                    evidence["category"] == "ioc" for evidence in report["evidence"]
                )

                if case["id"] == "benign_no_indicators":
                    benign_control_findings = finding_count
                    no_findings = finding_count == 0
                    if not no_findings:
                        errors.append(
                            "No-indicator control produced findings; "
                            "review these as potential false positives."
                        )

                if case["id"] == "indicator_strings" and ioc_evidence_count == 0:
                    errors.append(
                        "Indicator fixture produced no IOC-category evidence."
                    )

            passed = not errors
            all_expectations_passed &= passed

            case_results.append(
                {
                    "case_id": case["id"],
                    "expected_valid_pe": case["expected_valid_pe"],
                    "runs": runs,
                    "rejected_runs": rejected_runs,
                    "successful_analysis_runs": successful_analysis_runs,
                    "valid_report_runs": (
                        len(valid_reports) if case["expected_valid_pe"] else 0
                    ),
                    "median_runtime_ms": round(statistics.median(durations_ms), 3),
                    "repeatable_json": repeatable,
                    "ioc_evidence_count": ioc_evidence_count,
                    "finding_count": finding_count,
                    "benign_control_no_findings": no_findings,
                    "passed": passed,
                    "errors": errors,
                }
            )

    total_valid_reports_expected = expected_valid_runs
    report_validity_rate = (
        valid_report_runs / successful_valid_runs if successful_valid_runs else 0.0
    )
    parser_success_rate = successful_valid_runs / expected_valid_runs
    repeatability_rate = repeatable_valid_cases / 2

    return {
        "evaluation_version": "1.0.0",
        "fixture_policy": (
            "Synthetic byte fixtures only; no sample execution, "
            "network lookups, or external uploads."
        ),
        "repeat_runs": repeat_runs,
        "metrics": {
            "valid_fixture_analysis_success_rate": round(parser_success_rate, 4),
            "json_report_validity_rate": round(report_validity_rate, 4),
            "repeatable_valid_case_rate": round(repeatability_rate, 4),
            "expected_valid_report_runs": total_valid_reports_expected,
            "valid_report_runs": valid_report_runs,
            "benign_control_finding_count": benign_control_findings,
            "observed_false_positive_rate": None,
            "false_positive_rate_note": (
                "Not estimated: one synthetic no-indicator control is not "
                "a representative benign corpus."
            ),
        },
        "cases": case_results,
        "passed": all_expectations_passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the static PE pipeline on synthetic fixtures."
    )
    parser.add_argument(
        "--repeat-runs",
        type=int,
        default=3,
        help="Number of runs per valid fixture (minimum: 2).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the metrics JSON; prints to stdout by default.",
    )
    args = parser.parse_args()

    try:
        metrics = run_evaluation(args.repeat_runs)
    except ValueError as exc:
        parser.error(str(exc))

    rendered = json.dumps(metrics, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = args.output.expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)

        try:
            with destination.open("x", encoding="utf-8") as stream:
                stream.write(rendered)
        except FileExistsError:
            parser.error(f"Output file already exists: {destination}")
        except OSError as exc:
            parser.error(f"Cannot write evaluation output: {exc}")
    else:
        print(rendered, end="")

    return 0 if metrics["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

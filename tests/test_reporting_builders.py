"""Tests for canonical JSON and Markdown report builders."""

import json
from pathlib import Path

import pytest

from src.reporting import (
    ReportValidationError,
    render_json_report,
    render_markdown_report,
    validate_report,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "report.schema.json"


def minimal_valid_report() -> dict:
    """Build a minimal report satisfying the existing report contract."""
    return {
        "schema_version": "1.0.0",
        "analysis_status": "completed",
        "file": {
            "name": "fixture.exe",
            "size_bytes": 12,
            "sha256": "a" * 64,
            "format": "PE",
        },
        "evidence": [],
        "findings": [],
        "attack_candidates": [],
        "triage": {
            "ruleset_version": "1.0.0",
            "status": "no_rule_match",
            "score": 0,
            "raw_score": 0,
            "score_cap": 100,
            "severity": "unknown",
            "matched_rule_ids": [],
            "findings": [],
            "score_breakdown": [],
            "warnings": ["No matching rule does not mean the file is safe."],
        },
        "tool": {"name": "malware-analysis-agent", "version": "0.1.0"},
        "status": "static_analysis_completed",
        "input": {},
        "pe_metadata": {},
        "section_analysis": {},
        "import_analysis": {},
        "string_analysis": {},
        "ioc_analysis": {"iocs": []},
        "warnings": ["Static analysis only."],
    }


def test_valid_report_passes_schema_validation():
    validate_report(minimal_valid_report(), SCHEMA_PATH)


def test_json_renderer_is_deterministic_and_valid():
    report = minimal_valid_report()

    first = render_json_report(report, SCHEMA_PATH)
    second = render_json_report(report, SCHEMA_PATH)

    assert first == second
    assert json.loads(first) == report


def test_invalid_report_is_rejected_before_rendering():
    report = minimal_valid_report()
    del report["file"]["sha256"]

    with pytest.raises(ReportValidationError, match="sha256"):
        render_json_report(report, SCHEMA_PATH)


def test_markdown_reflects_report_findings_and_evidence():
    report = minimal_valid_report()
    report["evidence"] = [
        {
            "schema_version": "1.0.0",
            "id": "ev_0123456789abcdef",
            "category": "import",
            "description": "Imported API observed",
            "source": "import_analyzer",
            "value": {"api": "VirtualAlloc"},
            "location": None,
            "confidence": 0.9,
            "severity": "informational",
            "rationale": "Synthetic test evidence.",
            "caveats": ["An import does not prove runtime behavior."],
            "record_type": "observation",
        }
    ]
    report["findings"] = [
        {
            "id": "CAP-TEST",
            "rule_version": "1.0.0",
            "title": "Memory allocation API imported",
            "capability": "memory_management",
            "severity": "low",
            "weight": 10,
            "rule_ids": ["CAP-TEST"],
            "evidence_ids": ["ev_0123456789abcdef"],
            "rationale": "An import does not prove runtime behavior.",
            "record_type": "interpretation",
        }
    ]
    report["triage"]["findings"] = report["findings"]
    report["triage"]["score_breakdown"] = [
        {
            "rule_id": "CAP-TEST",
            "weight": 10,
            "evidence_ids": ["ev_0123456789abcdef"],
        }
    ]
    report["ioc_analysis"]["iocs"] = [
        {"type": "url", "value": "https://example.org/check", "offset": 20}
    ]

    markdown = render_markdown_report(report)

    assert "fixture.exe" in markdown
    assert "Memory allocation API imported" in markdown
    assert "CAP-TEST" in markdown
    assert "ev_0123456789abcdef" in markdown
    assert "VirtualAlloc" in markdown
    assert "https://example.org/check" in markdown
    assert "No-match does not mean safe" in markdown


def test_markdown_handles_empty_findings_and_iocs():
    markdown = render_markdown_report(minimal_valid_report())

    assert "No rule-backed findings" in markdown
    assert "No candidate IOCs" in markdown
    assert "Warnings and limitations" in markdown


def test_markdown_renders_attack_candidates_with_traceability():
    report = minimal_valid_report()
    report["attack_candidates"] = [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "finding_ids": ["CAP-TEST"],
            "evidence_ids": ["ev_0123456789abcdef"],
            "rationale": "A test-only, explicitly rule-backed mapping.",
            "confidence": 0.7,
            "status": "candidate",
            "disclaimer": (
                "Candidate mapping only; static evidence does not confirm "
                "that the technique occurred."
            ),
        }
    ]

    markdown = render_markdown_report(report)

    assert "## MITRE ATT&CK candidate mappings" in markdown
    assert "T1059" in markdown
    assert "Command and Scripting Interpreter" in markdown
    assert "CAP-TEST" in markdown
    assert "ev_0123456789abcdef" in markdown
    assert "Candidate mapping only" in markdown


def test_attack_candidates_are_required_by_report_schema():
    report = minimal_valid_report()
    del report["attack_candidates"]

    with pytest.raises(ReportValidationError, match="attack_candidates"):
        validate_report(report, SCHEMA_PATH)


def test_json_and_markdown_preserve_the_same_finding_and_evidence_references():
    report = minimal_valid_report()
    finding_id = "CAP-CROSS-FORMAT"
    evidence_id = "ev_abcdef0123456789"

    report["evidence"] = [
        {
            "schema_version": "1.0.0",
            "id": evidence_id,
            "category": "string",
            "description": "Test evidence for cross-format consistency",
            "source": "string_analyzer",
            "value": "example marker",
            "location": None,
            "confidence": 0.8,
            "severity": "informational",
            "rationale": "Synthetic test evidence only.",
            "caveats": [],
            "record_type": "observation",
        }
    ]
    report["findings"] = [
        {
            "id": finding_id,
            "rule_version": "1.0.0",
            "title": "Cross-format test finding",
            "capability": "test_capability",
            "severity": "low",
            "weight": 5,
            "rule_ids": ["RULE-CROSS-FORMAT"],
            "evidence_ids": [evidence_id],
            "rationale": "Synthetic test finding only.",
            "record_type": "interpretation",
        }
    ]
    report["triage"]["findings"] = report["findings"]
    report["attack_candidates"] = [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "finding_ids": [finding_id],
            "evidence_ids": [evidence_id],
            "rationale": "Synthetic test mapping only.",
            "confidence": 0.25,
            "status": "candidate",
            "disclaimer": (
                "Candidate mapping only; static evidence does not confirm "
                "that the technique occurred."
            ),
        }
    ]

    json_output = render_json_report(report, SCHEMA_PATH)
    markdown_output = render_markdown_report(report)
    decoded_json = json.loads(json_output)

    assert decoded_json["findings"][0]["id"] == finding_id
    assert decoded_json["findings"][0]["evidence_ids"] == [evidence_id]
    assert decoded_json["attack_candidates"][0]["finding_ids"] == [finding_id]
    assert decoded_json["attack_candidates"][0]["evidence_ids"] == [evidence_id]

    for reference in (finding_id, evidence_id, "T1059.001"):
        assert reference in markdown_output
        assert reference in json_output

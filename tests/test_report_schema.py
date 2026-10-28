"""Validate emitted CLI reports against the versioned JSON Schema."""

import hashlib
import json
import struct
from pathlib import Path

import jsonschema
from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "evidence.schema.json"


def make_synthetic_pe(*, include_indicators: bool = True) -> bytes:
    """Build a minimal synthetic PE fixture; never execute it."""
    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        0,
        0x12345678,
        0,
        0,
        224,
        0x0102,
    )

    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x010B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x1000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)

    content = bytes(dos) + b"PE\0\0" + coff + bytes(optional)

    if include_indicators:
        content += (
            b"\0https://updates.example.org/check\0"
            + b"analyst@example.net\0"
        )

    return content


def test_schema_is_valid_and_accepts_generated_cli_report(tmp_path):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)

    sample = tmp_path / "schema-fixture.exe"
    content = make_synthetic_pe()
    sample.write_bytes(content)

    result = runner.invoke(app, ["analyze", str(sample)])
    assert result.exit_code == 0, result.output

    report = json.loads(result.output)
    jsonschema.validate(instance=report, schema=schema)

    assert report["file"]["sha256"] == hashlib.sha256(content).hexdigest()

    evidence_ids = {record["id"] for record in report["evidence"]}
    for finding in report["findings"]:
        assert finding["evidence_ids"]
        assert set(finding["evidence_ids"]) <= evidence_ids
        assert finding["rule_ids"]
        assert set(finding["rule_ids"]) <= set(report["triage"]["matched_rule_ids"])

    triage = report["triage"]
    assert triage["score"] <= triage["score_cap"]
    assert triage["score"] == min(triage["raw_score"], triage["score_cap"])


def test_valid_pe_with_no_matching_rules_is_unknown_not_safe(tmp_path):
    sample = tmp_path / "no-indicators.exe"
    sample.write_bytes(make_synthetic_pe(include_indicators=False))

    result = runner.invoke(app, ["analyze", str(sample)])
    assert result.exit_code == 0, result.output

    report = json.loads(result.output)
    jsonschema.validate(
        instance=report,
        schema=json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )

    assert report["triage"]["status"] == "no_rule_match"
    assert report["triage"]["severity"] == "unknown"
    assert report["findings"] == []
    assert any(
        "does not mean the file is safe" in warning.lower()
        for warning in report["triage"]["warnings"]
    )


def test_missing_input_is_rejected(tmp_path):
    missing = tmp_path / "does-not-exist.exe"
    result = runner.invoke(app, ["analyze", str(missing)])

    assert result.exit_code == 2
    assert "Input rejected" in result.output


def test_finding_schema_requires_interpretation_record_type():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    finding_schema = schema["$defs"]["finding"]

    assert "record_type" in finding_schema["required"]
    assert finding_schema["properties"]["record_type"]["const"] == "interpretation"

    minimal_finding = {
        "id": "CAP-TEST",
        "rule_version": "1.0.0",
        "title": "Test finding",
        "capability": "test",
        "severity": "low",
        "weight": 1,
        "rule_ids": ["CAP-TEST"],
        "evidence_ids": ["ev_0123456789abcdef"],
        "rationale": "Test rationale",
    }
    validator = jsonschema.Draft202012Validator(finding_schema)
    assert not validator.is_valid(minimal_finding)

    typed_finding = {**minimal_finding, "record_type": "interpretation"}
    assert validator.is_valid(typed_finding)

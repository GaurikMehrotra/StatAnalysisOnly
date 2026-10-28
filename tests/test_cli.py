import hashlib
import json
import struct

from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()


def make_minimal_pe():
    """Build a small synthetic PE32 header for tests; never executed."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
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

    return (
        bytes(dos)
        + b"PE\0\0"
        + coff
        + bytes(optional)
        + b"\0https://updates.example.org/check\0"
        + b"analyst@example.net\0"
        + b"192.0.2.10\0"
    )


def test_analyze_outputs_pe_metadata(tmp_path):
    sample = tmp_path / "fixture.exe"
    content = make_minimal_pe()
    sample.write_bytes(content)

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["attack_candidates"] == []
    assert report["tool"]["name"] == "malware-analysis-agent"
    assert isinstance(report["tool"]["version"], str)
    assert report["tool"]["version"]
    assert report["status"] == "static_analysis_completed"
    assert report["input"]["filename"] == "fixture.exe"
    assert report["input"]["size_bytes"] == len(content)
    assert report["input"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["pe_metadata"]["architecture"] == "x86"
    assert report["pe_metadata"]["entry_point"] == 0x1000
    assert report["section_analysis"]["section_count"] == 0
    assert report["section_analysis"]["sections"] == []

    imports = report["import_analysis"]
    assert imports["import_library_count"] == 0
    assert imports["imported_function_count"] == 0
    assert imports["imports"] == []
    assert imports["export_count"] == 0
    assert imports["exports"] == []
    assert isinstance(imports["warnings"], list)

    strings = report["string_analysis"]
    assert strings["string_count"] > 0
    assert any(
        item["value"] == "https://updates.example.org/check"
        for item in strings["strings"]
    )

    iocs = report["ioc_analysis"]
    assert iocs["ioc_count"] > 0
    assert any(
        item["type"] == "url" and item["value"] == "https://updates.example.org/check"
        for item in iocs["iocs"]
    )
    assert any(
        item["type"] == "domain" and item["value"] == "updates.example.org"
        for item in iocs["iocs"]
    )
    assert any(
        item["type"] == "email" and item["value"] == "analyst@example.net"
        for item in iocs["iocs"]
    )
    assert any(
        item["type"] == "ipv4" and item["value"] == "192.0.2.10"
        for item in iocs["iocs"]
    )
    assert iocs["truncated"] is False

    assert any(
        "Import names are static evidence" in warning for warning in report["warnings"]
    )
    assert any(
        "Extracted strings and IOCs are static indicators" in warning
        for warning in report["warnings"]
    )
    assert not any("not yet integrated" in warning for warning in report["warnings"])
    assert report["warnings"]


def test_analyze_rejects_missing_file(tmp_path):
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing.exe")])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_analyze_rejects_malformed_pe(tmp_path):
    sample = tmp_path / "malformed.exe"
    sample.write_bytes(b"ordinary text renamed to exe")

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 2
    assert "PE analysis rejected" in result.output


def test_analyze_rejects_existing_output_file(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    output = tmp_path / "report.json"
    output.write_text("preserve this content")

    result = runner.invoke(
        app,
        ["analyze", str(sample), "--output", str(output)],
    )

    assert result.exit_code == 2
    assert output.read_text() == "preserve this content"


def test_analyze_writes_json_report(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["analyze", str(sample), "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report["status"] == "static_analysis_completed"
    assert report["pe_metadata"]["architecture"] == "x86"
    assert "import_analysis" in report
    assert "string_analysis" in report
    assert "ioc_analysis" in report


def test_analyze_accepts_dll_and_sys_extensions(tmp_path):
    for extension in (".dll", ".sys"):
        sample = tmp_path / f"fixture{extension}"
        sample.write_bytes(make_minimal_pe())

        result = runner.invoke(app, ["analyze", str(sample)])

        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        assert report["status"] == "static_analysis_completed"
        assert report["input"]["filename"] == sample.name


def test_report_includes_versioned_evidence_and_unknown_triage(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)

    assert report["schema_version"] == "1.0.0"
    assert report["analysis_status"] == "completed"
    assert report["file"]["name"] == "fixture.exe"
    assert report["file"]["format"] == "PE"
    assert report["evidence"]
    assert all(item["schema_version"] == "1.0.0" for item in report["evidence"])
    assert all(item["record_type"] == "observation" for item in report["evidence"])

    evidence_ids = {item["id"] for item in report["evidence"]}
    for finding in report["findings"]:
        assert finding["rule_ids"]
        assert set(finding["evidence_ids"]) <= evidence_ids
        assert finding["rule_ids"][0] == finding["id"]

    triage = report["triage"]
    assert triage["score"] <= triage["score_cap"]
    assert triage["score"] == min(triage["raw_score"], triage["score_cap"])
    assert triage["findings"] == report["findings"]

    if triage["status"] == "no_rule_match":
        assert triage["severity"] == "unknown"
        assert any(
            "does not mean the file is safe" in warning
            for warning in triage["warnings"]
        )


def test_cli_report_evidence_ids_are_deterministic(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    first = runner.invoke(app, ["analyze", str(sample)])
    second = runner.invoke(app, ["analyze", str(sample)])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output

    first_report = json.loads(first.output)
    second_report = json.loads(second.output)

    assert [item["id"] for item in first_report["evidence"]] == [
        item["id"] for item in second_report["evidence"]
    ]
    assert (
        first_report["triage"]["score_breakdown"]
        == second_report["triage"]["score_breakdown"]
    )


def test_analyze_outputs_markdown_report(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    result = runner.invoke(app, ["analyze", str(sample), "--format", "markdown"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("# Malware Analysis Report")
    assert "fixture.exe" in result.output
    assert "Warnings and limitations" in result.output
    assert not result.output.lstrip().startswith("{")


def test_analyze_writes_markdown_report(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        ["analyze", str(sample), "--format", "markdown", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert "MARKDOWN report written to:" in result.output
    markdown = output.read_text(encoding="utf-8")
    assert markdown.startswith("# Malware Analysis Report")
    assert "fixture.exe" in markdown


def test_validate_report_accepts_cli_generated_json(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())
    output = tmp_path / "report.json"

    analyze_result = runner.invoke(
        app, ["analyze", str(sample), "--output", str(output)]
    )
    assert analyze_result.exit_code == 0, analyze_result.output

    result = runner.invoke(app, ["validate-report", str(output)])

    assert result.exit_code == 0, result.output
    assert "Report is valid:" in result.output


def test_validate_report_rejects_invalid_json(tmp_path):
    report_path = tmp_path / "invalid.json"
    report_path.write_text("{not valid JSON", encoding="utf-8")

    result = runner.invoke(app, ["validate-report", str(report_path)])

    assert result.exit_code == 2
    assert "Cannot read JSON report" in result.output


def test_validate_report_rejects_schema_invalid_json(tmp_path):
    report_path = tmp_path / "invalid.json"
    report_path.write_text('{"schema_version": "1.0.0"}', encoding="utf-8")

    result = runner.invoke(app, ["validate-report", str(report_path)])

    assert result.exit_code == 2
    assert "Report validation failed" in result.output


def test_validate_report_rejects_invalid_utf8(tmp_path):
    report_path = tmp_path / "invalid-encoding.json"
    report_path.write_bytes(b"\xff\xfe\xfa")

    result = runner.invoke(app, ["validate-report", str(report_path)])

    assert result.exit_code == 2
    assert "Cannot read JSON report" in result.output
    assert "Traceback" not in result.output


def test_validate_report_rejects_oversized_file(tmp_path, monkeypatch):
    import src.cli as cli_module

    monkeypatch.setattr(cli_module, "MAX_REPORT_SIZE_BYTES", 16)
    report_path = tmp_path / "oversized.json"
    report_path.write_bytes(b" " * 17)

    result = runner.invoke(app, ["validate-report", str(report_path)])

    assert result.exit_code == 2
    assert "exceeds the maximum size" in result.output


def test_analyze_rejects_unsupported_report_format(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    result = runner.invoke(app, ["analyze", str(sample), "--format", "xml"])

    assert result.exit_code == 2
    assert "Unsupported format" in result.output


def test_ai_explanation_is_disabled_by_default(tmp_path, monkeypatch):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    def unexpected(*args, **kwargs):
        raise AssertionError("AI must not run unless --explain is supplied.")

    monkeypatch.setattr("src.cli.explain_report", unexpected)
    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert "ai_explanation" not in report
    assert report["analysis_status"] == "completed"


def test_cli_accepts_valid_ai_explanation(tmp_path, monkeypatch):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    def fake_explanation(report, **kwargs):
        evidence_id = report["evidence"][0]["id"]
        return {
            "status": "available",
            "generated_by_ai": True,
            "model": "test-model",
            "summary": "A cautious explanation of static evidence.",
            "claims": [
                {
                    "text": "A static observation was recorded.",
                    "evidence_ids": [evidence_id],
                }
            ],
            "limitations": (
                "AI-generated explanation, not a verified detection. "
                "Evidence references establish traceability, not factual correctness."
            ),
        }

    monkeypatch.setattr("src.cli.explain_report", fake_explanation)
    result = runner.invoke(app, ["analyze", str(sample), "--explain"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    explanation = report["ai_explanation"]
    assert explanation["status"] == "available"
    assert explanation["generated_by_ai"] is True
    known_ids = {item["id"] for item in report["evidence"]}
    for claim in explanation["claims"]:
        assert set(claim["evidence_ids"]) <= known_ids


def test_cli_ai_fallback_does_not_fail_analysis(tmp_path, monkeypatch):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    monkeypatch.setattr(
        "src.cli.explain_report",
        lambda report, **kwargs: {
            "status": "unavailable",
            "reason": "Local model service is unavailable.",
        },
    )
    result = runner.invoke(app, ["analyze", str(sample), "--explain"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["analysis_status"] == "completed"
    assert report["ai_explanation"]["status"] == "unavailable"
    assert report["findings"] == report["triage"]["findings"]


def test_cli_ai_explanation_renders_in_markdown(tmp_path, monkeypatch):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    def fake_explanation(report, **kwargs):
        return {
            "status": "available",
            "generated_by_ai": True,
            "model": "test-model",
            "summary": "A cautious explanation.",
            "claims": [
                {
                    "text": "A static clue exists.",
                    "evidence_ids": [report["evidence"][0]["id"]],
                }
            ],
            "limitations": "Not a verified detection.",
        }

    monkeypatch.setattr("src.cli.explain_report", fake_explanation)
    result = runner.invoke(
        app,
        ["analyze", str(sample), "--explain", "--format", "markdown"],
    )

    assert result.exit_code == 0, result.output
    assert "## Optional AI explanation" in result.output
    assert "AI-generated content is not a verified detection" in result.output
    assert "A cautious explanation." in result.output
    assert "Evidence IDs:" in result.output

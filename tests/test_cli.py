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

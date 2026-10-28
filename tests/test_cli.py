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

    return bytes(dos) + b"PE\0\0" + coff + bytes(optional)


def test_analyze_outputs_pe_metadata(tmp_path):
    sample = tmp_path / "fixture.exe"
    content = make_minimal_pe()
    sample.write_bytes(content)

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["status"] == "static_analysis_completed"
    assert report["input"]["filename"] == "fixture.exe"
    assert report["input"]["size_bytes"] == len(content)
    assert report["input"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["pe_metadata"]["architecture"] == "x86"
    assert report["pe_metadata"]["entry_point"] == 0x1000
    assert report["section_analysis"]["section_count"] == 0
    assert report["section_analysis"]["sections"] == []
    assert report["warnings"]


def test_analyze_rejects_missing_file(tmp_path):
    result = runner.invoke(
        app, ["analyze", str(tmp_path / "missing.exe")]
    )

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

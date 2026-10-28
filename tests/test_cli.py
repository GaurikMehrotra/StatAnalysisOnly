import hashlib
import json

from typer.testing import CliRunner

from src.cli import app

runner = CliRunner()


def test_analyze_outputs_json_for_accepted_input(tmp_path):
    sample = tmp_path / "fixture.exe"
    content = b"benign synthetic test data"
    sample.write_bytes(content)

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 0, result.output

    report = json.loads(result.output)
    assert report["status"] == "input_gate_passed"
    assert report["input"]["filename"] == "fixture.exe"
    assert report["input"]["size_bytes"] == len(content)
    assert report["input"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report["warnings"]


def test_analyze_rejects_missing_file(tmp_path):
    sample = tmp_path / "missing.exe"

    result = runner.invoke(app, ["analyze", str(sample)])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_analyze_rejects_existing_output_file(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(b"synthetic data")

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
    sample.write_bytes(b"synthetic data")

    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["analyze", str(sample), "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report["input"]["filename"] == "fixture.exe"
    assert report["status"] == "input_gate_passed"

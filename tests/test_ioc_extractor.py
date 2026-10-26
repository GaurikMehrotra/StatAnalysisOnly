import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_report_schema_is_valid_json_schema():
    schema = json.loads(
        Path("schemas/evidence.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)


def test_report_schema_rejects_wrong_version():
    schema = json.loads(
        Path("schemas/evidence.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)

    report = {
        "schema_version": "0.0.0",
        "analysis_status": "rejected",
        "file": {
            "name": "sample.exe",
            "size_bytes": 0,
            "sha256": None,
            "format": "unknown",
        },
        "evidence": [],
        "findings": [],
        "warnings": [],
    }

    assert list(validator.iter_errors(report))

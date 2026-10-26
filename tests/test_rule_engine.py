import json
from pathlib import Path


def test_report_schema_is_versioned():
    schema = json.loads(
        Path("schemas/evidence.schema.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["schema_version"]["const"] == "1.0.0"


def test_report_schema_requires_core_sections():
    schema = json.loads(
        Path("schemas/evidence.schema.json").read_text(encoding="utf-8")
    )
    required = set(schema["required"])
    assert {
        "schema_version",
        "analysis_status",
        "file",
        "evidence",
        "findings",
        "warnings",
    } <= required

"""Canonical JSON report validation and rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "report.schema.json"
)


class ReportValidationError(ValueError):
    """Raised when a report fails schema validation."""


def validate_report(
    report: dict[str, Any],
    schema_path: Path | None = None,
) -> None:
    """Validate a report against the canonical JSON Schema."""
    path = schema_path or DEFAULT_SCHEMA_PATH

    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(
            validator.iter_errors(report),
            key=lambda error: list(map(str, error.absolute_path)),
        )
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise ReportValidationError(
            f"Cannot load or validate report schema at {path}: {exc}"
        ) from exc

    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        detail = f"{location}: {error.message}"
        if len(errors) > 1:
            detail += f" (and {len(errors) - 1} more validation error(s))"
        raise ReportValidationError(detail)


def render_json_report(
    report: dict[str, Any],
    schema_path: Path | None = None,
) -> str:
    """Return deterministic, schema-validated JSON."""
    validate_report(report, schema_path)
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)

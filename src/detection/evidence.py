"""Versioned, deterministic evidence records for static analysis."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

EVIDENCE_SCHEMA_VERSION = "1.0.0"

EVIDENCE_CATEGORIES = {
    "file_metadata",
    "pe_metadata",
    "import",
    "export",
    "section",
    "string",
    "entropy",
    "ioc",
    "parser_warning",
}

EVIDENCE_SEVERITIES = {
    "informational", "low", "medium", "high", "critical", "unknown"
}


class EvidenceRecord(BaseModel):
    """One traceable static-analysis observation or interpretation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0.0"] = EVIDENCE_SCHEMA_VERSION
    id: str = Field(pattern=r"^ev_[a-f0-9]{16}$")
    category: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=2000)
    source: str = Field(min_length=1, max_length=128)
    value: Any = None
    location: dict[str, Any] | None = None
    confidence: float | None = Field(
        default=None, ge=0.0, le=1.0, strict=True
    )
    severity: str = "unknown"
    rationale: str = Field(min_length=1, max_length=2000)
    caveats: list[str] = Field(default_factory=list, max_length=50)
    record_type: Literal["observation", "interpretation"] = "observation"

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        if value not in EVIDENCE_CATEGORIES:
            raise ValueError(f"Unsupported evidence category: {value}")
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in EVIDENCE_SEVERITIES:
            raise ValueError(f"Unsupported severity: {value}")
        return value

    @field_validator("description", "source", "rationale")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Field must not be blank")
        return value

    @field_validator("caveats")
    @classmethod
    def reject_blank_caveats(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("Caveats must not contain blank strings")
        return value


def _canonical_json(value: Any) -> str:
    """Serialize JSON-compatible values deterministically."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence values must be JSON-serializable") from exc


def normalize_observation(
    *,
    category: str,
    description: str,
    source: str,
    value: Any = None,
    location: dict[str, Any] | None = None,
    confidence: float | None = None,
    severity: str = "unknown",
    rationale: str | None = None,
    caveats: list[str] | None = None,
    record_type: Literal["observation", "interpretation"] = "observation",
) -> EvidenceRecord:
    """Validate an observation and assign a deterministic content-derived ID.

    The ID depends on category, description, source, value, location and type.
    Confidence and rationale do not change the identity of the observation.
    """
    identity = {
        "category": category,
        "description": description,
        "source": source,
        "value": value,
        "location": location,
        "record_type": record_type,
    }
    digest = hashlib.sha256(
        _canonical_json(identity).encode("utf-8")
    ).hexdigest()[:16]

    return EvidenceRecord(
        id=f"ev_{digest}",
        category=category,
        description=description,
        source=source,
        value=value,
        location=location,
        confidence=confidence,
        severity=severity,
        rationale=description if rationale is None else rationale,
        caveats=[] if caveats is None else caveats,
        record_type=record_type,
    )


def normalize_observations(
    observations: list[dict[str, Any]],
) -> list[EvidenceRecord]:
    """Normalize a list of observation dictionaries."""
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")

    records = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ValueError(
                f"Observation at index {index} must be an object"
            )
        try:
            records.append(normalize_observation(**observation))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid observation at index {index}: {exc}"
            ) from exc

    return records

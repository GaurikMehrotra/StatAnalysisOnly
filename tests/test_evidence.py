"""Tests for deterministic evidence normalization."""

import pytest
from pydantic import ValidationError

from src.detection.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceRecord,
    normalize_observation,
    normalize_observations,
)


def sample(**overrides):
    data = {
        "category": "import",
        "description": "PE import table contains VirtualAlloc",
        "source": "import_analyzer",
        "value": {"api": "VirtualAlloc"},
        "confidence": 0.95,
        "severity": "informational",
        "rationale": "The API name was observed in the import table.",
        "caveats": ["An import does not prove the API is called."],
    }
    data.update(overrides)
    return data


def test_normalizes_valid_observation():
    record = normalize_observation(**sample())
    assert isinstance(record, EvidenceRecord)
    assert record.schema_version == EVIDENCE_SCHEMA_VERSION
    assert record.id.startswith("ev_")
    assert record.record_type == "observation"


def test_ids_are_deterministic():
    assert normalize_observation(**sample()).id == (
        normalize_observation(**sample()).id
    )


def test_changed_value_changes_id():
    first = normalize_observation(**sample())
    second = normalize_observation(
        **sample(value={"api": "CreateFileW"})
    )
    assert first.id != second.id


def test_rationale_does_not_change_identity():
    first = normalize_observation(**sample())
    second = normalize_observation(
        **sample(rationale="Different explanation of the same observation.")
    )
    assert first.id == second.id


def test_record_serializes_to_json_compatible_data():
    result = normalize_observation(**sample()).model_dump(mode="json")
    assert result["schema_version"] == "1.0.0"
    assert result["value"] == {"api": "VirtualAlloc"}


@pytest.mark.parametrize("confidence", [-0.1, 1.1, True])
def test_rejects_invalid_confidence(confidence):
    with pytest.raises((ValidationError, TypeError, ValueError)):
        normalize_observation(**sample(confidence=confidence))


def test_rejects_unknown_category():
    with pytest.raises(ValidationError):
        normalize_observation(**sample(category="unknown_category"))


def test_rejects_blank_rationale():
    with pytest.raises(ValidationError):
        normalize_observation(**sample(rationale="   "))


def test_rejects_blank_caveat():
    with pytest.raises(ValidationError):
        normalize_observation(**sample(caveats=["   "]))


def test_normalizes_multiple_observations():
    records = normalize_observations(
        [sample(), sample(category="string")]
    )
    assert len(records) == 2
    assert records[0].category == "import"
    assert records[1].category == "string"


def test_rejects_non_object_observation():
    with pytest.raises(ValueError, match="index 0"):
        normalize_observations(["not an observation"])


def test_rejects_non_json_serializable_value():
    with pytest.raises(ValueError, match="JSON-serializable"):
        normalize_observation(**sample(value={"bad": object()}))

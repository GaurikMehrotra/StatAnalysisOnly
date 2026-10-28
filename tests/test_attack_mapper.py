"""Tests for conservative, evidence-backed ATT&CK candidate mapping."""

import copy

import pytest
import yaml

from src.detection.attack_mapper import (
    DISCLAIMER,
    AttackMappingError,
    load_attack_mappings,
    map_attack_candidates,
)


def finding(
    finding_id="CAP-TEST",
    evidence_ids=None,
):
    return {
        "id": finding_id,
        "evidence_ids": evidence_ids or ["ev_0123456789abcdef"],
    }


def evidence(evidence_id="ev_0123456789abcdef"):
    return {"id": evidence_id, "category": "import", "value": {"api": "TestApi"}}


def write_catalog(tmp_path, mappings):
    path = tmp_path / "attack_mappings.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0.0",
                "description": "Test-only catalog",
                "mappings": mappings,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def mapping(finding_id="CAP-TEST"):
    return {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "finding_id": finding_id,
        "rationale": "Test mapping rationale; this is not a behavior confirmation.",
        "confidence": 0.25,
    }


def test_default_catalog_is_versioned_and_has_no_unsupported_claims():
    catalog = load_attack_mappings()
    assert catalog["schema_version"] == "1.0.0"
    assert catalog["mappings"] == []


def test_empty_catalog_returns_no_candidates():
    assert map_attack_candidates([finding()], [evidence()]) == []


def test_catalog_mapping_retains_finding_and_evidence_traceability(tmp_path):
    path = write_catalog(tmp_path, [mapping()])

    result = map_attack_candidates(
        [finding()],
        [evidence()],
        catalog_path=path,
    )

    assert len(result) == 1
    candidate = result[0]
    assert candidate["technique_id"] == "T1059"
    assert candidate["finding_ids"] == ["CAP-TEST"]
    assert candidate["evidence_ids"] == ["ev_0123456789abcdef"]
    assert candidate["status"] == "candidate"
    assert candidate["disclaimer"] == DISCLAIMER


def test_mapping_without_matching_finding_is_ignored(tmp_path):
    path = write_catalog(tmp_path, [mapping("CAP-NOT-PRESENT")])

    assert map_attack_candidates([finding()], [evidence()], path) == []


def test_mapping_rejects_missing_evidence_links(tmp_path):
    path = write_catalog(tmp_path, [mapping()])

    with pytest.raises(AttackMappingError, match="evidence links"):
        map_attack_candidates(
            [finding(evidence_ids=["ev_aaaaaaaaaaaaaaaa"])],
            [evidence()],
            path,
        )


def test_mapping_rejects_duplicate_technique_ids(tmp_path):
    duplicate = copy.deepcopy(mapping())
    path = write_catalog(tmp_path, [mapping(), duplicate])

    with pytest.raises(AttackMappingError, match="Duplicate technique ID"):
        load_attack_mappings(path)


def test_mapping_rejects_invalid_confidence(tmp_path):
    item = mapping()
    item["confidence"] = 1.5
    path = write_catalog(tmp_path, [item])

    with pytest.raises(AttackMappingError, match="Confidence"):
        load_attack_mappings(path)

@pytest.mark.parametrize(
    "technique_id",
    [
        "T",
        "T123",
        "T12345",
        "X1059",
        "T1059.1",
        "T1059.0000",
        "T１０５９",
    ],
)
def test_mapping_rejects_malformed_technique_ids(tmp_path, technique_id):
    item = mapping()
    item["technique_id"] = technique_id
    path = write_catalog(tmp_path, [item])

    with pytest.raises(AttackMappingError, match="T####"):
        load_attack_mappings(path)


@pytest.mark.parametrize("technique_id", ["T1059", "T1059.001"])
def test_mapping_accepts_standard_technique_ids(tmp_path, technique_id):
    item = mapping()
    item["technique_id"] = technique_id
    path = write_catalog(tmp_path, [item])

    catalog = load_attack_mappings(path)

    assert catalog["mappings"][0]["technique_id"] == technique_id


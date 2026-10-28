"""Tests for versioned rules, traceable findings, and deterministic scoring."""

import copy

import pytest
import yaml

from src.detection.evidence import normalize_observation
from src.detection.rule_engine import (
    RuleEngineError,
    evaluate_rules,
    load_rules,
)


def evidence(category, description, value, source="test"):
    return normalize_observation(
        category=category,
        description=description,
        source=source,
        value=value,
        rationale=description,
    )


def test_ruleset_loads_and_is_versioned():
    ruleset = load_rules()
    assert ruleset["ruleset_version"] == "1.0.0"
    assert ruleset["rules"]


def test_import_rule_produces_traceable_finding():
    item = evidence(
        "import",
        "VirtualAlloc imported",
        {"api": "VirtualAlloc"},
        "import_analyzer",
    )
    result = evaluate_rules([item])

    finding = next(
        item for item in result["findings"]
        if item["id"] == "CAP-IMPORT-MEMORY-ALLOCATION"
    )
    assert item.id in finding["evidence_ids"]
    assert finding["rule_ids"] == ["CAP-IMPORT-MEMORY-ALLOCATION"]
    assert result["status"] == "rules_matched"


def test_nonmatching_import_does_not_trigger_virtualalloc_rule():
    item = evidence("import", "ReadFile imported", {"api": "ReadFile"})
    result = evaluate_rules([item])

    assert "CAP-IMPORT-MEMORY-ALLOCATION" not in result["matched_rule_ids"]


def test_ioc_rule_matches_url_candidate():
    item = evidence("ioc", "URL candidate recovered", {"type": "url", "value": "https://example.org"})
    result = evaluate_rules([item])

    finding = next(
        item for item in result["findings"] if item["id"] == "CAP-IOC-URL"
    )
    assert item.id in finding["evidence_ids"]


def test_empty_evidence_is_insufficient_not_benign():
    result = evaluate_rules([])
    assert result["status"] == "insufficient_evidence"
    assert result["severity"] == "unknown"
    assert result["findings"] == []


def test_no_matching_rules_does_not_mean_safe():
    item = evidence("string", "Ordinary string", {"text": "hello"})
    result = evaluate_rules([item])

    assert result["status"] == "no_rule_match"
    assert result["severity"] == "unknown"
    assert any("does not mean" in warning for warning in result["warnings"])


def test_scoring_is_reproducible():
    records = [
        evidence("import", "VirtualAlloc imported", {"api": "VirtualAlloc"}),
        evidence("ioc", "URL candidate", {"type": "url", "value": "https://example.org"}),
    ]
    first = evaluate_rules(records)
    second = evaluate_rules(records)

    assert first == second
    assert first["score"] == 15
    assert first["score_breakdown"] == second["score_breakdown"]


def test_score_is_capped():
    records = [
        evidence("import", "VirtualAlloc", {"api": "VirtualAlloc"}),
        evidence("import", "VirtualProtect", {"api": "VirtualProtect"}),
        evidence("ioc", "URL", {"type": "url"}),
        evidence("section", "WX section", {"writable_executable": True}),
    ]
    result = evaluate_rules(records)

    assert result["score"] <= result["score_cap"]
    assert result["score"] == min(result["raw_score"], result["score_cap"])


def test_findings_reference_existing_evidence_only():
    records = [
        evidence("import", "VirtualAlloc", {"api": "VirtualAlloc"}),
        evidence("ioc", "URL", {"type": "url"}),
    ]
    ids = {item.id for item in records}
    result = evaluate_rules(records)

    for finding in result["findings"]:
        assert finding["evidence_ids"]
        assert set(finding["evidence_ids"]) <= ids


def test_duplicate_evidence_ids_are_rejected():
    item = evidence("import", "VirtualAlloc", {"api": "VirtualAlloc"})
    with pytest.raises(RuleEngineError, match="Duplicate evidence ID"):
        evaluate_rules([item, item])


def test_rejects_malformed_ruleset(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("not: [valid", encoding="utf-8")

    with pytest.raises(RuleEngineError):
        load_rules(path)


def test_rejects_duplicate_rule_ids(tmp_path):
    ruleset = load_rules()
    ruleset["rules"].append(copy.deepcopy(ruleset["rules"][0]))
    path = tmp_path / "duplicate.yaml"
    path.write_text(yaml.safe_dump(ruleset), encoding="utf-8")

    with pytest.raises(RuleEngineError, match="Duplicate rule ID"):
        load_rules(path)


def test_rejects_unknown_rule_fields(tmp_path):
    ruleset = load_rules()
    ruleset["rules"][0]["shell_command"] = "unsafe"
    path = tmp_path / "unknown.yaml"
    path.write_text(yaml.safe_dump(ruleset), encoding="utf-8")

    with pytest.raises(RuleEngineError, match="unsupported fields"):
        load_rules(path)


def test_rule_engine_accepts_evidence_dictionaries():
    item = evidence("import", "VirtualAlloc", {"api": "VirtualAlloc"})
    result = evaluate_rules([item.model_dump(mode="json")])

    assert "CAP-IMPORT-MEMORY-ALLOCATION" in result["matched_rule_ids"]


RULE_CASES = [
    (
        "CAP-IMPORT-MEMORY-ALLOCATION",
        "import",
        {"api": "VirtualAlloc"},
        {"api": "ReadFile"},
        {},
    ),
    (
        "CAP-IMPORT-MEMORY-PROTECTION",
        "import",
        {"api": "VirtualProtect"},
        {"api": "ReadFile"},
        {},
    ),
    (
        "CAP-IOC-URL",
        "ioc",
        {"type": "url", "value": "https://example.org"},
        {"type": "domain", "value": "example.org"},
        {"value": "https://example.org"},
    ),
    (
        "CAP-SECTION-WRITABLE-EXECUTABLE",
        "section",
        {"writable_executable": True},
        {"writable_executable": False},
        {"writable_executable": "true"},
    ),
]


@pytest.mark.parametrize(
    ("rule_id", "category", "positive_value", "negative_value", "ambiguous_value"),
    RULE_CASES,
)
def test_each_rule_matches_its_positive_case(
    rule_id, category, positive_value, negative_value, ambiguous_value
):
    item = evidence(category, f"Positive case for {rule_id}", positive_value)
    result = evaluate_rules([item])

    assert rule_id in result["matched_rule_ids"]
    finding = next(f for f in result["findings"] if f["id"] == rule_id)
    assert item.id in finding["evidence_ids"]
    assert rule_id in finding["rule_ids"]


@pytest.mark.parametrize(
    ("rule_id", "category", "positive_value", "negative_value", "ambiguous_value"),
    RULE_CASES,
)
def test_each_rule_rejects_its_negative_case(
    rule_id, category, positive_value, negative_value, ambiguous_value
):
    item = evidence(category, f"Negative case for {rule_id}", negative_value)
    result = evaluate_rules([item])

    assert rule_id not in result["matched_rule_ids"]


@pytest.mark.parametrize(
    ("rule_id", "category", "positive_value", "negative_value", "ambiguous_value"),
    RULE_CASES,
)
def test_each_rule_rejects_its_ambiguous_case(
    rule_id, category, positive_value, negative_value, ambiguous_value
):
    item = evidence(category, f"Ambiguous case for {rule_id}", ambiguous_value)
    result = evaluate_rules([item])

    assert rule_id not in result["matched_rule_ids"]

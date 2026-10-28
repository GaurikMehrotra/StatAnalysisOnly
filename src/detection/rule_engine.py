"""Validated YAML rules and explainable deterministic triage scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "capabilities.yaml"

ALLOWED_CATEGORIES = {
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
ALLOWED_SEVERITIES = {
    "informational", "low", "medium", "high", "critical", "unknown"
}
ALLOWED_OPERATORS = {"equals", "contains", "exists"}


class RuleEngineError(ValueError):
    """Raised when a ruleset or evidence input is invalid."""


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleEngineError(f"{label} must be a non-empty string")
    return value


def _get_field(evidence: dict[str, Any], path: str) -> Any:
    """Read a dot-separated field from evidence without evaluating code."""
    def descend(root: Any) -> tuple[bool, Any]:
        current = root
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return False, None
            current = current[part]
        return True, current

    found, result = descend(evidence)
    if found:
        return result

    # Analyzer-specific fields are stored inside EvidenceRecord.value.
    found, result = descend(evidence.get("value"))
    return result if found else None


def _validate_condition(condition: Any, rule_id: str) -> None:
    if not isinstance(condition, dict):
        raise RuleEngineError(f"{rule_id}: each condition must be a mapping")

    if set(condition) - {"category", "field", "equals", "contains", "exists"}:
        raise RuleEngineError(f"{rule_id}: condition has unsupported fields")

    category = condition.get("category")
    if category not in ALLOWED_CATEGORIES:
        raise RuleEngineError(f"{rule_id}: unsupported condition category")

    _require_text(condition.get("field"), f"{rule_id} condition field")

    operators = set(condition) & ALLOWED_OPERATORS
    if len(operators) != 1:
        raise RuleEngineError(
            f"{rule_id}: condition must define exactly one operator"
        )

    operator = next(iter(operators))
    if operator == "contains" and not isinstance(condition["contains"], str):
        raise RuleEngineError(f"{rule_id}: contains must be a string")
    if operator == "exists" and not isinstance(condition["exists"], bool):
        raise RuleEngineError(f"{rule_id}: exists must be boolean")


def load_rules(path: str | Path = DEFAULT_RULES_PATH) -> dict[str, Any]:
    """Load and validate a versioned YAML ruleset."""
    rules_path = Path(path)
    try:
        with rules_path.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except OSError as exc:
        raise RuleEngineError(f"Cannot read ruleset: {rules_path}") from exc
    except yaml.YAMLError as exc:
        raise RuleEngineError("Ruleset is not valid YAML") from exc

    if not isinstance(document, dict):
        raise RuleEngineError("Ruleset root must be a mapping")
    if set(document) != {"ruleset_version", "scoring", "rules"}:
        raise RuleEngineError("Ruleset must contain version, scoring, and rules")

    _require_text(document["ruleset_version"], "ruleset_version")

    scoring = document["scoring"]
    if not isinstance(scoring, dict) or set(scoring) != {
        "maximum_score", "thresholds"
    }:
        raise RuleEngineError("Invalid scoring configuration")

    maximum = scoring["maximum_score"]
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        raise RuleEngineError("maximum_score must be a positive integer")

    thresholds = scoring["thresholds"]
    if not isinstance(thresholds, dict) or set(thresholds) != {
        "informational", "low", "medium", "high", "critical"
    }:
        raise RuleEngineError("Invalid severity thresholds")

    severity_order = ("informational", "low", "medium", "high", "critical")
    threshold_values = [thresholds[level] for level in severity_order]
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
        for value in threshold_values
    ):
        raise RuleEngineError("Thresholds must be integers within the score cap")
    if threshold_values != sorted(threshold_values):
        raise RuleEngineError("Thresholds must be in ascending severity order")

    rules = document["rules"]
    if not isinstance(rules, list):
        raise RuleEngineError("rules must be a list")

    seen_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise RuleEngineError("Each rule must be a mapping")
        required = {
            "id", "version", "title", "description", "capability",
            "severity", "weight", "rationale", "conditions",
        }
        if set(rule) != required:
            raise RuleEngineError("Rule has missing or unsupported fields")

        rule_id = _require_text(rule["id"], "rule id")
        if rule_id in seen_ids:
            raise RuleEngineError(f"Duplicate rule ID: {rule_id}")
        seen_ids.add(rule_id)

        for field in ("version", "title", "description", "capability", "rationale"):
            _require_text(rule[field], f"{rule_id} {field}")

        if rule["severity"] not in ALLOWED_SEVERITIES:
            raise RuleEngineError(f"{rule_id}: unsupported severity")

        weight = rule["weight"]
        if (
            isinstance(weight, bool)
            or not isinstance(weight, int)
            or not 0 <= weight <= maximum
        ):
            raise RuleEngineError(f"{rule_id}: invalid weight")

        conditions = rule["conditions"]
        if (
            not isinstance(conditions, dict)
            or set(conditions) != {"all"}
            or not isinstance(conditions["all"], list)
            or not conditions["all"]
        ):
            raise RuleEngineError(f"{rule_id}: conditions.all must be non-empty")

        for condition in conditions["all"]:
            _validate_condition(condition, rule_id)

    return document


def _condition_matches(
    condition: dict[str, Any], evidence: dict[str, Any]
) -> bool:
    if evidence.get("category") != condition["category"]:
        return False

    actual = _get_field(evidence, condition["field"])

    if "equals" in condition:
        # Avoid Python's True == 1 equivalence for rule matching.
        expected = condition["equals"]
        return type(actual) is type(expected) and actual == expected
    if "contains" in condition:
        return (
            isinstance(actual, str)
            and condition["contains"].casefold() in actual.casefold()
        )
    return actual is not None if condition["exists"] else actual is None


def evaluate_rules(
    evidence_records: list[Any],
    rules_path: str | Path = DEFAULT_RULES_PATH,
) -> dict[str, Any]:
    """Evaluate rules and return evidence-linked findings and a capped score.

    No match means only that no configured rule matched; it never means safe.
    """
    if not isinstance(evidence_records, list):
        raise RuleEngineError("evidence_records must be a list")

    evidence: list[dict[str, Any]] = []
    seen_evidence_ids: set[str] = set()

    for record in evidence_records:
        if hasattr(record, "model_dump"):
            item = record.model_dump(mode="json")
        elif isinstance(record, dict):
            item = record
        else:
            raise RuleEngineError("Each evidence record must be a mapping or model")

        evidence_id = item.get("id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise RuleEngineError("Each evidence record must have a non-empty id")
        if evidence_id in seen_evidence_ids:
            raise RuleEngineError(f"Duplicate evidence ID: {evidence_id}")
        seen_evidence_ids.add(evidence_id)
        evidence.append(item)

    ruleset = load_rules(rules_path)
    findings: list[dict[str, Any]] = []

    for rule in ruleset["rules"]:
        matched_ids: set[str] = set()
        all_conditions_met = True

        for condition in rule["conditions"]["all"]:
            supporting = [
                item["id"]
                for item in evidence
                if _condition_matches(condition, item)
            ]
            if not supporting:
                all_conditions_met = False
                break
            matched_ids.update(supporting)

        if all_conditions_met:
            findings.append({
                "id": rule["id"],
                "record_type": "interpretation",
                "rule_version": rule["version"],
                "title": rule["title"],
                "capability": rule["capability"],
                "severity": rule["severity"],
                "weight": rule["weight"],
                "rule_ids": [rule["id"]],
                "evidence_ids": sorted(matched_ids),
                "rationale": rule["rationale"].strip(),
            })

    findings.sort(key=lambda item: item["id"])
    scoring = ruleset["scoring"]
    raw_score = sum(item["weight"] for item in findings)
    score = min(raw_score, scoring["maximum_score"])

    if not evidence:
        status = "insufficient_evidence"
        severity = "unknown"
    elif not findings:
        status = "no_rule_match"
        severity = "unknown"
    else:
        status = "rules_matched"
        severity = "informational"
        for level in ("low", "medium", "high", "critical"):
            if score >= scoring["thresholds"][level]:
                severity = level

    return {
        "ruleset_version": ruleset["ruleset_version"],
        "status": status,
        "score": score,
        "raw_score": raw_score,
        "score_cap": scoring["maximum_score"],
        "severity": severity,
        "matched_rule_ids": [item["id"] for item in findings],
        "findings": findings,
        "score_breakdown": [
            {
                "rule_id": item["id"],
                "weight": item["weight"],
                "evidence_ids": item["evidence_ids"],
            }
            for item in findings
        ],
        "warnings": [
            "Heuristic score is a triage aid, not proof of maliciousness.",
            "No matching rule does not mean the file is safe.",
        ],
    }

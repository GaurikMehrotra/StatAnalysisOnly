"""Conservative, evidence-backed MITRE ATT&CK candidate mapping."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

DEFAULT_ATTACK_MAPPINGS_PATH = (
    Path(__file__).resolve().parents[2] / "rules" / "attack_mappings.yaml"
)

DISCLAIMER = (
    "Candidate mapping only; static evidence does not confirm that "
    "the technique occurred."
)


class AttackMappingError(ValueError):
    """Raised when ATT&CK mapping input or catalog is invalid."""


def load_attack_mappings(
    path: str | Path = DEFAULT_ATTACK_MAPPINGS_PATH,
) -> dict[str, Any]:
    """Load a versioned mapping catalog without performing network lookups."""
    mapping_path = Path(path)

    try:
        document = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AttackMappingError(
            f"Cannot read ATT&CK mapping catalog: {mapping_path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise AttackMappingError("ATT&CK mapping catalog is invalid YAML") from exc

    if not isinstance(document, dict):
        raise AttackMappingError("ATT&CK mapping catalog must be a mapping")

    if set(document) != {"schema_version", "description", "mappings"}:
        raise AttackMappingError("ATT&CK catalog has missing or unsupported fields")

    if document["schema_version"] != "1.0.0":
        raise AttackMappingError("Unsupported ATT&CK mapping catalog version")

    if (
        not isinstance(document["description"], str)
        or not document["description"].strip()
    ):
        raise AttackMappingError("ATT&CK catalog description must be non-empty")

    mappings = document["mappings"]
    if not isinstance(mappings, list):
        raise AttackMappingError("ATT&CK mappings must be a list")

    seen_ids: set[str] = set()

    for item in mappings:
        if not isinstance(item, dict):
            raise AttackMappingError("Each ATT&CK mapping must be a mapping")

        required = {
            "technique_id",
            "technique_name",
            "finding_id",
            "rationale",
            "confidence",
        }
        if set(item) != required:
            raise AttackMappingError("ATT&CK mapping has missing or unsupported fields")

        technique_id = item["technique_id"]
        technique_name = item["technique_name"]
        finding_id = item["finding_id"]
        rationale = item["rationale"]
        confidence = item["confidence"]

        if not isinstance(technique_id, str) or not re.fullmatch(
            r"T[0-9]{4}(?:\.[0-9]{3})?",
            technique_id,
        ):
            raise AttackMappingError(
                "Technique ID must match T#### or T####.### format"
            )
        if technique_id in seen_ids:
            raise AttackMappingError(f"Duplicate technique ID: {technique_id}")
        seen_ids.add(technique_id)

        for field_name, value in (
            ("technique_name", technique_name),
            ("finding_id", finding_id),
            ("rationale", rationale),
        ):
            if not isinstance(value, str) or not value.strip():
                raise AttackMappingError(f"{field_name} must be non-empty")

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 < confidence <= 1
        ):
            raise AttackMappingError("Confidence must be greater than 0 and at most 1")

    return document


def map_attack_candidates(
    findings: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    catalog_path: str | Path = DEFAULT_ATTACK_MAPPINGS_PATH,
) -> list[dict[str, Any]]:
    """Map explicitly catalogued findings to traceable ATT&CK candidates.

    No generic import, IOC, or section evidence can create a candidate on
    its own. A catalog entry must reference an existing finding, and the
    finding must reference existing evidence.
    """
    if not isinstance(findings, list) or not isinstance(evidence, list):
        raise AttackMappingError("Findings and evidence must be lists")

    catalog = load_attack_mappings(catalog_path)

    findings_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise AttackMappingError("Each finding must be a mapping")
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            raise AttackMappingError("Each finding must have a non-empty ID")
        if finding_id in findings_by_id:
            raise AttackMappingError(f"Duplicate finding ID: {finding_id}")
        findings_by_id[finding_id] = finding

    evidence_by_id: dict[str, dict[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, dict):
            raise AttackMappingError("Each evidence record must be a mapping")
        evidence_id = item.get("id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise AttackMappingError("Each evidence record must have a non-empty ID")
        if evidence_id in evidence_by_id:
            raise AttackMappingError(f"Duplicate evidence ID: {evidence_id}")
        evidence_by_id[evidence_id] = item

    candidates: list[dict[str, Any]] = []

    for mapping in catalog["mappings"]:
        finding = findings_by_id.get(mapping["finding_id"])
        if finding is None:
            continue

        evidence_ids = finding.get("evidence_ids")
        if (
            not isinstance(evidence_ids, list)
            or not evidence_ids
            or any(
                not isinstance(item, str) or item not in evidence_by_id
                for item in evidence_ids
            )
        ):
            raise AttackMappingError(
                f"Finding {mapping['finding_id']} has missing or invalid evidence links"
            )

        candidates.append(
            {
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
                "finding_ids": [mapping["finding_id"]],
                "evidence_ids": sorted(set(evidence_ids)),
                "rationale": mapping["rationale"],
                "confidence": mapping["confidence"],
                "status": "candidate",
                "disclaimer": DISCLAIMER,
            }
        )

    candidates.sort(key=lambda item: (item["technique_id"], item["finding_ids"]))
    return candidates

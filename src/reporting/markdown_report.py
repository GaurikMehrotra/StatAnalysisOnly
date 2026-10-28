"""Human-readable Markdown reports rendered from canonical report objects."""

from __future__ import annotations

import json
from typing import Any


def _text(value: Any) -> str:
    """Format untrusted values as single-line Markdown text."""
    if value is None:
        return "N/A"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render the report without rerunning analysis or changing its findings."""
    file_info = report.get("file", {})
    tool = report.get("tool", {})
    triage = report.get("triage", {})
    findings = report.get("findings", [])
    attack_candidates = report.get("attack_candidates", [])
    evidence = report.get("evidence", [])
    ioc_analysis = report.get("ioc_analysis", {})
    iocs = ioc_analysis.get("iocs", [])
    warnings = list(report.get("warnings", []))
    warnings.extend(triage.get("warnings", []))

    lines = [
        "# Malware Analysis Report",
        "",
        "> Static analysis only. A heuristic score is a triage aid, not proof",
        "> of maliciousness. No-match does not mean safe.",
        "",
        "## File summary",
        "",
        f"- **Filename:** {_text(file_info.get('name'))}",
        f"- **Format:** {_text(file_info.get('format'))}",
        f"- **Size:** {_text(file_info.get('size_bytes'))} bytes",
        f"- **SHA-256:** `{_text(file_info.get('sha256'))}`",
        f"- **Analysis status:** {_text(report.get('analysis_status'))}",
        f"- **Tool version:** {_text(tool.get('version'))}",
        f"- **Report schema version:** {_text(report.get('schema_version'))}",
        f"- **Ruleset version:** {_text(triage.get('ruleset_version'))}",
        "",
        "## Triage",
        "",
        f"- **Status:** {_text(triage.get('status'))}",
        f"- **Score:** {_text(triage.get('score'))} / {_text(triage.get('score_cap'))}",
        f"- **Raw score:** {_text(triage.get('raw_score'))}",
        f"- **Severity:** {_text(triage.get('severity'))}",
        "",
        "### Score breakdown",
        "",
        "| Rule ID | Weight | Supporting evidence IDs |",
        "|---|---:|---|",
    ]

    for item in triage.get("score_breakdown", []):
        evidence_ids = ", ".join(item.get("evidence_ids", []))
        lines.append(
            f"| {_text(item.get('rule_id'))} | "
            f"{_text(item.get('weight'))} | {_text(evidence_ids)} |"
        )

    if not triage.get("score_breakdown"):
        lines.append("| None | 0 | None |")

    lines.extend(["", "## Findings", ""])

    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {_text(finding.get('title', finding.get('id')))}",
                    "",
                    f"- **Finding ID:** {_text(finding.get('id'))}",
                    f"- **Capability:** {_text(finding.get('capability'))}",
                    f"- **Severity:** {_text(finding.get('severity'))}",
                    f"- **Weight:** {_text(finding.get('weight'))}",
                    f"- **Rule IDs:** {_text(finding.get('rule_ids', []))}",
                    f"- **Evidence IDs:** {_text(finding.get('evidence_ids', []))}",
                    f"- **Rationale:** {_text(finding.get('rationale'))}",
                    "",
                ]
            )
    else:
        lines.extend(["No rule-backed findings were produced.", ""])

    lines.extend(["## MITRE ATT&CK candidate mappings", ""])

    if attack_candidates:
        for candidate in attack_candidates:
            lines.extend(
                [
                    f"### {_text(candidate.get('technique_id'))}: "
                    f"{_text(candidate.get('technique_name'))}",
                    "",
                    f"- **Status:** {_text(candidate.get('status'))}",
                    f"- **Confidence:** {_text(candidate.get('confidence'))}",
                    f"- **Finding IDs:** {_text(candidate.get('finding_ids', []))}",
                    f"- **Evidence IDs:** {_text(candidate.get('evidence_ids', []))}",
                    f"- **Rationale:** {_text(candidate.get('rationale'))}",
                    f"- **Caveat:** {_text(candidate.get('disclaimer'))}",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "No ATT&CK candidate mappings are supported by the current "
                "mapping catalog and findings.",
                "",
            ]
        )

    lines.extend(["## Evidence", ""])

    if evidence:
        lines.extend(
            [
                "| Evidence ID | Category | Source | Observation |",
                "|---|---|---|---|",
            ]
        )
        for item in evidence:
            observation = item.get("description", "")
            value = item.get("value")
            if value is not None:
                observation = f"{observation}: {_text(value)}"
            lines.append(
                f"| `{_text(item.get('id'))}` | "
                f"{_text(item.get('category'))} | "
                f"{_text(item.get('source'))} | {_text(observation)} |"
            )
    else:
        lines.append("No evidence records were produced.")

    lines.extend(["", "## Candidate indicators of compromise", ""])

    if iocs:
        lines.extend(
            [
                "| Type | Value | Source offset |",
                "|---|---|---:|",
            ]
        )
        for ioc in iocs:
            lines.append(
                f"| {_text(ioc.get('type'))} | "
                f"`{_text(ioc.get('value'))}` | "
                f"{_text(ioc.get('offset'))} |"
            )
    else:
        lines.append("No candidate IOCs were extracted.")

    lines.extend(["", "## Warnings and limitations", ""])

    if warnings:
        for warning in dict.fromkeys(warnings):
            lines.append(f"- {_text(warning)}")
    else:
        lines.append("- No warnings were recorded.")

    lines.extend(
        [
            "",
            "This report records static observations and rule-backed hypotheses.",
            "It does not establish maliciousness, attribution, or runtime behavior.",
            "",
        ]
    )

    return "\n".join(lines)

"""Convert static analyzer outputs into normalized, traceable evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.detection.evidence import EvidenceRecord, normalize_observation


def _record(
    *,
    category: str,
    description: str,
    source: str,
    value: Any,
    location: dict[str, Any] | None = None,
    rationale: str | None = None,
    caveats: list[str] | None = None,
) -> EvidenceRecord:
    """Create a validated observation with a deterministic evidence ID."""
    return normalize_observation(
        category=category,
        description=description,
        source=source,
        value=value,
        location=location,
        confidence=1.0,
        rationale=rationale or description,
        caveats=caveats or [],
        record_type="observation",
    )


def collect_evidence(
    *,
    file_identity: Mapping[str, Any],
    pe_metadata: Mapping[str, Any],
    section_analysis: Mapping[str, Any],
    import_analysis: Mapping[str, Any],
    string_analysis: Mapping[str, Any],
    ioc_analysis: Mapping[str, Any],
) -> list[EvidenceRecord]:
    """Normalize analyzer results into observations for the rule engine.

    Source analyzer outputs are not modified. Location fields distinguish
    repeated imports, exports, sections, strings, and IOC occurrences.
    """
    records: list[EvidenceRecord] = []

    records.append(
        _record(
            category="file_metadata",
            description="Input file identity recorded by the validator",
            source="input_validator",
            value=dict(file_identity),
            rationale=(
                "File identity is supplied by input validation; it does not "
                "establish whether the file is benign or malicious."
            ),
        )
    )

    records.append(
        _record(
            category="pe_metadata",
            description="Portable Executable header metadata extracted",
            source="pe_analyzer",
            value=dict(pe_metadata),
            rationale=(
                "These fields were parsed from the PE headers. Header values "
                "can be malformed or deliberately forged."
            ),
            caveats=["Static header metadata is not proof of runtime behavior."],
        )
    )

    sections = section_analysis.get("sections", [])
    if not isinstance(sections, list):
        raise ValueError("section_analysis.sections must be a list")

    for index, section in enumerate(sections):
        if not isinstance(section, Mapping):
            raise ValueError(f"Section at index {index} must be an object")

        section_value = dict(section)
        writable = section.get("writable")
        executable = section.get("executable")
        section_value["writable_executable"] = (
            writable is True and executable is True
        )

        section_name = str(section.get("name", f"section_{index}"))
        location = {
            "section_index": index,
            "section_name": section_name,
            "raw_offset": section.get("raw_offset"),
            "virtual_address": section.get("virtual_address"),
        }

        records.append(
            _record(
                category="section",
                description=f"PE section metadata observed: {section_name}",
                source="section_analyzer",
                value=section_value,
                location=location,
                rationale=(
                    "Section attributes are static PE metadata. Writable and "
                    "executable permissions can be legitimate and are not "
                    "by themselves proof of maliciousness."
                ),
            )
        )

        if isinstance(section.get("entropy"), (int, float)):
            records.append(
                _record(
                    category="entropy",
                    description=f"Raw section entropy measured: {section_name}",
                    source="section_analyzer",
                    value={
                        "entropy": section["entropy"],
                        "section_name": section_name,
                    },
                    location=location,
                    rationale=(
                        "Entropy describes byte distribution; high entropy "
                        "may have several causes and is not proof of packing "
                        "or maliciousness."
                    ),
                )
            )

    imports = import_analysis.get("imports", [])
    if not isinstance(imports, list):
        raise ValueError("import_analysis.imports must be a list")

    for library_index, library in enumerate(imports):
        if not isinstance(library, Mapping):
            raise ValueError(
                f"Import library at index {library_index} must be an object"
            )

        dll = library.get("dll")
        functions = library.get("functions", [])
        if not isinstance(functions, list):
            raise ValueError(
                f"Import functions at library index {library_index} must be a list"
            )

        for function_index, function in enumerate(functions):
            if not isinstance(function, Mapping):
                raise ValueError(
                    "Import function at "
                    f"{library_index}:{function_index} must be an object"
                )

            api_name = function.get("name")
            value = {
                "dll": dll,
                "api": api_name,
                "name": api_name,
                "ordinal": function.get("ordinal"),
            }
            records.append(
                _record(
                    category="import",
                    description=(
                        f"Imported API observed: {api_name}"
                        if api_name
                        else f"Ordinal import observed: {function.get('ordinal')}"
                    ),
                    source="import_analyzer",
                    value=value,
                    location={
                        "library_index": library_index,
                        "dll": dll,
                        "function_index": function_index,
                    },
                    rationale=(
                        "An import indicates a declared dependency, not that "
                        "the API was called during execution."
                    ),
                )
            )

    exports = import_analysis.get("exports", [])
    if not isinstance(exports, list):
        raise ValueError("import_analysis.exports must be a list")

    for index, export in enumerate(exports):
        if not isinstance(export, Mapping):
            raise ValueError(f"Export at index {index} must be an object")

        export_name = export.get("name")
        records.append(
            _record(
                category="export",
                description=f"PE export observed: {export_name or 'ordinal export'}",
                source="import_analyzer",
                value=dict(export),
                location={"export_index": index},
                rationale="Export metadata describes symbols exposed by the PE.",
            )
        )

    strings = string_analysis.get("strings", [])
    if not isinstance(strings, list):
        raise ValueError("string_analysis.strings must be a list")

    for index, string in enumerate(strings):
        if not isinstance(string, Mapping):
            raise ValueError(f"String at index {index} must be an object")

        offset = string.get("offset")
        encoding = string.get("encoding")
        text = string.get("value")
        records.append(
            _record(
                category="string",
                description="Printable string extracted from the input",
                source="string_analyzer",
                value={
                    "value": text,
                    "offset": offset,
                    "encoding": encoding,
                },
                location={"offset": offset, "encoding": encoding},
                rationale=(
                    "An embedded string is a static artifact. It may be "
                    "unused, misleading, or unrelated to runtime behavior."
                ),
            )
        )

    iocs = ioc_analysis.get("iocs", [])
    if not isinstance(iocs, list):
        raise ValueError("ioc_analysis.iocs must be a list")

    for index, ioc in enumerate(iocs):
        if not isinstance(ioc, Mapping):
            raise ValueError(f"IOC at index {index} must be an object")

        ioc_type = ioc.get("type")
        ioc_value = dict(ioc)
        records.append(
            _record(
                category="ioc",
                description=(
                    f"Candidate {ioc_type or 'unknown-type'} indicator extracted"
                ),
                source="ioc_extractor",
                value=ioc_value,
                location={
                    "offset": ioc.get("offset"),
                    "source_encoding": ioc.get("source_encoding"),
                    "occurrence_index": index,
                },
                rationale=(
                    "This is a candidate indicator extracted from static "
                    "content. Format validation does not establish reachability, "
                    "ownership, maliciousness, or safety."
                ),
                caveats=[
                    "Indicator format validation is not a network lookup.",
                    "A candidate indicator may be benign or a false positive.",
                ],
            )
        )

    warning_sources = (
        ("section_analyzer", section_analysis),
        ("import_analyzer", import_analysis),
        ("string_analyzer", string_analysis),
        ("ioc_extractor", ioc_analysis),
    )
    for source, result in warning_sources:
        warnings = result.get("warnings", [])
        if not isinstance(warnings, list):
            raise ValueError(f"{source}.warnings must be a list")
        for index, warning in enumerate(warnings):
            if not isinstance(warning, str) or not warning.strip():
                continue
            records.append(
                _record(
                    category="parser_warning",
                    description=warning,
                    source=source,
                    value={"warning": warning},
                    location={"warning_index": index},
                    rationale=(
                        "The analyzer reported a limitation or warning that "
                        "should be considered when interpreting its output."
                    ),
                )
            )

    # Identical content at distinct source locations remains distinct because
    # location participates in the deterministic evidence identity.
    return records

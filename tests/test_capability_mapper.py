"""Tests for conversion of analyzer results into normalized evidence."""

from src.detection.capability_mapper import collect_evidence


def sample_inputs():
    return {
        "file_identity": {
            "path": "/samples/sample.exe",
            "size_bytes": 1234,
            "sha256": "a" * 64,
        },
        "pe_metadata": {
            "format": "PE",
            "architecture": "x86",
            "entry_point": 4096,
        },
        "section_analysis": {
            "section_count": 2,
            "sections": [
                {
                    "name": ".text",
                    "raw_offset": 512,
                    "virtual_address": 4096,
                    "writable": False,
                    "executable": True,
                    "entropy": 5.25,
                },
                {
                    "name": ".odd",
                    "raw_offset": 1024,
                    "virtual_address": 8192,
                    "writable": True,
                    "executable": True,
                    "entropy": 7.5,
                },
            ],
        },
        "import_analysis": {
            "imports": [
                {
                    "dll": "KERNEL32.dll",
                    "functions": [
                        {"name": "VirtualAlloc", "ordinal": None},
                        {"name": "ExitProcess", "ordinal": None},
                    ],
                }
            ],
            "exports": [
                {
                    "name": "ExportedFunction",
                    "ordinal": 1,
                    "address": 4096,
                    "forwarder": None,
                }
            ],
            "warnings": [],
        },
        "string_analysis": {
            "strings": [
                {"offset": 700, "encoding": "ascii", "value": "hello"},
                {"offset": 900, "encoding": "utf-16le", "value": "hello"},
            ],
            "warnings": [],
        },
        "ioc_analysis": {
            "iocs": [
                {
                    "type": "url",
                    "value": "https://example.org/",
                    "normalized_value": "https://example.org/",
                    "offset": 700,
                    "source_encoding": "ascii",
                    "origin": "string_analysis",
                    "validation_status": "valid_format",
                    "origins": [
                        {
                            "source": "string_analysis",
                            "offset": 700,
                            "encoding": "ascii",
                        }
                    ],
                }
            ],
            "warnings": [],
        },
    }


def collect():
    return collect_evidence(**sample_inputs())


def test_collector_returns_versioned_evidence_records():
    records = collect()

    assert records
    assert all(record.schema_version == "1.0.0" for record in records)
    assert all(record.record_type == "observation" for record in records)
    assert len({record.id for record in records}) == len(records)


def test_import_api_is_available_at_expected_rule_field():
    records = collect()

    virtual_alloc = [
        record
        for record in records
        if record.category == "import"
        and record.value["api"] == "VirtualAlloc"
    ]

    assert len(virtual_alloc) == 1
    assert virtual_alloc[0].value["dll"] == "KERNEL32.dll"
    assert virtual_alloc[0].source == "import_analyzer"


def test_section_writable_executable_is_derived_from_explicit_flags():
    records = collect()

    by_name = {
        record.value["name"]: record
        for record in records
        if record.category == "section"
    }

    assert by_name[".text"].value["writable_executable"] is False
    assert by_name[".odd"].value["writable_executable"] is True


def test_section_entropy_is_preserved_as_separate_evidence():
    records = collect()

    entropy = [
        record for record in records if record.category == "entropy"
    ]

    assert len(entropy) == 2
    assert {record.value["entropy"] for record in entropy} == {5.25, 7.5}


def test_repeated_string_content_at_different_locations_is_preserved():
    records = collect()

    repeated = [
        record
        for record in records
        if record.category == "string" and record.value["value"] == "hello"
    ]

    assert len(repeated) == 2
    assert {record.location["offset"] for record in repeated} == {700, 900}
    assert repeated[0].id != repeated[1].id


def test_ioc_evidence_preserves_validation_and_origin():
    records = collect()
    ioc = next(record for record in records if record.category == "ioc")

    assert ioc.value["type"] == "url"
    assert ioc.value["validation_status"] == "valid_format"
    assert ioc.value["origins"][0]["offset"] == 700
    assert "not a network lookup" in ioc.caveats[0]


def test_exports_and_file_identity_are_preserved():
    records = collect()

    file_record = next(
        record for record in records if record.category == "file_metadata"
    )
    export_record = next(
        record for record in records if record.category == "export"
    )

    assert file_record.value["sha256"] == "a" * 64
    assert export_record.value["name"] == "ExportedFunction"


def test_collector_does_not_mutate_analyzer_results():
    inputs = sample_inputs()
    original_section = dict(inputs["section_analysis"]["sections"][0])
    original_import = dict(inputs["import_analysis"]["imports"][0]["functions"][0])

    collect_evidence(**inputs)

    assert inputs["section_analysis"]["sections"][0] == original_section
    assert inputs["import_analysis"]["imports"][0]["functions"][0] == original_import


def test_malformed_section_collection_is_rejected():
    inputs = sample_inputs()
    inputs["section_analysis"]["sections"] = "not-a-list"

    try:
        collect_evidence(**inputs)
    except ValueError as exc:
        assert "sections must be a list" in str(exc)
    else:
        raise AssertionError("Expected malformed section data to be rejected")

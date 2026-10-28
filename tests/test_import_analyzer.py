"""Tests for static PE import/export analysis."""

import struct

import pytest

from src.analyzers.import_analyzer import (
    ImportAnalysisError,
    analyze_imports_exports,
)


def make_minimal_pe():
    """Build a synthetic PE32 header without import/export directories."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        0,
        0x12345678,
        0,
        0,
        224,
        0x0102,
    )

    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x010B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x1000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)

    return bytes(dos) + b"PE\0\0" + coff + bytes(optional)


def test_valid_pe_without_imports_or_exports(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    result = analyze_imports_exports(sample)

    assert result["import_library_count"] == 0
    assert result["imported_function_count"] == 0
    assert result["imports"] == []
    assert result["export_count"] == 0
    assert result["exports"] == []
    assert result["warnings"] == []


@pytest.mark.parametrize(
    "content",
    [
        b"not a PE file",
        b"",
        b"MZ" + b"\0" * 30,
    ],
)
def test_rejects_malformed_pe(tmp_path, content):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(content)

    with pytest.raises(ImportAnalysisError):
        analyze_imports_exports(sample)


def test_rejects_oversized_input(tmp_path):
    sample = tmp_path / "large.exe"
    sample.write_bytes(b"MZ" + b"\0" * 100)

    with pytest.raises(ImportAnalysisError, match="maximum size"):
        analyze_imports_exports(sample, max_file_size=50)


def test_rejects_directory(tmp_path):
    with pytest.raises(ImportAnalysisError, match="regular file"):
        analyze_imports_exports(tmp_path)


def test_rejects_unsupported_extension(tmp_path):
    sample = tmp_path / "fixture.bin"
    sample.write_bytes(make_minimal_pe())

    with pytest.raises(ImportAnalysisError, match="Unsupported input type"):
        analyze_imports_exports(sample)


def make_pe_with_import():
    """Build a synthetic PE with one import: KERNEL32.dll!ExitProcess."""
    data = bytearray(make_minimal_pe())
    data.extend(b"\0" * (0x400 - len(data)))

    # Update the PE header to declare one section.
    pe_offset = 0x80
    coff_offset = pe_offset + 4
    struct.pack_into("<H", data, coff_offset + 2, 1)

    # Optional header: one import data directory at RVA 0x1000.
    optional_offset = coff_offset + 20
    struct.pack_into("<I", data, optional_offset + 92, 16)
    struct.pack_into("<II", data, optional_offset + 96 + 8, 0x1000, 40)

    # One .rdata section maps RVA 0x1000 to file offset 0x200.
    section_offset = optional_offset + 224
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    data[section_offset : section_offset + 40] = section_header

    # Import descriptor at file offset 0x200.
    struct.pack_into("<IIIII", data, 0x200, 0x1040, 0, 0, 0x1050, 0x1060)

    # Null descriptor follows automatically because the buffer is zeroed.
    # Import lookup table at file offset 0x240.
    struct.pack_into("<II", data, 0x240, 0x1070, 0)

    # DLL name at file offset 0x250.
    data[0x250 : 0x250 + 13] = b"KERNEL32.dll\0"

    # Hint/name entry at file offset 0x270.
    struct.pack_into("<H", data, 0x270, 0)
    data[0x272 : 0x272 + 12] = b"ExitProcess\0"

    # IAT at file offset 0x260.
    struct.pack_into("<II", data, 0x260, 0x1070, 0)

    return bytes(data)


def test_extracts_imported_dll_and_function(tmp_path):
    sample = tmp_path / "imports.exe"
    sample.write_bytes(make_pe_with_import())

    result = analyze_imports_exports(sample)

    assert result["import_library_count"] == 1
    assert result["imported_function_count"] == 1
    assert result["imports"][0]["dll"].lower() == "kernel32.dll"
    assert result["imports"][0]["functions"][0]["name"] == "ExitProcess"
    assert result["imports"][0]["functions"][0]["ordinal"] is None

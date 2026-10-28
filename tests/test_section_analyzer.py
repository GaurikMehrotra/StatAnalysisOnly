"""Tests for static PE section analysis using synthetic fixtures."""

import struct

import pytest

from src.analyzers.pe_analyzer import PEAnalysisError
from src.analyzers.section_analyzer import analyze_sections


def make_pe_with_one_section(section_data=b"AB" * 256):
    """Build a synthetic PE32 file with one section; never execute it."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
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
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)

    headers = bytearray(dos + b"PE\0\0" + coff + optional)
    headers.extend(b"\0" * (0x200 - len(headers)))

    padded_data = section_data.ljust(
        ((len(section_data) + 0x1FF) // 0x200) * 0x200,
        b"\0",
    )

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        len(section_data),
        0x1000,
        len(padded_data),
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    headers[0x80 + 4 + 20 + 224 : 0x80 + 4 + 20 + 224 + 40] = (
        section_header
    )

    return bytes(headers) + padded_data


def test_extracts_section_metadata(tmp_path):
    sample = tmp_path / "section-fixture.exe"
    sample.write_bytes(make_pe_with_one_section())

    result = analyze_sections(sample)

    assert result["section_count"] == 1
    section = result["sections"][0]
    assert section["name"] == ".text"
    assert section["virtual_address"] == 0x1000
    assert section["virtual_size"] == 512
    assert section["raw_offset"] == 0x200
    assert section["raw_size"] == 512
    assert section["readable"] is True
    assert section["writable"] is False
    assert section["executable"] is True
    assert section["entropy"] == pytest.approx(1.0)


def test_rejects_non_pe_input(tmp_path):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(b"not a PE file")

    with pytest.raises(PEAnalysisError):
        analyze_sections(sample)


def test_rejects_oversized_input(tmp_path):
    sample = tmp_path / "large.exe"
    sample.write_bytes(b"MZ" + b"\0" * 100)

    with pytest.raises(PEAnalysisError, match="maximum size"):
        analyze_sections(sample, max_file_size=50)


def test_rejects_directory(tmp_path):
    with pytest.raises(PEAnalysisError, match="regular file"):
        analyze_sections(tmp_path)


def test_rejects_truncated_section_data(tmp_path):
    sample = tmp_path / "truncated-section.exe"
    sample.write_bytes(make_pe_with_one_section()[:-10])

    with pytest.raises(PEAnalysisError, match="raw data extends beyond"):
        analyze_sections(sample)

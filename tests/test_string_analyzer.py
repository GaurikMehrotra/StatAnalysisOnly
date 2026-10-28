"""Tests for bounded static string extraction."""

import pytest

from src.analyzers.string_analyzer import (
    StringAnalysisError,
    analyze_strings,
)


def make_synthetic_pe(payload: bytes) -> bytes:
    """Build a harmless synthetic DOS header and PE signature."""
    header = bytearray(0x80)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")
    header[0x40:0x44] = b"PE\x00\x00"
    return bytes(header) + payload


def test_extracts_ascii_strings_with_offsets(tmp_path):
    sample = tmp_path / "fixture.exe"
    data = make_synthetic_pe(b"\x00HelloWorld\x00")
    sample.write_bytes(data)

    result = analyze_strings(sample)

    matches = [
        item for item in result["strings"]
        if item["value"] == "HelloWorld"
    ]
    assert len(matches) == 1
    assert matches[0]["encoding"] == "ascii"
    assert matches[0]["offset"] == data.index(b"HelloWorld")


def test_extracts_utf16le_strings(tmp_path):
    sample = tmp_path / "fixture.exe"
    payload = "WideString".encode("utf-16le")
    sample.write_bytes(make_synthetic_pe(b"\x00\x00" + payload + b"\x00\x00"))

    result = analyze_strings(sample)

    assert any(
        item["value"] == "WideString" and item["encoding"] == "utf-16le"
        for item in result["strings"]
    )


def test_respects_minimum_string_length(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_synthetic_pe(b"\x00ABC\x00ABCD\x00"))

    result = analyze_strings(sample, min_length=4)

    values = [item["value"] for item in result["strings"]]
    assert "ABCD" in values
    assert "ABC" not in values


def test_limits_number_of_results(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_synthetic_pe(b"\x00ONE1\x00TWO2\x00THREE3\x00"))

    result = analyze_strings(sample, max_strings=2)

    assert result["string_count"] == 2
    assert len(result["strings"]) == 2
    assert result["truncated"] is True
    assert result["warnings"]


@pytest.mark.parametrize("content", [b"", b"ordinary text", b"MZ"])
def test_rejects_empty_or_non_pe_like_input(tmp_path, content):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(content)

    with pytest.raises(StringAnalysisError):
        analyze_strings(sample)


def test_rejects_oversized_input(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_synthetic_pe(b"LONGSTRING"))

    with pytest.raises(StringAnalysisError, match="size"):
        analyze_strings(sample, max_file_size=16)


def test_rejects_unsupported_extension(tmp_path):
    sample = tmp_path / "fixture.txt"
    sample.write_bytes(make_synthetic_pe(b"HelloWorld"))

    with pytest.raises(StringAnalysisError, match="Unsupported"):
        analyze_strings(sample)


def test_rejects_symlink(tmp_path):
    target = tmp_path / "target.exe"
    target.write_bytes(make_synthetic_pe(b"HelloWorld"))
    link = tmp_path / "link.exe"
    link.symlink_to(target)

    with pytest.raises(StringAnalysisError, match="Symbolic links"):
        analyze_strings(link)


def test_rejects_invalid_configuration(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_synthetic_pe(b"HelloWorld"))

    with pytest.raises(ValueError, match="min_length"):
        analyze_strings(sample, min_length=0)
    with pytest.raises(ValueError, match="max_strings"):
        analyze_strings(sample, max_strings=0)

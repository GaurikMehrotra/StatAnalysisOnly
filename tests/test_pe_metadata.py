import struct

import pytest

from src.analyzers.pe_analyzer import PEAnalysisError, analyze_pe


def make_minimal_pe():
    """Create a minimal synthetic PE32 header for parser tests."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # x86
        0,  # sections
        0x12345678,  # intentionally untrusted timestamp
        0,
        0,
        224,  # PE32 optional header size
        0x0102,  # executable image and 32-bit machine
    )

    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x010B)  # PE32
    struct.pack_into("<I", optional, 16, 0x1000)  # entry point
    struct.pack_into("<I", optional, 28, 0x400000)  # image base
    struct.pack_into("<I", optional, 32, 0x1000)  # section alignment
    struct.pack_into("<I", optional, 36, 0x200)  # file alignment
    struct.pack_into("<I", optional, 56, 0x1000)  # image size
    struct.pack_into("<I", optional, 60, 0x200)  # headers size
    struct.pack_into("<H", optional, 68, 3)  # console subsystem
    struct.pack_into("<I", optional, 92, 16)  # data directories

    return bytes(dos) + b"PE\0\0" + coff + bytes(optional)


def test_extracts_pe_metadata(tmp_path):
    sample = tmp_path / "fixture.exe"
    sample.write_bytes(make_minimal_pe())

    result = analyze_pe(sample)

    assert result["format"] == "PE"
    assert result["architecture"] == "x86"
    assert result["machine"] == 0x014C
    assert result["entry_point"] == 0x1000
    assert result["image_base"] == 0x400000
    assert result["subsystem"] == "WINDOWS_CUI"
    assert result["timestamp"] == 0x12345678
    assert "forged" in result["timestamp_caveat"]
    assert "EXECUTABLE_IMAGE" in result["characteristic_flags"]


@pytest.mark.parametrize(
    "content",
    [
        b"ordinary text renamed to exe",
        b"",
        b"MZ" + b"\0" * 30,
    ],
)
def test_rejects_malformed_pe(tmp_path, content):
    sample = tmp_path / "invalid.exe"
    sample.write_bytes(content)

    with pytest.raises(PEAnalysisError):
        analyze_pe(sample)


@pytest.mark.parametrize(
    "truncate_at",
    [
        0x40,                 # Truncated DOS header
        0x82,                 # Truncated PE signature
        0x80 + 4 + 10,        # Truncated COFF header
        0x80 + 4 + 20 + 20,   # Truncated optional header
        0x80 + 4 + 20 + 223,  # Optional header short by one byte
    ],
)
def test_rejects_truncated_pe_structures(tmp_path, truncate_at):
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(make_minimal_pe()[:truncate_at])

    with pytest.raises(PEAnalysisError):
        analyze_pe(sample)


def test_rejects_oversized_input(tmp_path):
    sample = tmp_path / "large.exe"
    sample.write_bytes(b"MZ" + b"\0" * 100)

    with pytest.raises(PEAnalysisError, match="maximum size"):
        analyze_pe(sample, max_file_size=50)


def test_rejects_directory(tmp_path):
    with pytest.raises(PEAnalysisError, match="regular file"):
        analyze_pe(tmp_path)

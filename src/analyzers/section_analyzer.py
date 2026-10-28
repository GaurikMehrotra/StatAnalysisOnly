"""Static section analysis for Windows Portable Executable files."""

import stat
import struct
from pathlib import Path

import pefile

from src.analyzers.entropy_analyzer import calculate_entropy
from src.analyzers.pe_analyzer import DEFAULT_MAX_FILE_SIZE, PEAnalysisError

SECTION_FLAGS = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


def analyze_sections(
    file_path: str | Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict[str, object]:
    """Extract PE section metadata and entropy without executing the file."""
    if max_file_size <= 0:
        raise ValueError("max_file_size must be greater than zero")

    path = Path(file_path).expanduser()

    try:
        file_info = path.lstat()
    except OSError as exc:
        raise PEAnalysisError(f"Cannot access input file: {exc}") from exc

    if stat.S_ISLNK(file_info.st_mode):
        raise PEAnalysisError("Symbolic links are not accepted")

    if not stat.S_ISREG(file_info.st_mode):
        raise PEAnalysisError("Input must be a regular file")

    if file_info.st_size == 0:
        raise PEAnalysisError("PE input is empty")

    if file_info.st_size > max_file_size:
        raise PEAnalysisError(
            f"PE input exceeds the maximum size of {max_file_size} bytes"
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PEAnalysisError(f"Cannot read PE input: {exc}") from exc

    if len(data) != file_info.st_size:
        raise PEAnalysisError("Input changed while being read")

    if len(data) > max_file_size:
        raise PEAnalysisError("PE input exceeds the configured size limit")

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, ValueError, IndexError, struct.error) as exc:
        raise PEAnalysisError(f"Invalid or malformed PE file: {exc}") from exc

    try:
        sections = []

        for section in pe.sections:
            raw_name = bytes(section.Name).split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            characteristics = int(section.Characteristics)

            flags = [
                flag_name
                for bit, flag_name in SECTION_FLAGS.items()
                if characteristics & bit
            ]

            raw_offset = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)

            if raw_size and (
                raw_offset > len(data) or raw_size > len(data) - raw_offset
            ):
                raise PEAnalysisError(
                    f"Section {name!r} raw data extends beyond the input file"
                )

            raw_data = data[raw_offset : raw_offset + raw_size] if raw_size else b""
            sections.append(
                {
                    "name": name,
                    "virtual_address": int(section.VirtualAddress),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_offset": raw_offset,
                    "raw_size": raw_size,
                    "characteristics": characteristics,
                    "flags": flags,
                    "readable": bool(characteristics & 0x40000000),
                    "writable": bool(characteristics & 0x80000000),
                    "executable": bool(characteristics & 0x20000000),
                    "entropy": calculate_entropy(raw_data),
                }
            )

        return {
            "section_count": len(sections),
            "sections": sections,
        }
    except (AttributeError, IndexError, ValueError, struct.error) as exc:
        raise PEAnalysisError(f"Cannot extract PE section metadata: {exc}") from exc
    finally:
        pe.close()

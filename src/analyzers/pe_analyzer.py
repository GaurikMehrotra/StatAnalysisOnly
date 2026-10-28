"""Defensive, static parsing of Windows Portable Executable files."""

import stat
import struct
from pathlib import Path

import pefile

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMNT",
    0xAA64: "ARM64",
}

SUBSYSTEM_NAMES = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
}

CHARACTERISTIC_FLAGS = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}


class PEAnalysisError(ValueError):
    """Raised when a file cannot be safely parsed as a PE."""


def analyze_pe(
    file_path: str | Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict[str, object]:
    """Parse PE headers and return metadata; never execute the input."""
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

    if len(data) > max_file_size:
        raise PEAnalysisError("PE input exceeds the configured size limit")

    if len(data) != file_info.st_size:
        raise PEAnalysisError("Input changed while being read")

    if not data.startswith(b"MZ"):
        raise PEAnalysisError("Invalid DOS signature: expected MZ")

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError, IndexError, struct.error) as exc:
        raise PEAnalysisError(f"Invalid or malformed PE file: {exc}") from exc

    try:
        if pe.NT_HEADERS.Signature != 0x00004550:
            raise PEAnalysisError("Invalid PE signature")

        if pe.FILE_HEADER is None or pe.OPTIONAL_HEADER is None:
            raise PEAnalysisError("Required PE headers are missing")

        file_header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER

        characteristics = int(file_header.Characteristics)
        flags = [
            name
            for bit, name in CHARACTERISTIC_FLAGS.items()
            if characteristics & bit
        ]

        return {
            "format": "PE",
            "architecture": MACHINE_NAMES.get(
                int(file_header.Machine), "UNKNOWN"
            ),
            "machine": int(file_header.Machine),
            "number_of_sections": int(file_header.NumberOfSections),
            "timestamp": int(file_header.TimeDateStamp),
            "timestamp_caveat": (
                "Untrusted metadata; the timestamp may be forged or altered."
            ),
            "optional_header_magic": int(optional.Magic),
            "entry_point": int(optional.AddressOfEntryPoint),
            "image_base": int(optional.ImageBase),
            "subsystem": SUBSYSTEM_NAMES.get(
                int(optional.Subsystem), "UNKNOWN"
            ),
            "characteristics": characteristics,
            "characteristic_flags": flags,
            "size_of_image": int(optional.SizeOfImage),
            "size_of_headers": int(optional.SizeOfHeaders),
        }
    except AttributeError as exc:
        raise PEAnalysisError(
            f"Required PE metadata is unavailable: {exc}"
        ) from exc
    finally:
        pe.close()


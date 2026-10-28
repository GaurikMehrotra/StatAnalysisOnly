"""Bounded printable-string extraction for static PE analysis."""

import re
import stat
from pathlib import Path

from src.analyzers.pe_analyzer import DEFAULT_MAX_FILE_SIZE

SUPPORTED_EXTENSIONS = {".exe", ".dll", ".sys"}
DEFAULT_MIN_LENGTH = 4
DEFAULT_MAX_STRINGS = 10_000

_ASCII_PRINTABLE = rb"[\x20-\x7e]"
_UTF16LE_PRINTABLE = rb"(?:[\x20-\x7e]\x00)"


class StringAnalysisError(ValueError):
    """Raised when a file cannot be safely analyzed for strings."""


def analyze_strings(
    file_path: str | Path,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict[str, object]:
    """Extract printable ASCII and UTF-16LE strings without execution."""
    if min_length < 1:
        raise ValueError("min_length must be greater than zero")
    if max_strings < 1:
        raise ValueError("max_strings must be greater than zero")
    if max_file_size < 1:
        raise ValueError("max_file_size must be greater than zero")

    path = Path(file_path).expanduser()

    try:
        before = path.lstat()
    except OSError as exc:
        raise StringAnalysisError(
            f"Cannot access input file: {exc}"
        ) from exc

    if stat.S_ISLNK(before.st_mode):
        raise StringAnalysisError("Symbolic links are not accepted")
    if not stat.S_ISREG(before.st_mode):
        raise StringAnalysisError("Input must be a regular file")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise StringAnalysisError(
            "Unsupported input type: expected .exe, .dll, or .sys"
        )
    if before.st_size == 0:
        raise StringAnalysisError("Input file is empty")
    if before.st_size > max_file_size:
        raise StringAnalysisError(
            f"Input exceeds the maximum size of {max_file_size} bytes"
        )

    try:
        with path.open("rb") as input_file:
            data = input_file.read(max_file_size + 1)
        after = path.stat()
    except OSError as exc:
        raise StringAnalysisError(f"Cannot read input file: {exc}") from exc

    if len(data) > max_file_size:
        raise StringAnalysisError("Input exceeds the configured size limit")
    if (
        len(data) != before.st_size
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise StringAnalysisError("Input changed during inspection")
    if not data.startswith(b"MZ"):
        raise StringAnalysisError("Invalid DOS signature: expected MZ")

    # Validate the DOS header's PE offset and the PE signature.
    if len(data) < 0x40:
        raise StringAnalysisError("Truncated DOS header")

    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 4 > len(data):
        raise StringAnalysisError("Invalid or truncated PE header offset")
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise StringAnalysisError("Invalid PE signature")

    # Collect one extra result to determine whether the output was truncated.
    limit = max_strings + 1
    results: list[dict[str, object]] = []

    patterns = (
        ("ascii", re.compile(_ASCII_PRINTABLE + rb"{%d,}" % min_length)),
        (
            "utf-16le",
            re.compile(_UTF16LE_PRINTABLE + rb"{%d,}" % min_length),
        ),
    )

    for encoding, pattern in patterns:
        for match in pattern.finditer(data):
            if encoding == "ascii":
                value = match.group().decode("ascii")
            else:
                value = match.group().decode("utf-16le")

            results.append(
                {
                    "offset": match.start(),
                    "encoding": encoding,
                    "value": value,
                }
            )
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    results.sort(key=lambda item: int(item["offset"]))
    truncated = len(results) > max_strings
    results = results[:max_strings]

    warnings = []
    if truncated:
        warnings.append(
            f"String output was limited to {max_strings} results."
        )

    return {
        "string_count": len(results),
        "strings": results,
        "truncated": truncated,
        "warnings": warnings,
    }

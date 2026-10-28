"""Static import and export analysis for Windows PE files."""

import stat
import struct
from pathlib import Path

import pefile

MAX_FILE_SIZE = 100 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".exe", ".dll", ".sys"}
MAX_REPORTED_SYMBOLS = 10_000


class ImportAnalysisError(ValueError):
    """Raised when a PE file cannot be safely analyzed."""


def _decode_name(value: bytes | None) -> str | None:
    """Decode a PE symbol name without assuming valid text."""
    if value is None:
        return None
    return value.decode("utf-8", errors="replace")


def analyze_imports_exports(
    file_path: str | Path,
    *,
    max_file_size: int = MAX_FILE_SIZE,
) -> dict[str, object]:
    """Extract imported DLLs/functions and exported symbols without execution."""
    if max_file_size <= 0:
        raise ValueError("max_file_size must be greater than zero")

    path = Path(file_path).expanduser()

    try:
        file_info = path.lstat()
    except OSError as exc:
        raise ImportAnalysisError(f"Cannot access input file: {exc}") from exc

    if stat.S_ISLNK(file_info.st_mode):
        raise ImportAnalysisError("Symbolic links are not accepted")

    if not stat.S_ISREG(file_info.st_mode):
        raise ImportAnalysisError("Input must be a regular file")

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ImportAnalysisError(
            "Unsupported input type: expected .exe, .dll, or .sys"
        )

    if file_info.st_size == 0:
        raise ImportAnalysisError("PE input is empty")

    if file_info.st_size > max_file_size:
        raise ImportAnalysisError(
            f"PE input exceeds the maximum size of {max_file_size} bytes"
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ImportAnalysisError(f"Cannot read PE input: {exc}") from exc

    if len(data) != file_info.st_size:
        raise ImportAnalysisError("Input changed while being read")

    if len(data) > max_file_size:
        raise ImportAnalysisError("PE input exceeds the configured size limit")

    if not data.startswith(b"MZ"):
        raise ImportAnalysisError("Invalid DOS signature: expected MZ")

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError, IndexError, struct.error) as exc:
        raise ImportAnalysisError(f"Invalid or malformed PE file: {exc}") from exc

    try:
        if pe.NT_HEADERS.Signature != 0x00004550:
            raise ImportAnalysisError("Invalid PE signature")

        imports = []
        exports = []
        warnings = []

        for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            functions = []

            for symbol in library.imports:
                functions.append(
                    {
                        "name": _decode_name(symbol.name),
                        "ordinal": (
                            int(symbol.ordinal) if symbol.ordinal is not None else None
                        ),
                    }
                )

            imports.append(
                {
                    "dll": _decode_name(library.dll),
                    "functions": functions,
                }
            )

        export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_directory is not None:
            for symbol in export_directory.symbols:
                exports.append(
                    {
                        "name": _decode_name(symbol.name),
                        "ordinal": int(symbol.ordinal),
                        "address": int(symbol.address),
                        "forwarder": _decode_name(symbol.forwarder),
                    }
                )

        if len(imports) > MAX_REPORTED_SYMBOLS:
            imports = imports[:MAX_REPORTED_SYMBOLS]
            warnings.append("Import library count was truncated at the safety limit.")

        if len(exports) > MAX_REPORTED_SYMBOLS:
            exports = exports[:MAX_REPORTED_SYMBOLS]
            warnings.append("Export symbol count was truncated at the safety limit.")

        imported_function_count = sum(len(library["functions"]) for library in imports)

        return {
            "import_library_count": len(imports),
            "imported_function_count": imported_function_count,
            "imports": imports,
            "export_count": len(exports),
            "exports": exports,
            "warnings": warnings,
        }
    except (AttributeError, IndexError, TypeError, ValueError, struct.error) as exc:
        if isinstance(exc, ImportAnalysisError):
            raise
        raise ImportAnalysisError(
            f"Cannot extract PE import/export metadata: {exc}"
        ) from exc
    finally:
        pe.close()

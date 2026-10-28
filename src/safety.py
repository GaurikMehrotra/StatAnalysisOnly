"""Safe input validation and identity calculation for static PE analysis."""

import hashlib
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB
SUPPORTED_INPUT_EXTENSIONS = {".exe", ".dll", ".sys"}
HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB


class InputValidationError(ValueError):
    """Raised when an input file fails safety validation."""


@dataclass(frozen=True)
class InputIdentity:
    """Identity and basic metadata for an accepted input file."""

    path: str
    filename: str
    size_bytes: int
    sha256: str
    format: str = "PE"


def inspect_input(
    file_path: str | Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> InputIdentity:
    """Validate a PE input and calculate its SHA-256 without executing it."""
    if max_file_size <= 0:
        raise ValueError("max_file_size must be greater than zero")

    path = Path(file_path).expanduser()

    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise InputValidationError(f"Input file does not exist: {path}") from exc
    except OSError as exc:
        raise InputValidationError(f"Cannot inspect input path: {exc}") from exc

    if stat.S_ISLNK(file_stat.st_mode):
        raise InputValidationError("Symbolic links are not accepted")

    if not stat.S_ISREG(file_stat.st_mode):
        raise InputValidationError("Input must be a regular file")

    if path.suffix.lower() not in SUPPORTED_INPUT_EXTENSIONS:
        raise InputValidationError(
            "Unsupported input type: expected .exe, .dll, or .sys"
        )

    if file_stat.st_size == 0:
        raise InputValidationError("Input file is empty")

    if file_stat.st_size > max_file_size:
        raise InputValidationError(
            f"Input exceeds the maximum size of {max_file_size} bytes"
        )

    digest = hashlib.sha256()
    bytes_read = 0

    try:
        with path.open("rb") as input_file:
            while chunk := input_file.read(HASH_CHUNK_SIZE):
                bytes_read += len(chunk)

                if bytes_read > max_file_size:
                    raise InputValidationError(
                        "Input exceeded the maximum size while being read"
                    )

                digest.update(chunk)

        final_stat = path.stat()
        if (
            bytes_read != file_stat.st_size
            or final_stat.st_size != file_stat.st_size
            or final_stat.st_mtime_ns != file_stat.st_mtime_ns
        ):
            raise InputValidationError("Input changed during inspection")

    except InputValidationError:
        raise
    except OSError as exc:
        raise InputValidationError(f"Cannot read input file: {exc}") from exc

    return InputIdentity(
        path=str(path.resolve()),
        filename=path.name,
        size_bytes=bytes_read,
        sha256=digest.hexdigest(),
    )


def identity_to_dict(identity: InputIdentity) -> dict[str, object]:
    """Convert input identity to a JSON-serializable dictionary."""
    return asdict(identity)

import hashlib

import pytest

from src.safety import (
    InputValidationError,
    identity_to_dict,
    inspect_input,
)


def test_accepts_file_and_calculates_sha256(tmp_path):
    content = b"benign synthetic fixture"
    sample = tmp_path / "sample.exe"
    sample.write_bytes(content)

    result = inspect_input(sample)

    assert result.filename == "sample.exe"
    assert result.size_bytes == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.format == "PE"
    assert identity_to_dict(result)["sha256"] == result.sha256


def test_rejects_missing_file(tmp_path):
    with pytest.raises(InputValidationError, match="does not exist"):
        inspect_input(tmp_path / "missing.exe")


def test_rejects_directory(tmp_path):
    with pytest.raises(InputValidationError, match="regular file"):
        inspect_input(tmp_path)


def test_rejects_empty_file(tmp_path):
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"")

    with pytest.raises(InputValidationError, match="empty"):
        inspect_input(sample)


def test_rejects_unsupported_extension(tmp_path):
    sample = tmp_path / "notes.txt"
    sample.write_text("test")

    with pytest.raises(InputValidationError, match="Unsupported"):
        inspect_input(sample)


def test_rejects_oversized_file(tmp_path):
    sample = tmp_path / "large.exe"
    sample.write_bytes(b"A" * 11)

    with pytest.raises(InputValidationError, match="maximum size"):
        inspect_input(sample, max_file_size=10)


def test_rejects_invalid_size_limit(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"A")

    with pytest.raises(ValueError, match="greater than zero"):
        inspect_input(sample, max_file_size=0)


def test_hash_is_repeatable(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"same bytes")

    first = inspect_input(sample)
    second = inspect_input(sample)

    assert first.sha256 == second.sha256
    assert first.size_bytes == second.size_bytes


def test_rejects_symbolic_link(tmp_path):
    target = tmp_path / "target.exe"
    target.write_bytes(b"test bytes")
    link = tmp_path / "linked.exe"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are unavailable in this environment")

    with pytest.raises(InputValidationError, match="Symbolic links"):
        inspect_input(link)


def test_inspect_input_accepts_dll_and_sys_extensions(tmp_path):
    for extension in (".dll", ".sys"):
        sample = tmp_path / f"sample{extension}"
        sample.write_bytes(b"synthetic test content")

        identity = inspect_input(sample)

        assert identity.filename == sample.name
        assert identity.size_bytes == len(b"synthetic test content")

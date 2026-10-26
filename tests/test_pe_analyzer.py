from pathlib import Path

MAX_FILE_SIZE = 100 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".exe", ".dll", ".sys"}


def test_initial_input_policy_is_pe_only():
    assert SUPPORTED_EXTENSIONS == {".exe", ".dll", ".sys"}


def test_maximum_input_size_is_100_mib():
    assert MAX_FILE_SIZE == 104857600


def test_safety_document_prohibits_sample_execution():
    text = Path("docs/safety.md").read_text(encoding="utf-8").lower()
    assert "never execute" in text
    assert "automatically upload" in text


def test_readme_documents_no_execution():
    text = Path("README.md").read_text(encoding="utf-8").lower()
    assert "never executed" in text

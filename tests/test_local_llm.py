"""Tests for the optional local AI adapter; no live model is required."""

import json
from urllib.error import URLError

import pytest

from src.ai.local_llm import (
    build_evidence_summary,
    explain_report,
    validate_ai_output,
)

EVIDENCE_ID = "ev_0123456789abcdef"


def sample_report():
    return {
        "file": {"format": "PE", "sha256": "sensitive-hash"},
        "triage": {"status": "rules_matched", "score": 10, "severity": "low"},
        "findings": [
            {
                "title": "Test finding",
                "capability": "test",
                "severity": "low",
                "rule_ids": ["RULE-1"],
                "evidence_ids": [EVIDENCE_ID],
            }
        ],
        "evidence": [
            {
                "id": EVIDENCE_ID,
                "category": "import",
                "source": "import_analyzer",
                "description": "Synthetic import observation",
                "severity": "informational",
                "value": "must-not-be-sent",
            }
        ],
    }


def valid_output():
    return {
        "summary": "One static observation supports a cautious explanation.",
        "claims": [
            {
                "text": "The import is a static clue, not proof of runtime behavior.",
                "evidence_ids": [EVIDENCE_ID],
            }
        ],
    }


def test_summary_is_bounded_and_excludes_hash_and_raw_values():
    summary = build_evidence_summary(sample_report())

    assert len(summary) <= 12_000
    assert "sensitive-hash" not in summary
    assert "must-not-be-sent" not in summary
    assert EVIDENCE_ID in summary
    assert "Synthetic import observation" not in summary
    assert "Test finding" not in summary
    assert "RULE-1" not in summary


def test_summary_rejects_excessive_size_limit():
    with pytest.raises(ValueError, match="size limit"):
        build_evidence_summary(sample_report(), max_chars=10)


def test_valid_ai_output_is_accepted_with_ai_label():
    result = validate_ai_output(
        valid_output(),
        evidence_ids={EVIDENCE_ID},
        model="test-model",
    )

    assert result["status"] == "available"
    assert result["generated_by_ai"] is True
    assert result["claims"][0]["evidence_ids"] == [EVIDENCE_ID]
    assert "not a verified detection" in result["limitations"]


def test_invented_evidence_id_is_rejected():
    output = valid_output()
    output["claims"][0]["evidence_ids"] = ["ev_aaaaaaaaaaaaaaaa"]

    with pytest.raises(ValueError, match="unknown evidence"):
        validate_ai_output(output, evidence_ids={EVIDENCE_ID}, model="test-model")


def test_malformed_output_is_rejected():
    with pytest.raises(ValueError, match="summary and claims"):
        validate_ai_output(
            {"summary": "No claims key"},
            evidence_ids={EVIDENCE_ID},
            model="test-model",
        )


def test_unavailable_model_falls_back_without_raising(monkeypatch):
    def unavailable(*args, **kwargs):
        raise URLError("connection refused")

    monkeypatch.setattr("src.ai.local_llm.urlopen", unavailable)

    result = explain_report(sample_report())

    assert result["status"] == "unavailable"
    assert "unavailable" in result["reason"]


def test_timeout_falls_back_without_raising(monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr("src.ai.local_llm.urlopen", timed_out)

    result = explain_report(sample_report())

    assert result["status"] == "timeout"


def test_model_response_with_invented_id_is_rejected(monkeypatch):
    output = valid_output()
    output["claims"][0]["evidence_ids"] = ["ev_aaaaaaaaaaaaaaaa"]
    envelope = json.dumps({"response": json.dumps(output)}).encode()

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return envelope

    monkeypatch.setattr(
        "src.ai.local_llm.urlopen", lambda *args, **kwargs: FakeResponse()
    )

    result = explain_report(sample_report())

    assert result["status"] == "rejected"


def test_remote_endpoint_is_rejected_before_network_access(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Network access should not be attempted.")

    monkeypatch.setattr("src.ai.local_llm.urlopen", unexpected)

    result = explain_report(sample_report(), base_url="http://example.com:11434")

    assert result["status"] == "rejected"


def test_malformed_model_envelope_is_rejected(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            return b"not-json"

    monkeypatch.setattr(
        "src.ai.local_llm.urlopen", lambda *args, **kwargs: FakeResponse()
    )

    result = explain_report(sample_report())

    assert result["status"] == "rejected"


def test_ipv6_loopback_endpoint_is_formatted_correctly():
    from src.ai.local_llm import _local_endpoint

    assert _local_endpoint("http://[::1]:11434") == "http://[::1]:11434/api/generate"

"""Tests for static IOC extraction using synthetic strings."""

import pytest

from src.detection.ioc_extractor import IOCExtractionError, extract_iocs


def make_string(value: str, offset: int = 100) -> dict[str, object]:
    return {"value": value, "offset": offset, "encoding": "ascii"}


def test_extracts_url_domain_email_and_ipv4():
    result = extract_iocs(
        [
            make_string(
                "Visit https://updates.example.org/check and email "
                "analyst@example.net from 192.0.2.10"
            )
        ]
    )

    types = {item["type"] for item in result["iocs"]}
    values = {item["value"] for item in result["iocs"]}

    assert {"url", "domain", "email", "ipv4"} <= types
    assert "https://updates.example.org/check" in values
    assert "analyst@example.net" in values
    assert "192.0.2.10" in values
    assert result["truncated"] is False


def test_offsets_are_absolute_file_offsets():
    result = extract_iocs([make_string("xx 203.0.113.7", offset=40)])
    ipv4 = next(item for item in result["iocs"] if item["type"] == "ipv4")

    assert ipv4["offset"] == 43


def test_rejects_invalid_ipv4_address():
    result = extract_iocs([make_string("999.999.999.999")])

    assert not any(item["type"] == "ipv4" for item in result["iocs"])


def test_deduplicates_indicators_case_insensitively():
    result = extract_iocs(
        [
            make_string("https://Example.org/a", offset=10),
            make_string("https://example.org/a", offset=50),
        ]
    )

    urls = [item for item in result["iocs"] if item["type"] == "url"]
    assert len(urls) == 1
    assert urls[0]["offset"] == 10


def test_respects_ioc_limit_and_marks_truncation():
    result = extract_iocs(
        [make_string("https://one.example https://two.example")],
        max_iocs=1,
    )

    assert result["ioc_count"] == 1
    assert result["truncated"] is True


@pytest.mark.parametrize("max_iocs", [0, -1, True, 1.5, "2"])
def test_rejects_invalid_ioc_limit(max_iocs):
    with pytest.raises(IOCExtractionError):
        extract_iocs([], max_iocs=max_iocs)


def test_rejects_invalid_string_entries():
    with pytest.raises(IOCExtractionError):
        extract_iocs([{"value": "example.org", "offset": -1, "encoding": "ascii"}])


def test_empty_input_returns_empty_results():
    result = extract_iocs([])

    assert result["ioc_count"] == 0
    assert result["iocs"] == []
    assert result["truncated"] is False


def test_url_trailing_punctuation_is_not_included():
    result = extract_iocs([make_string("See https://example.org/path.")])
    url = next(item for item in result["iocs"] if item["type"] == "url")

    assert url["value"] == "https://example.org/path"
    assert url["offset"] == 104


def test_url_and_embedded_domain_are_reported_as_distinct_types():
    result = extract_iocs([make_string("https://updates.example.org/check")])

    assert any(item["type"] == "url" for item in result["iocs"])
    assert any(
        item["type"] == "domain" and item["value"] == "updates.example.org"
        for item in result["iocs"]
    )


def test_extracts_com_domain():
    result = extract_iocs([make_string("Connect to example.com")])
    domains = [item for item in result["iocs"] if item["type"] == "domain"]

    assert any(item["value"] == "example.com" for item in domains)

"""Bounded IOC extraction from strings recovered during static analysis."""

import ipaddress
import re

DEFAULT_MAX_IOCS = 1_000

_URL_RE = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s"'<>]+""")
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w.-])"
)
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)

# Avoid treating common executable and document extensions as domain TLDs.
_NON_DOMAIN_SUFFIXES = {
    "bin", "cfg", "dll", "doc", "exe", "gif", "ini",
    "jpg", "json", "log", "pdf", "png", "ps1", "py", "sys",
    "tmp", "txt", "xml", "yaml", "yml",
}


class IOCExtractionError(ValueError):
    """Raised when IOC extraction receives invalid input."""


def extract_iocs(
    strings: list[dict[str, object]],
    *,
    max_iocs: int = DEFAULT_MAX_IOCS,
) -> dict[str, object]:
    """Extract and deduplicate common IOCs from string-analysis results.

    Each input string entry must contain a non-negative integer ``offset``,
    a string ``encoding``, and a string ``value``.
    Offsets in results refer to byte positions in the original file.
    """
    if (
        isinstance(max_iocs, bool)
        or not isinstance(max_iocs, int)
        or max_iocs < 1
    ):
        raise IOCExtractionError("max_iocs must be a positive integer")
    if not isinstance(strings, list):
        raise IOCExtractionError("strings must be a list")

    found: dict[tuple[str, str], dict[str, object]] = {}
    truncated = False

    for entry in strings:
        if not isinstance(entry, dict):
            raise IOCExtractionError("Each string entry must be an object")

        offset = entry.get("offset")
        encoding = entry.get("encoding")
        value = entry.get("value")

        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise IOCExtractionError("String offset must be a non-negative integer")
        if not isinstance(encoding, str) or not isinstance(value, str):
            raise IOCExtractionError(
                "Each string entry must contain string encoding and value fields"
            )

        patterns = (
            ("url", _URL_RE),
            ("email", _EMAIL_RE),
            ("ipv4", _IPV4_RE),
            ("domain", _DOMAIN_RE),
        )

        for ioc_type, pattern in patterns:
            for match in pattern.finditer(value):
                candidate = match.group(0)

                if ioc_type == "url":
                    while candidate and candidate[-1] in ".,;:!?)]}":
                        candidate = candidate[:-1]
                    if not candidate:
                        continue
                elif ioc_type == "ipv4":
                    try:
                        ipaddress.IPv4Address(candidate)
                    except ipaddress.AddressValueError:
                        continue
                elif ioc_type == "domain":
                    suffix = candidate.rsplit(".", maxsplit=1)[-1].lower()
                    if suffix in _NON_DOMAIN_SUFFIXES:
                        continue

                key = (ioc_type, candidate.casefold())
                if key in found:
                    continue

                found[key] = {
                    "type": ioc_type,
                    "value": candidate,
                    "offset": offset + match.start(),
                    "source_encoding": encoding,
                }

                if len(found) > max_iocs:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break

    iocs = sorted(
        list(found.values())[:max_iocs],
        key=lambda item: (item["offset"], item["type"], item["value"]),
    )

    return {
        "ioc_count": len(iocs),
        "iocs": iocs,
        "truncated": truncated,
        "warnings": [
            "Extracted IOCs are static indicators and are not proof of maliciousness."
        ],
    }

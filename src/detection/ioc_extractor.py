"""Bounded, provenance-preserving IOC extraction from static strings."""

import ipaddress
import re
from urllib.parse import urlsplit

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

_NON_DOMAIN_SUFFIXES = {
    "bin", "cfg", "dll", "doc", "exe", "gif", "ini", "jpg", "json",
    "log", "pdf", "png", "ps1", "py", "sys", "tmp", "txt", "xml",
    "yaml", "yml",
}


class IOCExtractionError(ValueError):
    """Raised when IOC extraction receives invalid input."""


def _trim_url(candidate: str) -> str:
    while candidate and candidate[-1] in ".,;:!?)]}":
        candidate = candidate[:-1]
    return candidate


def _validation_status(ioc_type: str, candidate: str) -> str:
    """Validate candidate syntax only; never perform network requests."""
    try:
        if ioc_type == "ipv4":
            ipaddress.IPv4Address(candidate)
        elif ioc_type == "url":
            parsed = urlsplit(candidate)
            if parsed.scheme.lower() not in {"http", "https", "ftp"}:
                return "invalid_format"
            if not parsed.hostname:
                return "invalid_format"
            # Accessing port detects malformed port values.
            _ = parsed.port
            if any(character.isspace() for character in candidate):
                return "invalid_format"
        elif ioc_type == "email":
            local, separator, domain = candidate.rpartition("@")
            if not separator or not local or not domain or "." not in domain:
                return "invalid_format"
        elif ioc_type == "domain":
            if len(candidate) > 253:
                return "invalid_format"
            labels = candidate.split(".")
            if any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                for label in labels
            ):
                return "invalid_format"
        else:
            return "unsupported_type"
    except (ValueError, ipaddress.AddressValueError):
        return "invalid_format"

    return "valid_format"


def _origin(offset: int, encoding: str) -> dict[str, object]:
    return {
        "source": "string_analysis",
        "offset": offset,
        "encoding": encoding,
    }


def extract_iocs(
    strings: list[dict[str, object]],
    *,
    max_iocs: int = DEFAULT_MAX_IOCS,
) -> dict[str, object]:
    """Extract deduplicated IOC candidates while preserving their origins.

    ``offset`` is the absolute file offset of the first observed occurrence.
    ``normalized_value`` is a case-folded deduplication key, not a guarantee
    of protocol-level canonicalization. Validation is syntax-only.
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
    patterns = (
        ("url", _URL_RE),
        ("email", _EMAIL_RE),
        ("ipv4", _IPV4_RE),
        ("domain", _DOMAIN_RE),
    )

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
            raise IOCExtractionError(
                "String offset must be a non-negative integer"
            )
        if not isinstance(encoding, str) or not isinstance(value, str):
            raise IOCExtractionError(
                "Each string entry must contain string encoding and value fields"
            )

        for ioc_type, pattern in patterns:
            for match in pattern.finditer(value):
                candidate = match.group(0)

                if ioc_type == "url":
                    candidate = _trim_url(candidate)
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

                absolute_offset = offset + match.start()
                observed_origin = _origin(absolute_offset, encoding)
                normalized_value = candidate.casefold()
                key = (ioc_type, normalized_value)

                if key in found:
                    origins = found[key]["origins"]
                    if observed_origin not in origins:
                        origins.append(observed_origin)
                        origins.sort(
                            key=lambda item: (
                                item["offset"],
                                item["encoding"],
                            )
                        )
                    first_origin = origins[0]
                    found[key]["offset"] = first_origin["offset"]
                    found[key]["source_encoding"] = first_origin["encoding"]
                    continue

                found[key] = {
                    "type": ioc_type,
                    "value": candidate,
                    "normalized_value": normalized_value,
                    "offset": absolute_offset,
                    "source_encoding": encoding,
                    "origin": "string_analysis",
                    "origins": [observed_origin],
                    "validation_status": _validation_status(
                        ioc_type, candidate
                    ),
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
            "Extracted IOCs are static candidates, not proof of maliciousness.",
            "Validation checks syntax only; it does not establish reachability, "
            "ownership, reputation, or safety.",
        ],
    }

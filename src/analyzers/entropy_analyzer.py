"""Entropy calculations for static file analysis."""

import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte, between 0 and 8."""
    if not data:
        return 0.0

    length = len(data)
    frequencies = Counter(data)

    return -sum(
        (count / length) * math.log2(count / length) for count in frequencies.values()
    )

"""Tests for static byte entropy calculations."""

import pytest

from src.analyzers.entropy_analyzer import calculate_entropy


def test_empty_data_has_zero_entropy():
    assert calculate_entropy(b"") == 0.0


def test_repeated_byte_has_zero_entropy():
    assert calculate_entropy(b"A" * 128) == 0.0


def test_two_equally_frequent_bytes_have_one_bit_entropy():
    assert calculate_entropy(b"AB" * 64) == pytest.approx(1.0)


def test_all_byte_values_have_eight_bits_entropy():
    assert calculate_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_entropy_is_between_zero_and_eight():
    result = calculate_entropy(b"AAABBCDE")
    assert 0.0 <= result <= 8.0

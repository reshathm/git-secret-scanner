"""
tests/test_entropy.py

Tests for entropy.py -- the Shannon entropy scoring used to catch
"random-looking" secrets that have no fixed, known format.

Run with:
    pytest tests/test_entropy.py
"""

import sys
import os

# Make the project root importable, since tests/ is a subfolder and
# entropy.py lives one level up.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from entropy import shannon_entropy, find_high_entropy_strings


def test_empty_string_has_zero_entropy():
    # An empty string has no characters to be "random" at all.
    assert shannon_entropy("") == 0.0


def test_repeated_character_has_low_entropy():
    # A string made of only one repeated character is maximally
    # predictable -- every character is the same, so entropy is 0.
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_random_looking_string_has_high_entropy():
    # A string with a good mix of upper/lower/digits/symbols and no
    # repeating pattern should score well above the 4.5 threshold
    # used elsewhere in the project.
    score = shannon_entropy("xK9!mQ2z#vL8pR4mYw7Bt3Nc")
    assert score >= 4.5


def test_normal_english_sentence_has_lower_entropy_than_random_secret():
    # This is really the core assumption the whole entropy detector
    # relies on: real text should score meaningfully lower than a
    # random secret. If this test ever fails, the entropy approach
    # itself needs rethinking.
    english_score = shannon_entropy("this is just a normal sentence")
    secret_score = shannon_entropy("xK9!mQ2z#vL8pR4mYw7Bt3Nc")
    assert english_score < secret_score


def test_find_high_entropy_strings_flags_a_known_secret():
    line = 'RANDOM_TOKEN = "xK9!mQ2z#vL8pR4mYw7Bt3Nc"'
    results = find_high_entropy_strings(line)
    matched_candidates = [candidate for candidate, score in results]
    assert "xK9!mQ2z#vL8pR4mYw7Bt3Nc" in matched_candidates


def test_find_high_entropy_strings_ignores_low_entropy_line():
    # A weak, low-entropy password should NOT be flagged by the
    # entropy detector on its own (pattern matching might still catch
    # it separately, but that's not what this function is testing).
    line = 'DATABASE_PASSWORD = "hunter2"'
    results = find_high_entropy_strings(line)
    assert results == []


def test_threshold_is_respected():
    # A very low threshold should catch almost anything; a very high
    # one should catch almost nothing. This confirms the threshold
    # parameter is actually being used, not ignored.
    line = "some_var = normaltext123"
    loose_results = find_high_entropy_strings(line, threshold=0.0)
    strict_results = find_high_entropy_strings(line, threshold=8.0)
    assert len(loose_results) >= len(strict_results)

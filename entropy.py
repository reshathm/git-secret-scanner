"""
entropy.py

Detects "random-looking" strings using Shannon entropy — a measure of
how unpredictable a sequence of characters is.

Intuition:
- The word "password123" is low entropy — it's mostly predictable
  English letters plus a common number pattern.
- The string "aK9!xQ2z#vL8pR4m" is high entropy — every character
  looks unpredictable, no obvious pattern. This is what a randomly
  generated secret looks like.

We use this to catch secrets that don't match a known company format
(patterns.py only catches KNOWN formats like AWS/Stripe/GitHub).
"""

import math
import re

# Only consider "word-like" chunks — sequences of letters/digits/symbols
# with no spaces, since real secrets don't contain spaces.
CANDIDATE_PATTERN = re.compile(r"[A-Za-z0-9+/=_\-!@#$%^&*]{20,}")


def shannon_entropy(text: str) -> float:
    """
    Calculates Shannon entropy in bits per character.
    Higher = more randomness. Typical English text scores ~3.5-4.5.
    Random secrets typically score 4.5+.
    """
    if not text:
        return 0.0

    # Count how often each character appears
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def find_high_entropy_strings(line: str, threshold: float = 4.5):
    """
    Scans a line of text for substrings that look random enough
    to be a secret. Returns a list of (matched_string, entropy_score).
    """
    findings = []
    for match in CANDIDATE_PATTERN.finditer(line):
        candidate = match.group()
        score = shannon_entropy(candidate)
        if score >= threshold:
            findings.append((candidate, score))
    return findings

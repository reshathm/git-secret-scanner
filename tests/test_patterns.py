"""
tests/test_patterns.py

Tests for patterns.py -- the regex patterns that catch secrets with
a known, documented format (AWS keys, Stripe keys, GitHub tokens,
etc).

For each pattern we test two things:
  1. It DOES match a realistic fake example of that secret type.
  2. It does NOT match obviously unrelated, normal text (a basic
     false-positive check).

Run with:
    pytest tests/test_patterns.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patterns import SECRET_PATTERNS


def test_aws_access_key_matches_valid_format():
    pattern, _ = SECRET_PATTERNS["AWS Access Key ID"]
    assert pattern.search("AKIAIOSFODNN7EXAMPLE") is not None


def test_aws_access_key_does_not_match_normal_text():
    pattern, _ = SECRET_PATTERNS["AWS Access Key ID"]
    assert pattern.search("this is just a normal sentence") is None


def test_stripe_key_matches_valid_format():
    pattern, _ = SECRET_PATTERNS["Stripe Live Secret Key"]
    assert pattern.search("sk_live_FAKEKEYFAKEKEYFAKEKEYFAKE") is not None


def test_stripe_key_does_not_match_test_key_prefix():
    # Stripe TEST keys use a different prefix (sk_test_) and are not
    # sensitive in the same way -- the pattern should be specific to
    # sk_live_, not just any sk_ prefix.
    pattern, _ = SECRET_PATTERNS["Stripe Live Secret Key"]
    assert pattern.search("sk_test_FAKEKEYFAKEKEYFAKEKEYFAKE") is None


def test_github_pat_matches_valid_format():
    pattern, _ = SECRET_PATTERNS["GitHub Personal Access Token"]
    fake_token = "ghp_" + "a" * 36
    assert pattern.search(fake_token) is not None


def test_private_key_header_matches():
    pattern, _ = SECRET_PATTERNS["Generic Private Key Header"]
    assert pattern.search("-----BEGIN RSA PRIVATE KEY-----") is not None


def test_private_key_header_does_not_match_public_key():
    # A public key header should NOT trigger this pattern -- public
    # keys aren't secrets, so flagging them would be a false positive.
    pattern, _ = SECRET_PATTERNS["Generic Private Key Header"]
    assert pattern.search("-----BEGIN PUBLIC KEY-----") is None


def test_slack_token_matches_valid_format():
    pattern, _ = SECRET_PATTERNS["Slack Token"]
    assert pattern.search("xoxb-1234567890-abcdefg") is not None


def test_generic_api_key_assignment_matches_common_style():
    pattern, _ = SECRET_PATTERNS["Generic API Key Assignment"]
    line = 'API_KEY = "abcd1234EFGH5678ijkl"'
    assert pattern.search(line) is not None


def test_generic_api_key_assignment_ignores_short_values():
    # Short values (under the 16-character minimum) shouldn't trigger
    # this pattern -- they're too short to plausibly be a real key,
    # and flagging them would create noisy false positives.
    pattern, _ = SECRET_PATTERNS["Generic API Key Assignment"]
    line = 'api_key = "short"'
    assert pattern.search(line) is None

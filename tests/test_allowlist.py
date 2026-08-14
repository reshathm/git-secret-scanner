"""
tests/test_allowlist.py

Tests for allowlist.py -- parsing a .secretscanignore file and using
it to filter out findings that have already been reviewed and marked
safe (test fixtures, documentation, etc).

Run with:
    pytest tests/test_allowlist.py
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from allowlist import load_ignore_rules, is_file_ignored, is_string_ignored


def write_ignore_file(tmp_dir: str, contents: str):
    """Helper: writes a .secretscanignore file into a temp folder."""
    path = os.path.join(tmp_dir, ".secretscanignore")
    with open(path, "w", encoding="utf-8") as f:
        f.write(contents)
    return tmp_dir


def test_load_ignore_rules_returns_empty_when_no_file_exists():
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_patterns, ignored_strings = load_ignore_rules(tmp_dir)
        assert file_patterns == []
        assert ignored_strings == set()


def test_load_ignore_rules_parses_file_and_string_rules():
    contents = "\n".join([
        "# a comment, should be skipped",
        "file:README.md",
        "file:test_samples/*",
        "string:some-exact-secret-value",
        "",  # blank line, should be skipped
    ])
    with tempfile.TemporaryDirectory() as tmp_dir:
        write_ignore_file(tmp_dir, contents)
        file_patterns, ignored_strings = load_ignore_rules(tmp_dir)

        assert "README.md" in file_patterns
        assert "test_samples/*" in file_patterns
        assert "some-exact-secret-value" in ignored_strings


def test_load_ignore_rules_ignores_malformed_lines_without_crashing():
    # A line that doesn't start with "file:" or "string:" shouldn't
    # crash the whole scan -- it should just be silently skipped, so
    # a typo in the ignore file doesn't take down the tool.
    contents = "this line is not a valid rule\nfile:README.md"
    with tempfile.TemporaryDirectory() as tmp_dir:
        write_ignore_file(tmp_dir, contents)
        file_patterns, ignored_strings = load_ignore_rules(tmp_dir)
        assert file_patterns == ["README.md"]


def test_is_file_ignored_matches_exact_filename():
    assert is_file_ignored("README.md", ["README.md"]) is True


def test_is_file_ignored_matches_wildcard_pattern():
    assert is_file_ignored("test_samples/config.py", ["test_samples/*"]) is True


def test_is_file_ignored_does_not_match_unrelated_file():
    assert is_file_ignored("scanner.py", ["README.md", "test_samples/*"]) is False


def test_is_string_ignored_matches_exact_value_only():
    ignored = {"exact-secret-value"}
    assert is_string_ignored("exact-secret-value", ignored) is True
    # A partial match should NOT count -- allowlisting one specific
    # reviewed value should never accidentally allowlist a different
    # (even similar-looking) real secret.
    assert is_string_ignored("exact-secret-value-but-longer", ignored) is False


def test_allowlist_regression_ignore_file_documentation_does_not_self_match():
    # Regression test for a real bug we hit: allowlist.py's own
    # docstring used to contain a literal high-entropy example
    # string, which caused the scanner to flag its own ignore-file
    # documentation as a leaked secret. The fix was to replace the
    # example with a non-random placeholder. This test locks that
    # fix in so it can't quietly regress.
    allowlist_path = os.path.join(os.path.dirname(__file__), "..", "allowlist.py")
    with open(allowlist_path, "r", encoding="utf-8") as f:
        contents = f.read()
    assert "xK9!mQ2z#vL8pR4mYw7Bt3Nc" not in contents

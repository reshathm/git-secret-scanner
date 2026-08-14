"""
allowlist.py

Loads and applies ignore rules from a .secretscanignore file, so the
scanner can skip things you've already reviewed and decided are safe
(test fixtures, documentation examples, etc).

.secretscanignore format (one rule per line):

    # Comments start with a hash and are ignored
    file:README.md              -> skip this exact file entirely
    file:test_samples/*         -> skip every file in this folder
    string:PASTE_THE_EXACT_MATCHED_VALUE_HERE   -> skip this one exact matched string, everywhere

Blank lines are ignored. Rules are matched case-sensitively.
"""

import os
import fnmatch


def load_ignore_rules(repo_path: str):
    """
    Reads .secretscanignore from the root of repo_path, if it exists,
    and returns two things:
        - a list of file patterns to skip (e.g. "README.md", "test_samples/*")
        - a set of exact matched strings to skip, everywhere

    If no .secretscanignore file exists, returns empty rules (nothing
    is ignored) -- this keeps the tool working exactly as before for
    anyone who hasn't set one up.
    """
    ignore_path = os.path.join(repo_path, ".secretscanignore")
    file_patterns = []
    ignored_strings = set()

    if not os.path.isfile(ignore_path):
        return file_patterns, ignored_strings

    with open(ignore_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("file:"):
                file_patterns.append(line[len("file:"):].strip())
            elif line.startswith("string:"):
                ignored_strings.add(line[len("string:"):].strip())
            # Unrecognized lines are silently skipped rather than
            # crashing the scan -- a typo in the ignore file shouldn't
            # take down the whole tool.

    return file_patterns, ignored_strings


def is_file_ignored(filepath: str, file_patterns: list) -> bool:
    """
    Checks whether filepath matches any of the ignore file patterns.

    Uses fnmatch, the same wildcard-matching style as .gitignore
    (e.g. "*.log" matches any file ending in .log, "test_samples/*"
    matches anything directly inside test_samples/).

    filepath should be a path relative to the repo root, using
    forward slashes, so patterns behave consistently regardless of OS.
    """
    normalized = filepath.replace(os.sep, "/")
    for pattern in file_patterns:
        if fnmatch.fnmatch(normalized, pattern):
            return True
    return False


def is_string_ignored(matched_text: str, ignored_strings: set) -> bool:
    """
    Checks whether this exact matched string has been allowlisted.
    """
    return matched_text in ignored_strings

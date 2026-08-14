# git-secret-scanner

A command-line tool that scans a codebase — including its full git commit history — for accidentally committed secrets: API keys, tokens, passwords, private keys. It combines **known-format pattern matching** with **Shannon entropy analysis** to catch both well-known secret formats and generic random-looking credentials with no fixed shape.

Built as a hands-on project to understand how real secret-scanning tools (GitHub's push protection, TruffleHog, Gitleaks) actually detect leaked credentials, and how they fit into real developer workflows.

---

## Why two detection strategies?

Secrets generally fall into one of two categories:

1. **Known-format secrets.** Many providers issue keys with a fixed, documented shape — an AWS access key ID always starts with `AKIA` followed by 16 characters, a GitHub token always starts with `ghp_`. These are easy and reliable to catch with regular expressions.

2. **Unknown-format secrets.** A huge number of real secrets (custom API keys, internal tokens, database passwords) have no fixed format at all. Regex can't catch what it doesn't have a pattern for. To catch these, the scanner measures the **Shannon entropy** of candidate strings — a measure of how "random" a string looks. Random secrets score high; predictable text and passwords score low. Anything at or above **4.5 bits/character** is flagged.

Combining both catches well-known formats *and* generic high-randomness strings a pure regex tool would miss.

---

## Why scan git history, not just current files?

If a secret is committed and later deleted in a following commit, it doesn't actually disappear — it's still recoverable from git's history by anyone who clones the repo, using `git show` or `git log -p`. A scanner that only checks files as they exist *today* would miss this entirely, and it's arguably the more realistic threat: developers do accidentally commit and then "fix" a leak by deleting it, not realizing the leak persists in history.

`history_scanner.py` walks every commit, extracts the lines added in each one, and runs the same detectors against them — reporting the commit hash, date, and message alongside each finding, so you know exactly when a secret entered the repo.

---

## Features

- **Two detection strategies**: known-format pattern matching + entropy analysis
- **Current-file scanning** (`scanner.py`) and **full commit-history scanning** (`history_scanner.py`)
- **Allowlist system** (`.secretscanignore`) to suppress reviewed false positives — by file or by exact matched value
- **Masked output** — the tool never prints a full secret, even one it just found, only the first/last 4 characters
- **CI-friendly exit codes** — exits `1` if secrets are found, `0` if clean, so the scanner can be wired into a pre-commit hook or CI pipeline to actually fail a build
- **Colored terminal output** with a summary line, auto-disabled when output isn't going to a real terminal
- **Unit tests** covering entropy scoring, pattern matching, and allowlist logic

---

## How it works

```
scanner.py             → scans current files on disk
history_scanner.py     → scans full git commit history
patterns.py            → regex definitions for known secret formats
entropy.py             → Shannon entropy scoring
allowlist.py            → parses .secretscanignore and filters findings
cli_output.py           → shared color output, summary line, exit codes
tests/                  → unit tests for the above
test_samples/config.py  → fake secrets used to verify detection works
```

`scanner.py` walks a target directory line by line, skipping noisy directories (`.git`, `node_modules`, `__pycache__`, virtual environments) and binary files. `history_scanner.py` instead walks every commit via `git log` and `git show`, checking only the lines that were *added* in each commit. Both run the same detection logic and respect the same allowlist rules.

---

## Usage

Scan current files:

```bash
python3 scanner.py <path_to_scan>
```

Scan full commit history:

```bash
python3 history_scanner.py <path_to_git_repo>
```

Example:

```bash
$ python3 scanner.py test_samples/

4 pattern match(es), 1 entropy match(es) -- 5 total secret(s)

[PATTERN] AWS Access Key ID
  File: test_samples/config.py:4
  Match: AKIA...MPLE
  Detail: Starts with AKIA followed by 16 uppercase letters/digits

[PATTERN] Stripe Live Secret Key
  File: test_samples/config.py:6
  Match: sk_l...FAKE
  Detail: Stripe live secret key

[ENTROPY] High-entropy string
  File: test_samples/config.py:7
  Match: xK9!...t3Nc
  Detail: Shannon entropy score: 4.50
```

Exit code is `1` here since secrets were found — a CI pipeline running this command would fail the build. A clean scan prints "No secrets detected." and exits `0`.

Note that `DATABASE_PASSWORD = "hunter2"` in the test fixtures is **intentionally not flagged** — it's low-entropy and matches no known format, which is correct behavior for a weak/predictable string.

---

## Reducing false positives with an allowlist

Not everything that looks random is a secret — documentation, image URLs, and example output can score high on entropy without being sensitive at all. `.secretscanignore` lets you suppress findings you've reviewed and confirmed are safe:

```
# file:<pattern>   -> skip an entire file (supports wildcards)
# string:<exact>   -> skip one exact matched value, everywhere

file:README.md
file:test_samples/*
string:some-exact-reviewed-value
```

This mirrors how real secret-scanning tools handle the same problem — see [Design decisions](#design-decisions) below for a concrete example of a false positive this caught in practice.

---

## Design decisions

- **Masked output by default.** The scanner never prints a full secret, even one it just found — only the first and last 4 characters. This avoids the tool itself becoming a source of leaked credentials, e.g. in CI logs.
- **Entropy threshold of 4.5 bits/char.** Typical English text scores roughly 3.5–4.5; random secrets typically score 4.5 and above.
- **Combining regex and entropy, not just one.** Pattern matching alone misses custom/internal secret formats. Entropy alone produces too many false positives on hashes, UUIDs, and encoded non-secret data. Using both, with entropy as a fallback, balances precision and recall.
- **Exit codes matter as much as output.** A scanner that only prints findings is a manual tool. One that exits non-zero on findings can be wired into automation — that distinction is most of what separates a script from a usable piece of tooling.
- **subprocess over a git library for history scanning.** `history_scanner.py` calls real `git` commands directly rather than using a wrapper library like GitPython. This keeps the project dependency-free and made the mechanics of git history genuinely easier to understand while building it.

---

## Bugs found and fixed along the way

**Symbol-excluding regex silently missed real secrets.** Early character classes in the entropy candidate pattern and the generic API key pattern only matched `[A-Za-z0-9+/=_-]`, excluding common symbols like `!@#$%^&*`. A test secret containing symbols (`xK9!mQ2z#vL8pR4mYw7Bt3Nc`) was silently missed — the regex engine split it into smaller pieces at each symbol, each too short to trigger detection. Fixed by widening both character classes.

**The allowlist's own documentation flagged itself as a leak.** After adding `.secretscanignore` support, `allowlist.py`'s docstring included a real example secret string as sample usage text. The entropy detector — correctly — flagged that string inside `allowlist.py` itself, since it genuinely is high-entropy. Fixed by replacing the example with a non-random placeholder, and added a regression test (`test_allowlist_regression_ignore_file_documentation_does_not_self_match`) so this specific class of bug can't silently come back.

Both are good examples of the gap between "the code runs" and "the code is correct" — real bugs only surfaced once the tool was tested against realistic, messy input rather than a clean happy-path example.

---

## Testing

```bash
python3 -m pip install --user pytest
python3 -m pytest tests/ -v
```

Tests cover: entropy scoring behavior (including the assumption that real text scores lower than random secrets), every regex pattern's true-positive and false-positive behavior, and the allowlist's file/string matching logic — including the regression test above.

---

## What I'd add next

- **Broader secret coverage** — more provider-specific formats (Azure, GCP, database connection strings)
- **Pre-commit hook integration** — a ready-to-drop `.git/hooks/pre-commit` script using the existing exit codes
- **Configurable entropy threshold** via a CLI flag, rather than a hardcoded constant
- **Parallel scanning** for large repos, since commit history scanning currently runs `git show` sequentially per commit

---

## Requirements

- Python 3.8+
- No external dependencies for the scanners themselves (standard library only); `pytest` is required only to run the test suite

---

## Disclaimer

This is a learning project, not a production-grade security tool. For real-world secret scanning, consider established tools like [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), or GitHub's built-in secret scanning.

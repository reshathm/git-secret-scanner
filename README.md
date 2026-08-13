# git-secret-scanner

A command-line tool that scans a codebase for accidentally committed secrets — API keys, tokens, passwords, private keys — using two complementary detection strategies: **known-format pattern matching** and **Shannon entropy analysis**.

Built as a portfolio project to explore how real secret-scanning tools (like GitHub's own push protection, TruffleHog, and Gitleaks) actually detect leaked credentials.

> **Status:** Week 1 complete — core detector working on local files. Git commit history scanning is in progress (see [Roadmap](#roadmap)).

---

## Why two detection strategies?

Most secrets fall into one of two categories, so the scanner uses a matching strategy for each:

1. **Known-format secrets** — many providers issue keys with a fixed, documented shape. An AWS access key ID always starts with `AKIA` followed by 16 characters. A GitHub personal access token always starts with `ghp_`. These are easy and reliable to catch with regular expressions.

2. **Unknown-format secrets** — a huge number of secrets (custom API keys, internal tokens, database passwords) have no fixed format at all. Regex can't catch what it doesn't have a pattern for. To catch these, the scanner measures the **Shannon entropy** of candidate strings — a measure of how "random" a string looks. Random secrets score high in entropy; normal English text and predictable strings (like `password123`) score low. Anything at or above **4.5 bits/character** is flagged as a candidate.

Combining both means the tool catches well-known secret formats *and* generic high-randomness strings that a pure regex tool would miss.

---

## How it works

```
scanner.py          → walks the target directory, runs both detectors on every text file
patterns.py          → regex definitions for known secret formats (AWS, Stripe, GitHub, Slack, private keys, generic key assignments)
entropy.py            → Shannon entropy scoring for high-randomness strings
test_samples/config.py → sample file with fake secrets, used to verify detection works
```

The scanner walks the target directory line by line, skipping noisy directories (`.git`, `node_modules`, `__pycache__`, virtual environments) and binary files (images, PDFs, zips, executables). Every line is checked against both detectors, and any matches are reported with the file, line number, detection method, and a **masked** version of the secret (first/last 4 characters only) — the tool never prints full secrets to the terminal, which mirrors how real security tools are expected to behave.

---

## Usage

```bash
python scanner.py <path_to_scan>
```

Example, scanning the included test fixtures:

```bash
python scanner.py test_samples/
```

Example output:

```
Found 4 potential secret(s):

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
  Match: xK9!...3Nc
  Detail: Shannon entropy score: 4.73

...
```

Note that `DATABASE_PASSWORD = "hunter2"` in the test fixtures is **intentionally not flagged** — it's low-entropy and doesn't match any known secret format, which is the expected (and correct) behavior for a weak/predictable string.

---

## Design decisions

- **Masked output by default.** The scanner never prints a full secret, even one it just found — only the first and last 4 characters. This avoids the tool itself becoming a source of leaked credentials (e.g., in CI logs).
- **Entropy threshold of 4.5 bits/char.** Typical English text scores roughly 3.5–4.5; random secrets typically score 4.5 and above. This threshold was chosen to catch random-looking strings while keeping false positives from ordinary text low.
- **Combining regex and entropy, not just one.** Pattern matching alone misses custom/internal secret formats. Entropy alone produces too many false positives on things like hashes, UUIDs, or base64-encoded non-secret data. Using both together, with entropy as a fallback, balances precision and recall.

---

## A bug I found and fixed

Early versions of the entropy candidate pattern and the generic API key pattern only matched `[A-Za-z0-9+/=_-]`, which excluded common symbols like `!`, `@`, `#`, `$`, `%`, `^`, `&`, `*`. A test secret containing symbols (`xK9!mQ2z#vL8pR4mYw7Bt3Nc`) was silently missed — the regex engine split it into smaller pieces at each symbol, and each piece was too short to trigger detection.

Fixed by widening both character classes to include those symbols. This was a good reminder that testing against realistic secret formats (not just alphanumeric examples) is essential — a scanner that misses secrets because of what its own regex excludes is worse than one that's slightly noisy.

---

## Roadmap

- [x] **Week 1** — Core detector: pattern matching + entropy analysis on local files
- [ ] **Week 2** — Scan git commit history (not just current files), so secrets that were committed and later deleted are still caught, with commit hash and date reported
- [ ] **Week 3** — Allowlist/ignore system to reduce false positives on test fixtures and known-safe strings; CLI output polish
- [ ] **Week 4** — Unit tests, expanded documentation, write-up of lessons learned and future improvements

---

## Requirements

- Python 3.8+
- No external dependencies for the current version (standard library only)

---

## Disclaimer

This is a learning/portfolio project, not a production-grade security tool. For real-world secret scanning, consider established tools like [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), or GitHub's built-in secret scanning.

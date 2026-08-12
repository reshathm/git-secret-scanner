"""
patterns.py

Known formats for common secrets. Each entry is:
    name: (regex_pattern, description)

These are "signature-based" detections — we know exactly what these
secrets look like because the companies that issue them use a fixed,
documented format. This is why it's so effective: false positives are
rare because the format is very specific.
"""

import re

SECRET_PATTERNS = {
    "AWS Access Key ID": (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Starts with AKIA followed by 16 uppercase letters/digits"
    ),
    "AWS Secret Access Key": (
        re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
        "40-character base64-like string, often near the word 'aws'"
    ),
    "Stripe Live Secret Key": (
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe live secret key"
    ),
    "GitHub Personal Access Token": (
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        "GitHub personal access token (classic)"
    ),
    "Generic Private Key Header": (
        re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
        "Start of a private key file (PEM format)"
    ),
    "Slack Token": (
        re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
        "Slack API token"
    ),
    "Generic API Key Assignment": (
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][0-9a-zA-Z\-_/+=!@#$%^&*]{16,}['\"]"),
        "A variable assignment that looks like a key/secret/password/token"
    ),
}

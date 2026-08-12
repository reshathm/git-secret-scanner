"""
scanner.py

Main entry point. Walks through files in a directory, and for each
line of text, runs both detection strategies:
  1. Known secret format matching (patterns.py)
  2. High-entropy string detection (entropy.py)

Usage:
    python scanner.py <path_to_scan>
"""

import sys
import os
from patterns import SECRET_PATTERNS
from entropy import find_high_entropy_strings

# Skip files/folders that are noisy or irrelevant to scan
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe"}


def scan_line(line: str, line_number: int, filepath: str):
    """Runs both detectors on a single line and returns a list of findings."""
    findings = []

    # --- Strategy 1: known formats ---
    for secret_name, (pattern, description) in SECRET_PATTERNS.items():
        match = pattern.search(line)
        if match:
            findings.append({
                "file": filepath,
                "line": line_number,
                "type": secret_name,
                "matched_text": match.group(),
                "detection_method": "pattern",
                "detail": description,
            })

    # --- Strategy 2: high entropy strings ---
    for candidate, score in find_high_entropy_strings(line):
        findings.append({
            "file": filepath,
            "line": line_number,
            "type": "High-entropy string",
            "matched_text": candidate,
            "detection_method": "entropy",
            "detail": f"Shannon entropy score: {score:.2f}",
        })

    return findings


def scan_file(filepath: str):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                findings.extend(scan_line(line, line_number, filepath))
    except (OSError, UnicodeDecodeError):
        pass  # skip unreadable/binary files
    return findings


def scan_directory(root_path: str):
    all_findings = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Modify dirnames in-place to skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for filename in filenames:
            if any(filename.endswith(ext) for ext in IGNORE_EXTENSIONS):
                continue
            filepath = os.path.join(dirpath, filename)
            all_findings.extend(scan_file(filepath))
    return all_findings


def print_findings(findings):
    if not findings:
        print("No secrets detected.")
        return

    print(f"\nFound {len(findings)} potential secret(s):\n")
    for f in findings:
        # Mask the matched text so we don't print real secrets in full
        masked = f["matched_text"][:4] + "..." + f["matched_text"][-4:] \
            if len(f["matched_text"]) > 10 else "****"
        print(f"[{f['detection_method'].upper()}] {f['type']}")
        print(f"  File: {f['file']}:{f['line']}")
        print(f"  Match: {masked}")
        print(f"  Detail: {f['detail']}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <path_to_scan>")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"Error: path '{target}' does not exist.")
        sys.exit(1)

    results = scan_directory(target)
    print_findings(results)

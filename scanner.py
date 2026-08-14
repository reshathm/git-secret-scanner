"""
scanner.py

Main entry point. Walks through files in a directory, and for each
line of text, runs both detection strategies.

Usage:
    python scanner.py <path_to_scan>
"""

import sys
import os
from patterns import SECRET_PATTERNS
from entropy import find_high_entropy_strings
from allowlist import load_ignore_rules, is_file_ignored, is_string_ignored

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe"}


def scan_line(line: str, line_number: int, filepath: str):
    findings = []
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
        pass
    return findings


def scan_directory(root_path: str):
    all_findings = []
    file_patterns, ignored_strings = load_ignore_rules(root_path)

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for filename in filenames:
            if any(filename.endswith(ext) for ext in IGNORE_EXTENSIONS):
                continue

            filepath = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(filepath, root_path)

            if is_file_ignored(relative_path, file_patterns):
                continue

            for finding in scan_file(filepath):
                if is_string_ignored(finding["matched_text"], ignored_strings):
                    continue
                all_findings.append(finding)

    return all_findings


def print_findings(findings):
    if not findings:
        print("No secrets detected.")
        return
    print(f"\nFound {len(findings)} potential secret(s):\n")
    for f in findings:
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

"""
history_scanner.py

Scans a git repo's *commit history* for secrets, not just the current
files on disk. This catches secrets that were committed and later
deleted -- they still exist in git history and can be recovered with
`git show <commit>` by anyone who clones the repo.

Usage:
    python history_scanner.py <path_to_git_repo>
"""

import sys
import os
import subprocess

from patterns import SECRET_PATTERNS
from entropy import find_high_entropy_strings


def run_git(repo_path: str, args: list[str]) -> str:
    """
    Runs a git command inside repo_path and returns its text output.

    This is the core trick of the whole file: instead of using a git
    library, we just call the real `git` command exactly like you
    would on the terminal, and capture what it prints.
    """
    result = subprocess.run(
        ["git", "-C", repo_path] + args,
        capture_output=True,
        text=True,
    )
    return result.stdout


def get_commit_list(repo_path: str):
    """
    Returns a list of (commit_hash, date, message) for every commit
    in the repo, oldest first.

    Under the hood this runs:
        git log --reverse --format=%H|%ad|%s --date=short
    which prints one line per commit, in the exact fields we asked for,
    separated by '|' so we can split them apart easily.
    """
    output = run_git(
        repo_path,
        ["log", "--reverse", "--format=%H|%ad|%s", "--date=short"],
    )
    commits = []
    for line in output.splitlines():
        if not line.strip():
            continue
        commit_hash, date, message = line.split("|", 2)
        commits.append((commit_hash, date, message))
    return commits


def get_added_lines(repo_path: str, commit_hash: str):
    """
    Returns a list of (filename, added_line_text) for every line that
    was ADDED in this commit (not removed, not context lines).

    Under the hood this runs:
        git show <commit_hash>
    which prints a diff. In a diff:
        lines starting with '+++' or '---'  -> file headers, skip
        lines starting with '+'             -> a line that was added
        lines starting with '-'             -> a line that was removed
        everything else                     -> unchanged context, skip

    We only care about ADDED lines, because that's when a secret
    actually entered the repo's history.
    """
    output = run_git(repo_path, ["show", commit_hash])

    added_lines = []
    current_file = None

    for line in output.splitlines():
        # A line like "+++ b/secret.txt" tells us which file the
        # following +/- lines belong to.
        if line.startswith("+++ "):
            path = line[4:]
            if path.startswith("b/"):
                path = path[2:]
            current_file = path
            continue

        # Skip diff metadata lines that happen to start with '+' or '-'
        # but aren't actual content changes.
        if line.startswith("+++") or line.startswith("---"):
            continue

        # A real added line starts with a single '+'.
        if line.startswith("+") and current_file:
            added_lines.append((current_file, line[1:]))

    return added_lines


def scan_line_for_secrets(line: str):
    """
    Reuses the exact same detection logic as scanner.py, so history
    scanning and current-file scanning stay consistent.
    """
    findings = []
    for secret_name, (pattern, description) in SECRET_PATTERNS.items():
        match = pattern.search(line)
        if match:
            findings.append({
                "type": secret_name,
                "matched_text": match.group(),
                "detection_method": "pattern",
                "detail": description,
            })
    for candidate, score in find_high_entropy_strings(line):
        findings.append({
            "type": "High-entropy string",
            "matched_text": candidate,
            "detection_method": "entropy",
            "detail": f"Shannon entropy score: {score:.2f}",
        })
    return findings


def scan_repo_history(repo_path: str):
    """
    Walks every commit in the repo, checks every added line for
    secrets, and returns a flat list of findings with commit context
    attached.
    """
    all_findings = []
    commits = get_commit_list(repo_path)

    for commit_hash, date, message in commits:
        added_lines = get_added_lines(repo_path, commit_hash)
        for filename, line_text in added_lines:
            for finding in scan_line_for_secrets(line_text):
                finding["commit"] = commit_hash[:8]  # short hash, easier to read
                finding["date"] = date
                finding["message"] = message
                finding["file"] = filename
                all_findings.append(finding)

    return all_findings


def print_findings(findings):
    if not findings:
        print("No secrets found in commit history.")
        return

    print(f"\nFound {len(findings)} potential secret(s) in commit history:\n")
    for f in findings:
        matched = f["matched_text"]
        masked = matched[:4] + "..." + matched[-4:] if len(matched) > 10 else "****"
        print(f"[{f['detection_method'].upper()}] {f['type']}")
        print(f"  Commit: {f['commit']}  ({f['date']})  \"{f['message']}\"")
        print(f"  File: {f['file']}")
        print(f"  Match: {masked}")
        print(f"  Detail: {f['detail']}\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python history_scanner.py <path_to_git_repo>")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isdir(os.path.join(target, ".git")):
        print(f"Error: '{target}' does not look like a git repository (no .git folder found).")
        sys.exit(1)

    findings = scan_repo_history(target)
    print_findings(findings)

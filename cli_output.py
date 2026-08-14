"""
cli_output.py

Shared terminal output helpers: color codes and a summary line, used
by both scanner.py and history_scanner.py so their output looks and
behaves consistently.

Colors work by printing special "ANSI escape codes" before and after
text -- invisible characters that tell the terminal "start coloring
here" / "stop coloring here". No external library needed, every
modern terminal (including WSL) understands them.
"""

import sys

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _supports_color() -> bool:
    """
    Some environments (like output piped into a file, or certain CI
    systems) don't render color codes -- they'd just show up as ugly
    raw characters. This checks whether we're printing to a real
    terminal before using color at all.
    """
    return sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    if not _supports_color():
        return text
    return f"{color}{text}{RESET}"


def print_summary(findings, context_label: str = "secret(s)"):
    """
    Prints a short headline before the detailed findings list, e.g.:
        "3 pattern match(es), 2 entropy match(es) -- 5 total"

    context_label lets scanner.py and history_scanner.py phrase the
    headline slightly differently if needed, while sharing the same
    counting logic.
    """
    if not findings:
        print(colorize("No secrets detected.", GREEN))
        return

    pattern_count = sum(1 for f in findings if f["detection_method"] == "pattern")
    entropy_count = sum(1 for f in findings if f["detection_method"] == "entropy")

    headline = (
        f"{pattern_count} pattern match(es), {entropy_count} entropy match(es) "
        f"-- {len(findings)} total {context_label}"
    )
    print(colorize(f"\n{headline}\n", f"{BOLD}{RED}"))


def exit_code_for(findings) -> int:
    """
    Returns the exit code the script should use: 1 if anything was
    found (so CI pipelines and pre-commit hooks can detect failure),
    0 if the scan came back clean.
    """
    return 1 if findings else 0

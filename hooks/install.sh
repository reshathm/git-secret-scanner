#!/usr/bin/env bash
# Run this once after cloning the repo to activate the pre-commit hook.
# (git only ever runs hooks from .git/hooks, which is never tracked by git
# itself -- that's why this repo keeps the real script in hooks/ and copies
# it into place here instead.)

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cp "$REPO_ROOT/hooks/pre-commit" "$REPO_ROOT/.git/hooks/pre-commit"
chmod +x "$REPO_ROOT/.git/hooks/pre-commit"

echo "Pre-commit hook installed. It will now run automatically on every 'git commit'."

#!/usr/bin/env bash
# Installs the connectMWP git hooks (version SSOT drift gate) into .git/hooks.
# Run once per clone:  bash scripts/install-hooks.sh
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SRC="$ROOT/scripts/hooks/pre-commit"
DST="$ROOT/.git/hooks/pre-commit"
cp "$SRC" "$DST"
chmod +x "$DST"
echo "Installed pre-commit hook -> $DST"
echo "It runs: node scripts/sync-version.mjs --check (blocks commits on version drift)."

#!/usr/bin/env bash
# Runs the MCPB verifier and packaging tests on Linux or Windows Git Bash.

set -euo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# Finds the Python 3 interpreter provided by the current CI host.
resolve_python() {
  local candidate

  for candidate in "${PYTHON:-}" python3 python; do
    if [[ -n "$candidate" ]] && command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

PYTHON_BIN="$(resolve_python)" || {
  printf 'Python 3.9 or newer is required\n' >&2
  exit 1
}

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -m unittest discover \
  -s "$TEST_DIR" -p 'test_*.py'
PYTHON="$PYTHON_BIN" bash "$TEST_DIR/package-windows.test.sh"

#!/usr/bin/env bash
# verify-no-leaks.sh -- Pre-push leak scan for the public custom-agents repo.
# Scans all git-tracked files for known sensitive patterns.
# Exit 0 = clean. Exit 1 = findings detected.
#
# Usage: verify-no-leaks.sh [--quiet]
#   --quiet : suppress per-file output, only print summary and exit code

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." && pwd)"
ALLOWED_FILE="${REPO_ROOT}/bin/allowed-patterns.txt"

# ---------------------------------------------------------------------------
# Sensitive patterns (ERE, passed to grep -E)
# ---------------------------------------------------------------------------
PATTERNS=(
  '10\.50\.0\.'
  '172\.30\.0\.'
  '[Hh]etzner'
  '\bOVH\b'
  '\bovh\b'
  '[Zz]ero[Tt]ier'
  'zanuser'
  'zan@'
  'the theme system'
  '[Gg]oldberg'
  "Master's"
  '\bMASTER_ID\b'
  '\bthe memory server\b'
  '\bthe memory server\b'
  '\bthe agent framework\b'
  '\bthe agent framework\b'
  '\bthe bot framework\b'
  '\bmemoryserver\b'
  '\bMemoryServer\b'
  '\bmemory-ancestry\b'
  '\bSoma\b'
  '\bAegis\b'
  'the code analysis tool'
)

# Build a single alternation pattern for grep
GREP_PATTERN="$(printf '%s|' "${PATTERNS[@]}")"
GREP_PATTERN="${GREP_PATTERN%|}"  # strip trailing |

QUIET=false
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=true ;;
    *) echo "Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Load allowed exceptions
# Lines in allowed-patterns.txt are fixed strings; any finding line that
# contains an allowed string is suppressed.
# ---------------------------------------------------------------------------
declare -a ALLOWED=()
if [[ -f "$ALLOWED_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    ALLOWED+=("$line")
  done < "$ALLOWED_FILE"
fi

is_allowed() {
  local finding="$1"
  local a
  for a in "${ALLOWED[@]}"; do
    if [[ "$finding" == *"$a"* ]]; then
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
cd "$REPO_ROOT"

# Collect tracked files
mapfile -t TRACKED_FILES < <(git ls-files)

if [[ ${#TRACKED_FILES[@]} -eq 0 ]]; then
  echo "No tracked files found." >&2
  exit 0
fi

findings=0
suppressed=0

while IFS= read -r raw_finding; do
  [[ -z "$raw_finding" ]] && continue
  if is_allowed "$raw_finding"; then
    (( suppressed++ )) || true
    continue
  fi
  (( findings++ )) || true
  if ! $QUIET; then
    printf 'LEAK: %s\n' "$raw_finding"
  fi
done < <(
  printf '%s\n' "${TRACKED_FILES[@]}" \
    | xargs grep -nE "$GREP_PATTERN" 2>/dev/null \
    || true
)

echo ""
echo "--- verify-no-leaks summary ---"
echo "Files scanned    : ${#TRACKED_FILES[@]}"
echo "Findings         : $findings"
echo "Suppressed       : $suppressed (via allowed-patterns.txt)"

if [[ $findings -gt 0 ]]; then
  echo "STATUS: FAIL -- sensitive content detected"
  exit 1
else
  echo "STATUS: CLEAN"
  exit 0
fi

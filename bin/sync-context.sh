#!/bin/bash
# Shared sync library for per-context AGENTS.md propagation.
# Sourced by each ~/<context>/sync.sh.
#
# Caller must export CONTEXT_PHRASES as an array of context-specific phrases
# that AGENTS.md must contain.
#
# Universal structural phrases are checked here.
# Markdown structural sanity (headers, broken links) is checked here.
# After validation, AGENTS.md -> CLAUDE.md.

set -euo pipefail

# Caller passes its directory via CTX_DIR (resolved with -P).
CTX_DIR="${CTX_DIR:-$(cd -P "$(dirname "${BASH_SOURCE[1]}")" && pwd)}"
SRC="$CTX_DIR/AGENTS.md"
CTX_NAME=$(basename "$CTX_DIR")

if [ ! -f "$SRC" ]; then
  echo "SYNC ABORTED: $SRC does not exist."
  exit 1
fi

# Universal structural phrases -- present in every context's AGENTS.md.
UNIVERSAL_PHRASES=(
  "L2 Anchor"
  "Operating Frame"
  "L1 Rules"
  "Cascade Anchor"
  "Growth Integration"
  "Conflict Resolution"
)

# Context-specific phrases come from the caller via CONTEXT_PHRASES array.
# If unset, treat as empty (still gives universal-phrase coverage).
CONTEXT_PHRASES=("${CONTEXT_PHRASES[@]:-}")

FAILED=false
for phrase in "${UNIVERSAL_PHRASES[@]}" "${CONTEXT_PHRASES[@]}"; do
  [ -z "$phrase" ] && continue
  if ! grep -qF "$phrase" "$SRC"; then
    echo "SYNC ABORTED ($CTX_NAME): required phrase missing: \"$phrase\""
    FAILED=true
  fi
done

# Minimum size check.
LINES=$(wc -l < "$SRC")
if [[ $LINES -lt 50 ]]; then
  echo "SYNC ABORTED ($CTX_NAME): AGENTS.md has only $LINES lines -- looks truncated."
  FAILED=true
fi

# Markdown structural sanity: at least one top-level heading OUTSIDE any fenced
# code block (a `# foo` line inside ```...``` does not count); no obviously
# broken relative file references (text like [link](path) where path starts
# with ./ or ../ and does not resolve). External http(s) links are not
# validated.
if ! awk '
  /^```/ { fence = !fence; next }
  !fence && /^# / { found = 1 }
  END { exit !found }
' "$SRC"; then
  echo "SYNC ABORTED ($CTX_NAME): no top-level (#) heading found."
  FAILED=true
fi

# Find relative-path links of the form [text](./foo) or [text](foo.md) and check
# that they resolve. Skip http(s) URLs, mailto, and anchor-only links. Warning-
# only by design -- personas may reference future docs.
broken_links=""
while IFS= read -r raw; do
  # raw looks like [text](target); strip everything up through "(" and the trailing ")"
  target="${raw#*(}"
  target="${target%)}"
  target="${target%%#*}"
  [ -z "$target" ] && continue
  case "$target" in
    http://*|https://*|mailto:*) continue ;;
  esac
  if [[ "$target" = /* ]]; then
    candidate="$target"
  else
    candidate="$CTX_DIR/$target"
  fi
  [ -e "$candidate" ] || broken_links+="$target"$'\n'
done < <(grep -oE '\[[^]]+\]\([^)]+\)' "$SRC" || true)
if [ -n "$broken_links" ]; then
  while IFS= read -r link; do
    [ -z "$link" ] && continue
    echo "SYNC WARNING ($CTX_NAME): broken relative link: $link"
  done <<< "$broken_links"
  # Warnings only; do not fail the sync. Personas reference future docs.
fi

if $FAILED; then
  exit 1
fi

# AGENTS.md is the file. Claude Code, Codex, Cursor, and other agents read it
# natively; no CLAUDE.md duplicate needed at the directory level.
#
# Future per-directory targets for tools that don't read AGENTS.md natively can
# be added here when those tools are actually used:
#   cp "$SRC" "$CTX_DIR/GEMINI.md"

echo "$CTX_NAME/AGENTS.md validated ($(date '+%Y-%m-%d %H:%M:%S'))"

#!/usr/bin/env bash
# Validate the canonical public Wiki source and stage reviewed pages safely.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
wiki_dir="$repo_root/docs/wiki"

# Print an error message and terminate with a failing status.
fail() {
  printf 'wiki-docs: %s\n' "$*" >&2
  exit 1
}

# Convert a GitHub Wiki page label into its canonical Markdown filename.
page_filename() {
  local label=$1
  label=${label##*|}
  label=${label%%#*}
  label=${label// /-}
  printf '%s.md\n' "$label"
}

# Emit Wiki links from prose while ignoring fenced code blocks.
prose_wiki_links() {
  local file=$1
  awk '
    /^```/ { fenced = !fenced; next }
    !fenced { print }
  ' "$file" | grep -oE '\[\[[^]]+\]\]' || true
}

# Emit canonical filenames for every page linked from the sidebar.
sidebar_pages() {
  local link
  local label

  while IFS= read -r link; do
    [[ -n "$link" ]] || continue
    label=${link#'[['}
    label=${label%']]'}
    page_filename "$label"
  done < <(prose_wiki_links "$wiki_dir/_Sidebar.md")
}

# Verify that canonical pages are named safely and have complete navigation.
validate_inventory() {
  local file
  local base
  local sidebar_inventory

  [[ -d "$wiki_dir" ]] || fail "canonical directory is missing: $wiki_dir"
  if find "$wiki_dir" -mindepth 1 -type l -print -quit | grep -q .; then
    fail "canonical Wiki source must not contain symbolic links"
  fi
  if find "$wiki_dir" -mindepth 2 -print -quit | grep -q .; then
    fail "canonical Wiki source must contain only top-level pages"
  fi
  for required in Home.md _Sidebar.md _Footer.md SOURCES.md; do
    [[ -f "$wiki_dir/$required" ]] || fail "required page is missing: $required"
  done
  sidebar_inventory=$(sidebar_pages)

  while IFS= read -r file; do
    base=$(basename "$file")
    [[ "$base" =~ ^[A-Za-z0-9_-]+\.md$ ]] ||
      fail "unsafe Wiki page filename: $base"
    if [[ "$base" != _Sidebar.md && "$base" != _Footer.md && "$base" != SOURCES.md ]]; then
      grep -Fxq "$base" <<< "$sidebar_inventory" ||
        fail "sidebar does not link to $base"
    fi
    if [[ "$base" != SOURCES.md ]]; then
      grep -Fq "\`$base\`" "$wiki_dir/SOURCES.md" ||
        fail "source map does not cover $base"
    fi
  done < <(find "$wiki_dir" -maxdepth 1 -type f -name '*.md' | sort)
}

# Verify that every prose Wiki link resolves to a canonical page.
validate_links() {
  local file
  local link
  local label
  local target

  while IFS= read -r file; do
    while IFS= read -r link; do
      [[ -n "$link" ]] || continue
      label=${link#'[['}
      label=${label%']]'}
      target=$(page_filename "$label")
      [[ -f "$wiki_dir/$target" ]] ||
        fail "$(basename "$file") links to missing page: $label"
    done < <(prose_wiki_links "$file")
  done < <(find "$wiki_dir" -maxdepth 1 -type f -name '*.md' | sort)
}

# Reject private infrastructure and credential-shaped values from public prose.
validate_public_boundary() {
  local forbidden
  local unexpected_repo

  forbidden='(/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})'
  if rg -n -i "$forbidden" "$wiki_dir" --glob '*.md'; then
    fail "public documentation contains a forbidden private-content pattern"
  fi
  unexpected_repo=$(rg -n -i 'github\.com/Ghost-Frame/' "$wiki_dir" --glob '*.md' |
    rg -v 'github\.com/Ghost-Frame/FrameShift([^A-Za-z0-9_-]|$)' || true)
  [[ -z "$unexpected_repo" ]] ||
    fail "public documentation links to an unexpected organization repository"
}

# Run every deterministic check against the canonical Wiki source.
validate_all() {
  validate_inventory
  validate_links
  validate_public_boundary
  printf 'wiki-docs: canonical source is valid\n'
}

# Resolve and verify a clean checkout of the associated public Wiki repository.
verify_wiki_checkout() {
  local requested=$1
  local checkout
  local remote

  [[ -d "$requested/.git" ]] || fail "not a Git checkout: $requested"
  checkout=$(cd "$requested" && pwd)
  remote=$(git -C "$checkout" remote get-url origin)
  [[ "$remote" =~ (^|[:/])Ghost-Frame/FrameShift\.wiki\.git$ ]] ||
    fail "unexpected Wiki remote: $remote"
  [[ -z "$(git -C "$checkout" status --short)" ]] ||
    fail "Wiki checkout must be clean before staging"
  if find "$checkout" -maxdepth 1 -type l -name '*.md' -print -quit | grep -q .; then
    fail "Wiki checkout must not contain symbolic-link pages"
  fi
  printf '%s\n' "$checkout"
}

# Reject remote Markdown pages that have no reviewed canonical counterpart.
verify_managed_pages() {
  local checkout=$1
  local remote_page
  local base

  while IFS= read -r remote_page; do
    base=$(basename "$remote_page")
    [[ -f "$wiki_dir/$base" ]] ||
      fail "Wiki checkout has unmanaged page: $base"
  done < <(find "$checkout" -maxdepth 1 -type f -name '*.md' | sort)
}

# Compare a clean Wiki checkout with the canonical source.
check_checkout() {
  local checkout
  local canonical_page
  local base
  local changed=0

  checkout=$(verify_wiki_checkout "$1")
  verify_managed_pages "$checkout"
  while IFS= read -r canonical_page; do
    base=$(basename "$canonical_page")
    if [[ ! -f "$checkout/$base" ]] || ! cmp -s "$canonical_page" "$checkout/$base"; then
      printf 'wiki-docs: differs: %s\n' "$base" >&2
      changed=1
    fi
  done < <(find "$wiki_dir" -maxdepth 1 -type f -name '*.md' | sort)
  [[ "$changed" -eq 0 ]] || fail "Wiki checkout differs from canonical source"
  printf 'wiki-docs: Wiki checkout matches canonical source\n'
}

# Copy canonical pages into a verified checkout without deleting or publishing.
stage_checkout() {
  local checkout
  local canonical_page

  checkout=$(verify_wiki_checkout "$1")
  verify_managed_pages "$checkout"
  while IFS= read -r canonical_page; do
    cp -- "$canonical_page" "$checkout/$(basename "$canonical_page")"
  done < <(find "$wiki_dir" -maxdepth 1 -type f -name '*.md' | sort)
  printf 'wiki-docs: staged canonical pages in %s\n' "$checkout"
  git -C "$checkout" status --short
}

# Dispatch the requested validation or staging operation.
main() {
  local command=${1:-validate}

  case "$command" in
    validate)
      [[ "$#" -eq 1 || "$#" -eq 0 ]] || fail "usage: $0 validate"
      validate_all
      ;;
    check)
      [[ "$#" -eq 2 ]] || fail "usage: $0 check WIKI_CHECKOUT"
      validate_all
      check_checkout "$2"
      ;;
    stage)
      [[ "$#" -eq 2 ]] || fail "usage: $0 stage WIKI_CHECKOUT"
      validate_all
      stage_checkout "$2"
      ;;
    *)
      fail "usage: $0 {validate|check|stage} [WIKI_CHECKOUT]"
      ;;
  esac
}

main "$@"

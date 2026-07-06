#!/usr/bin/env bash
#
# preflight.sh -- run the same gates CI runs, locally, before you push.
#
# Mirrors .github/workflows/ci.yml so a green preflight means a green CI (minus
# the Postgres-integration and mirror jobs, which need Docker / the remote and
# are not reproduced here). Run this before opening or updating a PR.
#
# Usage:
#   scripts/preflight.sh           # fmt + clippy + test + audit
#   scripts/preflight.sh --fast    # fmt + audit only (no compile; what the
#                                   # pre-push hook runs)
#
# Exits nonzero on the first failing gate.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# The advisories CI ignores. Keep this in sync with the `ignore:` field in
# .github/workflows/ci.yml (see that file for the full justification of each):
#   RUSTSEC-2024-0370  proc-macro-error unmaintained (build-time only, age -> i18n-embed-fl)
#   RUSTSEC-2026-0194  quick-xml < 0.41 quadratic duplicate-attribute check (object_store -> R2, trusted XML)
#   RUSTSEC-2026-0195  quick-xml < 0.41 unbounded namespace allocation (same path)
AUDIT_IGNORE=(RUSTSEC-2024-0370 RUSTSEC-2026-0194 RUSTSEC-2026-0195)

fast_only=0
if [[ "${1:-}" == "--fast" ]]; then
    fast_only=1
fi

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
ok() { printf '\033[1;32m   ok: %s\033[0m\n' "$1"; }
fail() { printf '\033[1;31m   FAIL: %s\033[0m\n' "$1" >&2; exit 1; }

# 1. Formatting (instant, no compile). The most common CI failure.
step "cargo fmt --all -- --check"
cargo fmt --all -- --check || fail "rustfmt: run 'cargo fmt --all' to fix"
ok "formatting"

# 2. Supply-chain advisories (fast, reads Cargo.lock; no project compile).
step "cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
    audit_args=()
    for adv in "${AUDIT_IGNORE[@]}"; do audit_args+=(--ignore "$adv"); done
    cargo audit "${audit_args[@]}" || fail "cargo audit found advisories"
    ok "audit"
else
    printf '\033[1;33m   SKIP: cargo-audit not installed (cargo install cargo-audit)\033[0m\n'
fi

if [[ "$fast_only" == "1" ]]; then
    step "fast preflight complete"
    ok "fmt + audit clean -- safe to push (clippy/test not run in --fast mode)"
    exit 0
fi

# 3. Lints (compiles; matches CI's clippy job).
step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy"
ok "clippy"

# 4. Tests (compiles; matches CI's plain test job, Docker-gated tests skipped).
step "cargo test --workspace"
cargo test --workspace || fail "tests"
ok "tests"

step "preflight complete"
ok "all gates green -- safe to push"

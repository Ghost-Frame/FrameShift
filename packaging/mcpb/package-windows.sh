#!/usr/bin/env bash
# Builds one deterministic, fail-closed Windows MCPB with the pinned official CLI.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
STAGING_SOURCE="$SCRIPT_DIR/staging"
VERIFIER="$SCRIPT_DIR/verify_bundle.py"
PRELOAD="$SCRIPT_DIR/deterministic-preload.cjs"
EXPECTED_MCPB_VERSION="2.1.2"
VERSION=""
BINARY=""
OUTPUT=""
TEMP_ROOT=""

# Prints one packaging error and exits without publishing an output artifact.
fail() {
  printf 'MCPB packaging failed: %s\n' "$1" >&2
  exit 1
}

# Finds a Python 3 interpreter suitable for the independent ZIP verifier.
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

# Removes only the uniquely named temporary staging directory from this run.
cleanup() {
  if [[ -z "$TEMP_ROOT" ]]; then
    return
  fi
  case "$TEMP_ROOT" in
    "${TMPDIR:-/tmp}"/frameshift-mcpb.*) rm -rf -- "$TEMP_ROOT" ;;
    *) printf 'refusing to remove unexpected temporary path: %s\n' "$TEMP_ROOT" >&2 ;;
  esac
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --version)
      [[ -z "$VERSION" && "$#" -ge 2 ]] || fail "--version requires one value"
      VERSION="$2"
      shift 2
      ;;
    --binary)
      [[ -z "$BINARY" && "$#" -ge 2 ]] || fail "--binary requires one value"
      BINARY="$2"
      shift 2
      ;;
    --output)
      [[ -z "$OUTPUT" && "$#" -ge 2 ]] || fail "--output requires one value"
      OUTPUT="$2"
      shift 2
      ;;
    *) fail "unexpected argument: $1" ;;
  esac
done

[[ -n "$VERSION" ]] || fail "--version is required"
[[ -n "$BINARY" ]] || fail "--binary is required"
[[ -n "$OUTPUT" ]] || fail "--output is required"

PYTHON_BIN="$(resolve_python)" || fail "Python 3.9 or newer is required"
command -v node >/dev/null 2>&1 || fail "Node.js is required"
"$PYTHON_BIN" "$VERIFIER" version "$VERSION"

EXPECTED_OUTPUT_NAME="frameshift-windows-$VERSION.mcpb"
[[ "${OUTPUT##*/}" == "$EXPECTED_OUTPUT_NAME" ]] \
  || fail "output basename must be $EXPECTED_OUTPUT_NAME"
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || fail "refusing to overwrite output: $OUTPUT"

"$PYTHON_BIN" "$VERIFIER" source "$STAGING_SOURCE"
"$PYTHON_BIN" "$VERIFIER" binary "$BINARY"

MCPB_PACKAGE="$REPO_ROOT/node_modules/@anthropic-ai/mcpb/package.json"
MCPB_CLI="$REPO_ROOT/node_modules/@anthropic-ai/mcpb/dist/cli/cli.js"
[[ -f "$MCPB_PACKAGE" && ! -L "$MCPB_PACKAGE" ]] \
  || fail "run npm ci to install the pinned MCPB release toolchain"
[[ -f "$MCPB_CLI" && ! -L "$MCPB_CLI" ]] || fail "pinned MCPB CLI entry point is absent"

INSTALLED_MCPB_VERSION="$(node -p 'require(process.argv[1]).version' "$MCPB_PACKAGE")"
[[ "$INSTALLED_MCPB_VERSION" == "$EXPECTED_MCPB_VERSION" ]] \
  || fail "installed MCPB package is $INSTALLED_MCPB_VERSION, expected $EXPECTED_MCPB_VERSION"
REPORTED_MCPB_VERSION="$(node "$MCPB_CLI" --version | tr -d '\r\n')"
[[ "$REPORTED_MCPB_VERSION" == "$EXPECTED_MCPB_VERSION" ]] \
  || fail "MCPB CLI reports $REPORTED_MCPB_VERSION, expected $EXPECTED_MCPB_VERSION"

OUTPUT_DIR="$(dirname -- "$OUTPUT")"
mkdir -p -- "$OUTPUT_DIR"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/frameshift-mcpb.XXXXXX")"
trap cleanup EXIT
STAGE="$TEMP_ROOT/stage"
CANDIDATE="$TEMP_ROOT/$EXPECTED_OUTPUT_NAME"
mkdir -p -- "$STAGE/server"

"$PYTHON_BIN" "$VERIFIER" render \
  "$STAGING_SOURCE/manifest.json" "$VERSION" "$STAGE/manifest.json"
cp -- "$STAGING_SOURCE/README.md" "$STAGE/README.md"
cp -- "$REPO_ROOT/LICENSE" "$STAGE/LICENSE"
cp -- "$BINARY" "$STAGE/server/frameshift-mcp.exe"
chmod 0755 "$STAGE/server/frameshift-mcp.exe"

"$PYTHON_BIN" "$VERIFIER" stage "$STAGE" "$VERSION"
node "$MCPB_CLI" validate "$STAGE/manifest.json"
node --require "$PRELOAD" "$MCPB_CLI" pack "$STAGE" "$CANDIDATE"
"$PYTHON_BIN" "$VERIFIER" archive "$CANDIDATE" "$STAGE" "$VERSION"

mv -- "$CANDIDATE" "$OUTPUT"
printf 'Created %s with @anthropic-ai/mcpb %s\n' "$OUTPUT" "$EXPECTED_MCPB_VERSION"

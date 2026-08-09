#!/usr/bin/env bash
# Exercises the full MCPB packaging entry point with a synthetic Windows binary.

set -euo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MCPB_DIR="$(cd -- "$TEST_DIR/.." && pwd -P)"
PACKAGE_SCRIPT="$MCPB_DIR/package-windows.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/frameshift-mcpb-tests.XXXXXX")"
VERSION="1.2.3-beta.1+test"

# Removes only the uniquely named temporary directory created for this test run.
cleanup() {
  case "$TEST_ROOT" in
    "${TMPDIR:-/tmp}"/frameshift-mcpb-tests.*) rm -rf -- "$TEST_ROOT" ;;
    *) printf 'refusing to remove unexpected test path: %s\n' "$TEST_ROOT" >&2 ;;
  esac
}

trap cleanup EXIT

# Prints one focused assertion failure and stops the integration test.
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

# Requires a command to fail and records its diagnostics for inspection.
expect_failure() {
  local label="$1"
  shift

  if "$@" >"$TEST_ROOT/$label.stdout" 2>"$TEST_ROOT/$label.stderr"; then
    fail "$label unexpectedly succeeded"
  fi
}

VALID_BINARY="$TEST_ROOT/valid/frameshift-mcp.exe"
mkdir -p -- "${VALID_BINARY%/*}"
"${PYTHON:-python3}" - "$VALID_BINARY" <<'PY'
import struct
import sys

output = sys.argv[1]
data = bytearray(512)
data[:2] = b"MZ"
struct.pack_into("<I", data, 0x3C, 0x80)
data[0x80:0x84] = b"PE\0\0"
struct.pack_into("<HH", data, 0x84, 0x8664, 1)
struct.pack_into("<HH", data, 0x94, 0xF0, 0x0002)
struct.pack_into("<H", data, 0x98, 0x020B)
with open(output, "wb") as executable:
    executable.write(data)
PY

FIRST_OUTPUT="$TEST_ROOT/first/frameshift-windows-$VERSION.mcpb"
SECOND_OUTPUT="$TEST_ROOT/second/frameshift-windows-$VERSION.mcpb"
bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$VALID_BINARY" --output "$FIRST_OUTPUT"
bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$VALID_BINARY" --output "$SECOND_OUTPUT"
cmp -s "$FIRST_OUTPUT" "$SECOND_OUTPUT" || fail "repeated packages are not byte-identical"

expect_failure existing-output \
  bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$VALID_BINARY" --output "$FIRST_OUTPUT"

MISSING_BINARY="$TEST_ROOT/missing/frameshift-mcp.exe"
MISSING_OUTPUT="$TEST_ROOT/missing-output/frameshift-windows-$VERSION.mcpb"
expect_failure missing-binary \
  bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$MISSING_BINARY" --output "$MISSING_OUTPUT"
[[ ! -e "$MISSING_OUTPUT" ]] || fail "missing-binary failure left an output artifact"

WRONG_NAME="$TEST_ROOT/wrong-name/server.exe"
mkdir -p -- "${WRONG_NAME%/*}"
cp -- "$VALID_BINARY" "$WRONG_NAME"
WRONG_NAME_OUTPUT="$TEST_ROOT/wrong-name-output/frameshift-windows-$VERSION.mcpb"
expect_failure wrong-name \
  bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$WRONG_NAME" --output "$WRONG_NAME_OUTPUT"
[[ ! -e "$WRONG_NAME_OUTPUT" ]] || fail "wrong-name failure left an output artifact"

NON_PE_BINARY="$TEST_ROOT/non-pe/frameshift-mcp.exe"
mkdir -p -- "${NON_PE_BINARY%/*}"
printf 'not a Windows executable\n' >"$NON_PE_BINARY"
NON_PE_OUTPUT="$TEST_ROOT/non-pe-output/frameshift-windows-$VERSION.mcpb"
expect_failure non-pe \
  bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$NON_PE_BINARY" --output "$NON_PE_OUTPUT"
[[ ! -e "$NON_PE_OUTPUT" ]] || fail "non-PE failure left an output artifact"

# Windows hosted runners do not provide portable symbolic-link semantics.
if [[ "${RUNNER_OS:-}" != "Windows" ]]; then
  SYMLINK_BINARY="$TEST_ROOT/symlink/frameshift-mcp.exe"
  mkdir -p -- "${SYMLINK_BINARY%/*}"
  ln -s -- "$VALID_BINARY" "$SYMLINK_BINARY"
  SYMLINK_OUTPUT="$TEST_ROOT/symlink-output/frameshift-windows-$VERSION.mcpb"
  expect_failure symlink \
    bash "$PACKAGE_SCRIPT" --version "$VERSION" --binary "$SYMLINK_BINARY" --output "$SYMLINK_OUTPUT"
  [[ ! -e "$SYMLINK_OUTPUT" ]] || fail "symlink failure left an output artifact"
fi

INVALID_VERSION="01.2.3"
INVALID_OUTPUT="$TEST_ROOT/invalid-version/frameshift-windows-$INVALID_VERSION.mcpb"
expect_failure invalid-version \
  bash "$PACKAGE_SCRIPT" --version "$INVALID_VERSION" --binary "$VALID_BINARY" --output "$INVALID_OUTPUT"
[[ ! -e "$INVALID_OUTPUT" ]] || fail "invalid-version failure left an output artifact"

printf 'MCPB packaging integration tests passed\n'

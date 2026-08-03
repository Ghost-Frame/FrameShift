#!/usr/bin/env bash
# Exercises the backup sender and receiver with deterministic local command fakes.

set -euo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOY_DIR="$(cd -- "$TEST_DIR/.." && pwd -P)"
BACKUP_SCRIPT="$DEPLOY_DIR/frameshift-backup.sh"
RECEIVER_SCRIPT="$DEPLOY_DIR/frameshift-backup-receive.sh"
BACKUP_SERVICE="$DEPLOY_DIR/frameshift-backup.service"
SERVER_SERVICE="$DEPLOY_DIR/frameshift-server.service"
TEST_TIMESTAMP="20260802T120000Z"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/frameshift-backup-tests.XXXXXX")"
FAKE_BIN="$TEST_ROOT/fake-bin"
CASE_NUMBER=0

# Removes only the uniquely named temporary directory created by this test run.
cleanup() {
  case "$TEST_ROOT" in
    "${TMPDIR:-/tmp}"/frameshift-backup-tests.*) rm -rf -- "$TEST_ROOT" ;;
    *) printf 'refusing to remove unexpected test path: %s\n' "$TEST_ROOT" >&2 ;;
  esac
}

trap cleanup EXIT

# Prints a focused assertion failure and stops the test suite.
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

# Requires a file to contain exactly the supplied bytes.
assert_file_bytes() {
  local path="$1"
  local expected="$2"

  if ! cmp -s <(printf '%s' "$expected") "$path"; then
    printf 'unexpected content in %s\n' "$path" >&2
    diff -u <(printf '%s' "$expected") "$path" >&2 || true
    fail "file content mismatch"
  fi
}

# Requires a file to contain one fixed string.
assert_file_contains() {
  local path="$1"
  local expected="$2"

  grep -Fq -- "$expected" "$path" \
    || fail "$path does not contain expected text: $expected"
}

# Requires a path not to exist.
assert_path_absent() {
  local path="$1"

  [[ ! -e "$path" ]] || fail "unexpected path exists: $path"
}

# Installs deterministic stand-ins for every external backup producer and transport.
make_fake_commands() {
  mkdir -p "$FAKE_BIN"
  cat >"$FAKE_BIN/fake-command" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

case "${0##*/}" in
  date)
    [[ "$#" -eq 2 && "$1" == "-u" && "$2" == "+%Y%m%dT%H%M%SZ" ]]
    printf 'date\n' >>"$TEST_OUTPUT_DIR/producers.log"
    printf '%s\n' "$TEST_TIMESTAMP"
    ;;
  pg_dump)
    [[ "$#" -eq 4 ]]
    [[ "$1" == "--dbname=$POSTGRES_URL" ]]
    [[ "$2" == "--format=custom" ]]
    [[ "$3" == "--no-owner" ]]
    [[ "$4" == "--no-privileges" ]]
    printf 'pg_dump\n' >>"$TEST_OUTPUT_DIR/producers.log"
    printf 'postgres-stream\n'
    ;;
  gzip)
    [[ "$#" -eq 1 && "$1" == "-n" ]]
    cat
    ;;
  tar)
    directory=""
    entry=""
    for argument in "$@"; do
      case "$argument" in
        --create|--file=-) ;;
        --directory=*) directory="${argument#--directory=}" ;;
        *) entry="$argument" ;;
      esac
    done
    archive_path="$directory/$entry"
    if [[ "$archive_path" == "$OBJECT_STORE_ROOT" ]]; then
      printf 'tar:public\n' >>"$TEST_OUTPUT_DIR/producers.log"
      printf 'public-objects-stream\n'
    elif [[ -n "${QUARANTINE_OBJECT_STORE_ROOT:-}" \
      && "$archive_path" == "$QUARANTINE_OBJECT_STORE_ROOT" ]]; then
      printf 'tar:quarantine\n' >>"$TEST_OUTPUT_DIR/producers.log"
      printf 'quarantine-objects-stream\n'
    else
      printf 'unexpected tar source: %s\n' "$archive_path" >&2
      exit 70
    fi
    ;;
  ssh)
    remote_command="${!#}"
    action=""
    kind=""
    timestamp=""
    extra=""
    read -r action kind timestamp extra <<<"$remote_command"
    [[ "$action" == "put" && -z "$extra" && "$timestamp" == "$TEST_TIMESTAMP" ]]
    cat >"$TEST_OUTPUT_DIR/$kind.payload"
    printf '%s %s\n' "$kind" "$timestamp" >>"$TEST_OUTPUT_DIR/uploads.log"
    printf 'receipt-%s\n' "$kind"
    ;;
  *)
    printf 'unexpected fake command: %s\n' "${0##*/}" >&2
    exit 70
    ;;
esac
FAKE
  chmod 0755 "$FAKE_BIN/fake-command"
  ln -s fake-command "$FAKE_BIN/date"
  ln -s fake-command "$FAKE_BIN/gzip"
  ln -s fake-command "$FAKE_BIN/pg_dump"
  ln -s fake-command "$FAKE_BIN/ssh"
  ln -s fake-command "$FAKE_BIN/tar"
}

# Creates isolated paths and baseline backup credentials for one test case.
prepare_case() {
  local name="$1"

  CASE_NUMBER=$((CASE_NUMBER + 1))
  CASE_DIR="$TEST_ROOT/$(printf '%02d' "$CASE_NUMBER")-$name"
  OBJECTS_ROOT="$CASE_DIR/objects"
  QUARANTINE_ROOT="$CASE_DIR/quarantine"
  OUTPUT_DIR="$CASE_DIR/output"
  SERVER_ENV="$CASE_DIR/server.env"
  BACKUP_ENV="$CASE_DIR/backup.env"
  mkdir -p "$OBJECTS_ROOT" "$QUARANTINE_ROOT" "$OUTPUT_DIR"
  : >"$CASE_DIR/backup-key"
  : >"$CASE_DIR/known-hosts"
  printf '%s\n' \
    "BACKUP_SSH_KEY=$CASE_DIR/backup-key" \
    "BACKUP_SSH_TARGET=backup@example.invalid" \
    "BACKUP_KNOWN_HOSTS_FILE=$CASE_DIR/known-hosts" \
    "BACKUP_SSH_PORT=2222" \
    >"$BACKUP_ENV"
}

# Writes one server environment, optionally omitting either backend selector.
write_server_environment() {
  local public_backend="$1"
  local quarantine_backend="$2"
  local objects_root="$3"
  local quarantine_root="$4"

  {
    printf '%s\n' \
      'POSTGRES_URL=postgres://backup.invalid/frameshift' \
      "OBJECT_STORE_ROOT=$objects_root"
    if [[ "$public_backend" != "__unset__" ]]; then
      printf 'OBJECT_STORE_BACKEND=%s\n' "$public_backend"
    fi
    if [[ "$quarantine_backend" != "__unset__" ]]; then
      printf 'QUARANTINE_OBJECT_STORE_BACKEND=%s\n' "$quarantine_backend"
    fi
    if [[ "$quarantine_root" != "__unset__" ]]; then
      printf 'QUARANTINE_OBJECT_STORE_ROOT=%s\n' "$quarantine_root"
    fi
    printf '%s\n' \
      'R2_ENDPOINT=https://dormant-public.invalid' \
      'R2_BUCKET=dormant-public' \
      'R2_PREFIX=dormant-public-prefix' \
      'QUARANTINE_R2_ENDPOINT=https://dormant-quarantine.invalid' \
      'QUARANTINE_R2_BUCKET=dormant-quarantine' \
      'QUARANTINE_R2_PREFIX=dormant-quarantine-prefix'
  } >"$SERVER_ENV"
}

# Runs the sender in a clean environment with only deterministic fakes on PATH.
run_backup() {
  /usr/bin/env -i \
    PATH="$FAKE_BIN:/usr/bin:/bin" \
    SERVER_ENV_FILE="$SERVER_ENV" \
    BACKUP_ENV_FILE="$BACKUP_ENV" \
    TEST_OUTPUT_DIR="$OUTPUT_DIR" \
    TEST_TIMESTAMP="$TEST_TIMESTAMP" \
    /bin/bash "$BACKUP_SCRIPT"
}

# Requires a failed sender run to stop before producing or uploading any bytes.
assert_backup_rejected_before_upload() {
  local name="$1"
  local public_backend="$2"
  local quarantine_backend="$3"
  local objects_root="$4"
  local quarantine_root="$5"
  local expected_status="$6"
  local expected_error="$7"
  local status=0

  write_server_environment \
    "$public_backend" \
    "$quarantine_backend" \
    "$objects_root" \
    "$quarantine_root"
  run_backup >"$CASE_DIR/$name.stdout" 2>"$CASE_DIR/$name.stderr" || status=$?
  [[ "$status" -eq "$expected_status" ]] \
    || fail "$name exited with $status instead of $expected_status"
  assert_file_contains "$CASE_DIR/$name.stderr" "$expected_error"
  assert_path_absent "$OUTPUT_DIR/producers.log"
  assert_path_absent "$OUTPUT_DIR/uploads.log"
}

# Verifies omitted selectors preserve the original three-upload v1 protocol.
test_disabled_quarantine_preserves_v1() {
  prepare_case "v1"
  write_server_environment "__unset__" "__unset__" "$OBJECTS_ROOT" "$QUARANTINE_ROOT"

  run_backup >"$CASE_DIR/stdout" 2>"$CASE_DIR/stderr"

  assert_file_bytes "$OUTPUT_DIR/uploads.log" \
    $'postgres 20260802T120000Z\nobjects 20260802T120000Z\nmanifest 20260802T120000Z\n'
  assert_file_bytes "$OUTPUT_DIR/producers.log" $'date\npg_dump\ntar:public\n'
  assert_file_bytes "$OUTPUT_DIR/postgres.payload" $'postgres-stream\n'
  assert_file_bytes "$OUTPUT_DIR/objects.payload" $'public-objects-stream\n'
  assert_file_bytes "$OUTPUT_DIR/manifest.payload" \
    $'format=frameshift-backup-v1\ncreated_at=20260802T120000Z\npostgres=receipt-postgres\nobjects=receipt-objects\n'
  assert_file_bytes "$CASE_DIR/stdout" $'receipt-manifest\n'
  assert_file_bytes "$CASE_DIR/stderr" ''
  assert_path_absent "$OUTPUT_DIR/quarantine.payload"
}

# Verifies filesystem quarantine creates a separate stream and ordered v2 manifest.
test_filesystem_quarantine_uses_v2() {
  prepare_case "v2"
  write_server_environment "fs" "fs" "$OBJECTS_ROOT" "$QUARANTINE_ROOT"

  run_backup >"$CASE_DIR/stdout" 2>"$CASE_DIR/stderr"

  assert_file_bytes "$OUTPUT_DIR/uploads.log" \
    $'postgres 20260802T120000Z\nobjects 20260802T120000Z\nquarantine 20260802T120000Z\nmanifest 20260802T120000Z\n'
  assert_file_bytes "$OUTPUT_DIR/producers.log" \
    $'date\npg_dump\ntar:public\ntar:quarantine\n'
  assert_file_bytes "$OUTPUT_DIR/objects.payload" $'public-objects-stream\n'
  assert_file_bytes "$OUTPUT_DIR/quarantine.payload" $'quarantine-objects-stream\n'
  assert_file_bytes "$OUTPUT_DIR/manifest.payload" \
    $'format=frameshift-backup-v2\ncreated_at=20260802T120000Z\npostgres=receipt-postgres\nobjects=receipt-objects\nquarantine=receipt-quarantine\n'
  assert_file_bytes "$CASE_DIR/stdout" $'receipt-manifest\n'
  assert_file_bytes "$CASE_DIR/stderr" ''
}

# Verifies every R2 or unknown selector is rejected before backup work begins.
test_unsupported_backends_fail_closed() {
  prepare_case "backend-rejections"
  assert_backup_rejected_before_upload \
    "public-r2" "r2" "disabled" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "OBJECT_STORE_BACKEND=r2 is not supported"

  prepare_case "quarantine-r2"
  assert_backup_rejected_before_upload \
    "quarantine-r2" "fs" "r2" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "QUARANTINE_OBJECT_STORE_BACKEND=r2 is not supported"

  prepare_case "public-unknown"
  assert_backup_rejected_before_upload \
    "public-unknown" "other" "disabled" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "invalid OBJECT_STORE_BACKEND"

  prepare_case "quarantine-unknown"
  assert_backup_rejected_before_upload \
    "quarantine-unknown" "fs" "other" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "invalid QUARANTINE_OBJECT_STORE_BACKEND"

  prepare_case "public-empty"
  assert_backup_rejected_before_upload \
    "public-empty" "" "disabled" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "invalid OBJECT_STORE_BACKEND"

  prepare_case "quarantine-empty"
  assert_backup_rejected_before_upload \
    "quarantine-empty" "fs" "" "$OBJECTS_ROOT" "$QUARANTINE_ROOT" 64 \
    "invalid QUARANTINE_OBJECT_STORE_BACKEND"
}

# Verifies filesystem quarantine roots exist, are readable, and canonicalize apart.
test_filesystem_roots_fail_closed() {
  local alias_root
  local missing_root

  prepare_case "shared-roots"
  alias_root="$CASE_DIR/quarantine-alias"
  ln -s "$OBJECTS_ROOT" "$alias_root"
  assert_backup_rejected_before_upload \
    "shared-roots" "fs" "fs" "$OBJECTS_ROOT" "$alias_root" 64 \
    "public and quarantine object-store roots must be distinct"

  prepare_case "missing-quarantine"
  missing_root="$CASE_DIR/missing-quarantine"
  assert_backup_rejected_before_upload \
    "missing-quarantine" "fs" "fs" "$OBJECTS_ROOT" "$missing_root" 66 \
    "QUARANTINE_OBJECT_STORE_ROOT must name a readable directory"

  prepare_case "empty-public"
  assert_backup_rejected_before_upload \
    "empty-public" "fs" "fs" "" "$QUARANTINE_ROOT" 66 \
    "OBJECT_STORE_ROOT must name a readable directory"
}

# Verifies the restricted receiver accepts quarantine and assigns its fixed suffix.
test_receiver_accepts_quarantine() {
  local backup_root
  local filename
  local expected_hash

  prepare_case "receiver-quarantine"
  backup_root="$CASE_DIR/received"
  filename="frameshift-$TEST_TIMESTAMP-quarantine.tar.gz"
  printf 'quarantine-archive\n' \
    | /usr/bin/env -i \
      PATH="/usr/bin:/bin" \
      BACKUP_ROOT="$backup_root" \
      SSH_ORIGINAL_COMMAND="put quarantine $TEST_TIMESTAMP" \
      /bin/bash "$RECEIVER_SCRIPT" \
      >"$CASE_DIR/receipt" \
      2>"$CASE_DIR/receiver.stderr"

  expected_hash="$(printf 'quarantine-archive\n' | sha256sum | cut -d ' ' -f 1)"
  assert_file_bytes "$backup_root/$filename" $'quarantine-archive\n'
  assert_file_bytes "$backup_root/$filename.sha256" "$expected_hash  $filename"$'\n'
  assert_file_bytes "$CASE_DIR/receipt" "$expected_hash  $filename"$'\n'
  assert_file_bytes "$CASE_DIR/receiver.stderr" ''
}

# Verifies the restricted receiver still rejects unrecognized upload kinds.
test_receiver_rejects_unknown_kind() {
  local backup_root
  local status=0

  prepare_case "receiver-rejection"
  backup_root="$CASE_DIR/received"
  printf 'private-archive\n' \
    | /usr/bin/env -i \
      PATH="/usr/bin:/bin" \
      BACKUP_ROOT="$backup_root" \
      SSH_ORIGINAL_COMMAND="put private $TEST_TIMESTAMP" \
      /bin/bash "$RECEIVER_SCRIPT" \
      >"$CASE_DIR/receiver.stdout" \
      2>"$CASE_DIR/receiver.stderr" \
    || status=$?

  [[ "$status" -eq 64 ]] || fail "receiver rejection exited with $status instead of 64"
  assert_file_contains "$CASE_DIR/receiver.stderr" "invalid backup kind"
  assert_path_absent "$backup_root"
}

# Verifies the restricted receiver rejects commands with trailing arguments.
test_receiver_rejects_malformed_command() {
  local backup_root
  local status=0

  prepare_case "receiver-malformed"
  backup_root="$CASE_DIR/received"
  printf 'quarantine-archive\n' \
    | /usr/bin/env -i \
      PATH="/usr/bin:/bin" \
      BACKUP_ROOT="$backup_root" \
      SSH_ORIGINAL_COMMAND="put quarantine $TEST_TIMESTAMP extra" \
      /bin/bash "$RECEIVER_SCRIPT" \
      >"$CASE_DIR/receiver.stdout" \
      2>"$CASE_DIR/receiver.stderr" \
    || status=$?

  [[ "$status" -eq 64 ]] || fail "malformed receiver command exited with $status instead of 64"
  assert_file_contains "$CASE_DIR/receiver.stderr" \
    "expected: put <postgres|objects|quarantine|manifest> <UTC timestamp>"
  assert_path_absent "$backup_root"
}

# Verifies both hardened units expose the canonical persistent quarantine path.
test_units_allow_canonical_quarantine_path() {
  assert_file_contains "$BACKUP_SERVICE" \
    "ReadOnlyPaths=/etc/frameshift /var/lib/frameshift/objects"
  assert_file_contains "$BACKUP_SERVICE" \
    "ReadOnlyPaths=-/var/lib/frameshift/quarantine"
  assert_file_contains "$SERVER_SERVICE" \
    "ReadWritePaths=/var/lib/frameshift/objects"
  assert_file_contains "$SERVER_SERVICE" \
    "ReadWritePaths=-/var/lib/frameshift/quarantine"
}

# Runs syntax checks followed by every deterministic integration scenario.
main() {
  bash -n "$BACKUP_SCRIPT" "$RECEIVER_SCRIPT" "$0"
  make_fake_commands
  test_disabled_quarantine_preserves_v1
  test_filesystem_quarantine_uses_v2
  test_unsupported_backends_fail_closed
  test_filesystem_roots_fail_closed
  test_receiver_accepts_quarantine
  test_receiver_rejects_unknown_kind
  test_receiver_rejects_malformed_command
  test_units_allow_canonical_quarantine_path
  printf 'backup script integration tests passed\n'
}

main "$@"

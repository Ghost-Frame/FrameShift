#!/usr/bin/env bash
# Receives one compressed FrameShift backup stream through a forced SSH command.

set -euo pipefail

: "${BACKUP_ROOT:?BACKUP_ROOT must name the off-host backup directory}"

# Rejects commands other than a single, safely named FrameShift backup upload.
parse_upload_command() {
  local action=""
  local kind=""
  local timestamp=""
  local extra=""

  read -r action kind timestamp extra <<<"${SSH_ORIGINAL_COMMAND:-}"
  if [[ "$action" != "put" || -n "$extra" ]]; then
    echo "expected: put <postgres|objects|manifest> <UTC timestamp>" >&2
    return 64
  fi
  if [[ ! "$kind" =~ ^(postgres|objects|manifest)$ ]]; then
    echo "invalid backup kind" >&2
    return 64
  fi
  if [[ ! "$timestamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
    echo "invalid backup timestamp" >&2
    return 64
  fi

  printf '%s\n%s\n' "$kind" "$timestamp"
}

# Maps a validated backup kind to its immutable filename suffix.
backup_suffix() {
  case "$1" in
    postgres) printf '%s\n' 'postgres.dump.gz' ;;
    objects) printf '%s\n' 'objects.tar.gz' ;;
    manifest) printf '%s\n' 'manifest.txt' ;;
  esac
}

# Writes stdin atomically and emits the final SHA-256 receipt.
receive_backup() {
  local kind="$1"
  local timestamp="$2"
  local suffix
  local filename
  local partial
  local checksum_partial

  suffix="$(backup_suffix "$kind")"
  filename="frameshift-${timestamp}-${suffix}"
  partial="$BACKUP_ROOT/.${filename}.partial"
  checksum_partial="${partial}.sha256"

  install -d -m 0700 "$BACKUP_ROOT"
  umask 077
  test ! -e "$BACKUP_ROOT/$filename"
  test ! -e "$partial"
  cat >"$partial"
  test -s "$partial"
  sha256sum "$partial" | sed "s#  $partial#  $filename#" >"$checksum_partial"
  mv "$partial" "$BACKUP_ROOT/$filename"
  mv "$checksum_partial" "$BACKUP_ROOT/${filename}.sha256"
  cat "$BACKUP_ROOT/${filename}.sha256"
}

parsed_upload="$(parse_upload_command)"
mapfile -t upload <<<"$parsed_upload"
receive_backup "${upload[0]}" "${upload[1]}"

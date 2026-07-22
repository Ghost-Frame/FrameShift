#!/usr/bin/env bash
# Streams PostgreSQL and filesystem-object backups to a restricted SSH receiver.

set -euo pipefail

: "${SERVER_ENV_FILE:=/etc/frameshift/frameshift.env}"
: "${BACKUP_ENV_FILE:=/etc/frameshift/backup.env}"

# Loads one root-owned environment file without printing secret values.
load_environment() {
  local file="$1"

  if [[ ! -r "$file" ]]; then
    echo "required environment file is unreadable: $file" >&2
    return 66
  fi
  set -a
  # shellcheck disable=SC1090
  source "$file"
  set +a
}

# Streams stdin to the restricted remote receiver and returns its checksum receipt.
send_backup() {
  local kind="$1"
  local timestamp="$2"

  ssh \
    -i "$BACKUP_SSH_KEY" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$BACKUP_KNOWN_HOSTS_FILE" \
    -o ConnectTimeout=20 \
    "$BACKUP_SSH_TARGET" \
    "put $kind $timestamp"
}

# Produces a deterministic text manifest tying one backup set together.
backup_manifest() {
  local timestamp="$1"
  local postgres_receipt="$2"
  local objects_receipt="$3"

  printf 'format=frameshift-backup-v1\n'
  printf 'created_at=%s\n' "$timestamp"
  printf 'postgres=%s\n' "$postgres_receipt"
  printf 'objects=%s\n' "$objects_receipt"
}

# Creates and transmits one complete backup set without retaining archives locally.
main() {
  local timestamp
  local postgres_receipt
  local objects_receipt

  load_environment "$SERVER_ENV_FILE"
  load_environment "$BACKUP_ENV_FILE"
  : "${POSTGRES_URL:?POSTGRES_URL is required}"
  : "${OBJECT_STORE_ROOT:?OBJECT_STORE_ROOT is required}"
  : "${BACKUP_SSH_KEY:?BACKUP_SSH_KEY is required}"
  : "${BACKUP_SSH_TARGET:?BACKUP_SSH_TARGET is required}"
  : "${BACKUP_KNOWN_HOSTS_FILE:?BACKUP_KNOWN_HOSTS_FILE is required}"

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  postgres_receipt="$(PGDATABASE="$POSTGRES_URL" pg_dump \
    --format=custom \
    --no-owner \
    --no-privileges \
    | gzip -n \
    | send_backup postgres "$timestamp")"
  objects_receipt="$(tar \
    --create \
    --file=- \
    --directory="$(dirname "$OBJECT_STORE_ROOT")" \
    "$(basename "$OBJECT_STORE_ROOT")" \
    | gzip -n \
    | send_backup objects "$timestamp")"
  backup_manifest "$timestamp" "$postgres_receipt" "$objects_receipt" \
    | send_backup manifest "$timestamp"
}

main "$@"

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
    -p "$BACKUP_SSH_PORT" \
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

# Produces a deterministic v2 manifest that includes the quarantine archive.
backup_manifest_v2() {
  local timestamp="$1"
  local postgres_receipt="$2"
  local objects_receipt="$3"
  local quarantine_receipt="$4"

  printf 'format=frameshift-backup-v2\n'
  printf 'created_at=%s\n' "$timestamp"
  printf 'postgres=%s\n' "$postgres_receipt"
  printf 'objects=%s\n' "$objects_receipt"
  printf 'quarantine=%s\n' "$quarantine_receipt"
}

# Rejects unsupported stores and validates distinct filesystem quarantine roots.
validate_backup_sources() {
  local objects_canonical
  local quarantine_canonical

  case "$OBJECT_STORE_BACKEND" in
    fs) ;;
    r2)
      echo "OBJECT_STORE_BACKEND=r2 is not supported by this backup transport" >&2
      return 64
      ;;
    *)
      echo "invalid OBJECT_STORE_BACKEND: expected fs" >&2
      return 64
      ;;
  esac

  case "$QUARANTINE_OBJECT_STORE_BACKEND" in
    disabled) return 0 ;;
    fs) ;;
    r2)
      echo "QUARANTINE_OBJECT_STORE_BACKEND=r2 is not supported by this backup transport" >&2
      return 64
      ;;
    *)
      echo "invalid QUARANTINE_OBJECT_STORE_BACKEND: expected disabled or fs" >&2
      return 64
      ;;
  esac

  if [[ -z "${OBJECT_STORE_ROOT:-}" \
    || ! -d "$OBJECT_STORE_ROOT" \
    || ! -r "$OBJECT_STORE_ROOT" ]]; then
    echo "OBJECT_STORE_ROOT must name a readable directory for filesystem quarantine backups" >&2
    return 66
  fi
  if [[ -z "${QUARANTINE_OBJECT_STORE_ROOT:-}" \
    || ! -d "$QUARANTINE_OBJECT_STORE_ROOT" \
    || ! -r "$QUARANTINE_OBJECT_STORE_ROOT" ]]; then
    echo "QUARANTINE_OBJECT_STORE_ROOT must name a readable directory" >&2
    return 66
  fi

  objects_canonical="$(realpath -- "$OBJECT_STORE_ROOT")"
  quarantine_canonical="$(realpath -- "$QUARANTINE_OBJECT_STORE_ROOT")"
  if [[ "$objects_canonical" == "$quarantine_canonical" ]]; then
    echo "public and quarantine object-store roots must be distinct" >&2
    return 64
  fi
}

# Creates and transmits one complete backup set without retaining archives locally.
main() {
  local timestamp
  local postgres_receipt
  local objects_receipt
  local quarantine_receipt

  load_environment "$SERVER_ENV_FILE"
  load_environment "$BACKUP_ENV_FILE"
  : "${OBJECT_STORE_BACKEND=fs}"
  : "${QUARANTINE_OBJECT_STORE_BACKEND=disabled}"
  validate_backup_sources
  : "${POSTGRES_URL:?POSTGRES_URL is required}"
  : "${OBJECT_STORE_ROOT:?OBJECT_STORE_ROOT is required}"
  : "${BACKUP_SSH_KEY:?BACKUP_SSH_KEY is required}"
  : "${BACKUP_SSH_TARGET:?BACKUP_SSH_TARGET is required}"
  : "${BACKUP_KNOWN_HOSTS_FILE:?BACKUP_KNOWN_HOSTS_FILE is required}"
  : "${BACKUP_SSH_PORT:=22}"
  if [[ ! "$BACKUP_SSH_PORT" =~ ^[0-9]+$ ]] \
    || (( BACKUP_SSH_PORT < 1 || BACKUP_SSH_PORT > 65535 )); then
    echo "BACKUP_SSH_PORT must be an integer from 1 through 65535" >&2
    return 64
  fi

  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  postgres_receipt="$(pg_dump \
    --dbname="$POSTGRES_URL" \
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
  if [[ "$QUARANTINE_OBJECT_STORE_BACKEND" == "disabled" ]]; then
    backup_manifest "$timestamp" "$postgres_receipt" "$objects_receipt" \
      | send_backup manifest "$timestamp"
    return
  fi

  quarantine_receipt="$(tar \
    --create \
    --file=- \
    --directory="$(dirname "$QUARANTINE_OBJECT_STORE_ROOT")" \
    "$(basename "$QUARANTINE_OBJECT_STORE_ROOT")" \
    | gzip -n \
    | send_backup quarantine "$timestamp")"
  backup_manifest_v2 \
    "$timestamp" \
    "$postgres_receipt" \
    "$objects_receipt" \
    "$quarantine_receipt" \
    | send_backup manifest "$timestamp"
}

main "$@"

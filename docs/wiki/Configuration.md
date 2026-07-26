# Configuration

## Server environment variables

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:3000` | HTTP bind address |
| `POSTGRES_URL` | `""` | PostgreSQL connection URL |
| `OBJECT_STORE_ROOT` | `/tmp/frameshift-objects` | Filesystem object store root |
| `LOG_LEVEL` | `info` | Log filter (trace, debug, info, warn, error) |
| `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `MAX_REQUEST_BYTES` | `1048576` | Maximum request body size (1 MB default) |
| `MAX_SEARCH_LIMIT` | `200` | Maximum `limit` parameter on search endpoints |
| `SHUTDOWN_GRACE` | `30` | Graceful shutdown timeout in seconds |
| `CORS_ALLOWED_ORIGINS` | `""` | Comma-separated CORS origins (empty = no CORS) |

### Object store backend

Set via `OBJECT_STORE_BACKEND`:

- `"fs"` (default) -- Filesystem. Configure with `OBJECT_STORE_ROOT`.
- `"r2"` -- Cloudflare R2 / S3-compatible. Configure with standard AWS SDK variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL`) plus `R2_BUCKET` and optional `R2_PREFIX`, `R2_REGION`.

### Memory backend

Set via `MEMORY_BACKEND`:

- `"none"` (default) -- No memory adapter.
- `"http"` -- HTTP-backed memory. Configure with `MEMORY_HTTP_ENDPOINT`, `MEMORY_HTTP_TOKEN`.
- `"sqlite"` -- Local SQLite FTS5. Auto-creates the database.

### Download tokens

Signed download URLs use HMAC-SHA256 tokens:

| Variable | Default | Description |
|---|---|---|
| `DOWNLOAD_SECRET` | (required for downloads) | 64-char hex HMAC key |
| `DOWNLOAD_TOKEN_TTL` | `300` | Default token lifetime in seconds (5 min) |
| `DOWNLOAD_MAX_TOKEN_TTL` | `1800` | Hard cap on token lifetime (30 min) |
| `DOWNLOAD_RATE_PER_MIN` | (unset) | Per-IP rate limit on the token minting endpoint |

## XDG directories

Frameshift follows the XDG Base Directory Specification:

| Purpose | Variable | Default |
|---|---|---|
| Persona cache and project state | `$XDG_DATA_HOME/frameshift/` | `~/.local/share/frameshift/` |
| Infrastructure overlay | `$XDG_CONFIG_HOME/frameshift/infrastructure.md` | `~/.config/frameshift/infrastructure.md` |

## Project state layout

```
$XDG_DATA_HOME/frameshift/
  cache/<sha256>/                              # Content-addressed pack cache
  projects/<project-id>/
    config.toml                                # Declared dependencies
    lock.toml                                  # Installed versions, hashes, pubkeys
    active                                     # Currently active persona name
    personas/<name>/
      source/                                  # Pack contents
      rendered/{claude,codex,gemini,generic}/   # Per-agent rendered output
      growth.md                                # Legacy growth log (markdown)
      growth.jsonl                             # Structured growth log (JSONL)
    orchestrator/                              # Automate mode state
      automate.json                            # Mode state (on/off, sensitivity)
      automate-lock.json                       # Lock file (present = locked)
      automate-audit.jsonl                     # Transition audit log
      preferences.json                         # Per-persona bias data
```

## Vault

The vault stores identity, authentication, memory configuration, preferences, and per-agent overlay prose. It is encrypted at rest using age with scrypt passphrase recipients.

Vault location: `$XDG_DATA_HOME/frameshift/vault.age`

The vault TOML schema (inside the encrypted file):

```toml
schema_version = 1

[identity]
keypair_pub = "age1..."      # age public key
handle = "alice"             # human-readable name

[auth]
methods = ["piv-yubikey"]   # supported auth methods
unlock = "piv-yubikey"      # preferred unlock method

[preferences]
runtime_mode = "wrapped"     # "wrapped", "rendered", or "both"
publish_intent = "yes"
recovery = "own-backup"

[memory]
backend = "http"
endpoint = "http://..."
auth_method = "api-key"
auth_value_vault_ref = "memory_api_key"

[variables]
api_key_openai = "sk-..."   # arbitrary key-value secrets
github_token = "ghp_..."

[overlays]
"claude.system" = "..."     # per-agent overlay blocks (keyed by "agent.slot")
"gemini.constraints" = "..."
```

Security properties:
- Encrypted at rest with age (scrypt passphrase)
- Atomic writes via temp file + rename
- Plaintext zeroized in memory on drop (via `zeroize` crate)
- File permissions 0o600
- Secrets wrapped in `secrecy::SecretString`

## Daemon

The daemon listens on a Unix domain socket at `$XDG_RUNTIME_DIR/frameshift/daemon.sock` (falls back to `/tmp`) for JSON-RPC 2.0 IPC. Stale sockets from previous runs are removed on startup.

RPC methods: `project_id`, `install`, `activate`, `sync`, `gc`, `grow.append`, `shutdown`.

The daemon integrates a file watcher that monitors the project directory. When automate mode is enabled and the mode is not locked, file changes trigger an orchestrator evaluation cycle that may switch the active persona.

## Database

The marketplace catalog uses PostgreSQL via diesel-async with bb8 connection pooling. Migrations are embedded and run automatically on startup.

```
POSTGRES_URL=postgres://user:pass@host:5432/frameshift
```

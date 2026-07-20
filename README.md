<p align="center">
  <img src="personas/assets/banner.png" alt="Frameshift" width="100%" />
</p>

# Frameshift (WIP)

A persona engine for AI coding agents. Install behavioral identities as versioned packs, activate them per-project, and let the engine pick the right one for the task.

**Status:** The CLI, pack system, orchestrator, watch daemon, marketplace server, and web frontend all work. You can clone this repo and use the personas today via the CLI, or publish and browse packs against the live marketplace.

**Marketplace:** [frameshift.syntheos.dev](https://frameshift.syntheos.dev/) -- browse, search, and install published persona packs; the same registry the CLI talks to.

**Desktop app:** [download.frameshift.syntheos.dev](https://download.frameshift.syntheos.dev/) -- a proprietary companion app for browsing the marketplace and managing personas with one click. This repo is the engine it drives; the app ships separately with Ed25519-signed self-updates.

Personas are not instruction lists. They are complete behavioral frames -- identity, rules, skills, operating posture -- that survive long sessions, surprising inputs, and the slow drift that turns careful agents into sloppy ones around turn 200. Same model, different frame.

## Quickstart

```bash
# Install + activate + render in one shot:
frameshift use cryptographic --from ./personas

# Or step by step:
frameshift install cryptographic@0.1.0 --from-path ./personas/cryptographic
frameshift activate cryptographic
```

## Automate mode

Automate mode picks the persona for you. The engine classifies your task, scores every installed persona against the project context, and switches when the domain shifts.

```bash
# Turn on for this project:
frameshift automate on

# With a sensitivity dial (0.0 = stable, 1.0 = responsive):
frameshift automate on --sensitivity 0.7

# Check current state:
frameshift automate status
```

The selection pipeline scores four components: language overlap (how well the persona's language set matches your project), lexical match (IDF-weighted task token hits against persona keywords), intent alignment (10-category task classification), and capability fit. Scores blend into a ranked list with confidence values.

### Intent classification

The engine classifies task descriptions into one of ten intents: Implementation, Debugging, Review, Security, Writing, Ops, Testing, Refactoring, Performance, and Design. Personas declare which intents they handle best. A persona built for debugging scores higher when the task looks like debugging.

### Selection output

```bash
# Table format (default):
frameshift select --task "debug a rust compilation error" --library ~/.local/share/frameshift/personas

# Structured JSON for programmatic consumption or LLM reranking:
frameshift select --task "debug a rust compilation error" --library ~/.local/share/frameshift/personas --format json
```

JSON output includes the full context snapshot (detected languages, frameworks, inferred intent), per-candidate component scores, matched tokens, and rationale. Host LLMs can rerank using this data.

### Feedback loop

When the engine picks wrong, record the override. The engine adjusts per-persona bias for future selections, with optional intent context and time decay.

```bash
frameshift feedback --auto-pick web-designer --chosen rust --intent debugging
```

## How it works

Frameshift takes a typed persona definition, compiles it into the instruction file each agent expects, and distributes it as a signed, content-addressed pack that installs into a central store outside your project tree.

### Packs

A persona ships as a **pack**: a `pack.toml` manifest plus the persona's behavioral content. The manifest carries identity and contract metadata:

```toml
schema_version = 1
name = "cryptographic"
version = "0.1.0"
author_handle = "ghost-frame"
author_pubkey = "1a2b3c..."  # 64 hex chars (Ed25519 verifying key)
license = "Elastic-2.0"
description = "Specification-anchored cryptographic implementation"
tags = ["security", "rust"]

[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash"]
network_egress = false
filesystem_scope = "project-only"
memory_required = "none"
```

`description` and `tags` feed registry search; `capability_manifest` declares the tools, network egress, filesystem scope, and memory requirement the persona expects (see Capabilities and Memory below). `extends` and `mixin` drive composition. `parent_hash` tracks version lineage; `conformance_baseline` feeds the install-time regression gate (see Conformance below).

### Content addressing and signatures

Every pack has a **canonical hash**: a SHA-256 computed from its files by normalizing each relative path (NFC, forward slashes), sorting byte-lexicographically, and hashing `path \0 length \0 content \0` for each. Because it is derived from the directory's logical contents, the canonical hash is independent of how the pack is later archived or compressed -- two byte-identical pack directories always produce the same hash. This is the pack's identity and the exact value an author signs.

Signing is Ed25519 over that 32-byte hash; the signature travels alongside the pack, never inside the tarball. On the wire the registry addresses the compressed `.tar.gz` by a second hash (the SHA-256 of the archive bytes), which the client checks on download before it extracts anything.

### Trust: handle-bound keys, no central authority

There is no central signing authority. An author **claims a handle** (e.g. `ghost-frame`) with a signed request, and the registry binds that handle to the key that signed it, first-claim-wins. Key rotation must be signed by the current key -- the old key authorizes its own replacement. At publish, the server checks that the live signer owns the handle and that the pack signature verifies against that registered key. On install from the registry, the client verifies the pack signature against the key in the **registry's record** for that version, not the key embedded in the manifest, so a tampered manifest cannot smuggle in a different key. Installing directly from a local path verifies a signature if one is present, and installs unsigned local packs as-is. Registered authors are publicly listable via `GET /v1/authors`.

### Downloads

`frameshift install` fetches pack bytes from the direct, unauthenticated `GET /v1/packs/{name}/versions/{version}/pack` route -- this is the supported download path today. The server also implements a signed-download flow: `POST .../download-url` mints a short-lived, HMAC-signed `/dl/{hash}` URL (gated on the `DOWNLOAD_SECRET` env var, disabled when it is unset). That flow is fully built and tested server-side but has no caller yet in the CLI or client, so treat it as experimental / not-yet-default until something mints and follows those URLs.

### Admin

The registry server exposes one operator endpoint: `POST /v1/admin/packs/{name}/{version}/tombstone`, which marks a published version as removed from public availability. Like the handle-claim and rotation calls, it requires a signed request; the signer's key must also appear on `FRAMESHIFT_ADMIN_PUBKEYS`, a separate comma-separated allowlist of Ed25519 public keys. An empty allowlist disables the endpoint outright (`404`, indistinguishable from an unmapped route); a signed request from a key not on the list gets `403`. No CLI or client command calls this endpoint today -- it's reached directly.

### Install and the central store

`frameshift install` resolves a pack (from the registry, or `--from-path`), verifies it, and materializes it into a central store -- your project tree is never written to. The project is keyed by `project-id = sha256(realpath(project_root))`, so the same directory always maps to the same state regardless of how you path to it.

All state lives under `$XDG_DATA_HOME/frameshift/`:

```
cache/<canonical-hash>/                      Content-addressed pack cache (shared across projects)
identity/ed25519-signing-key.bin             Your managed author signing key (mode 0600)
projects/<project-id>/
  config.toml                                Declared dependencies, telemetry opt-in, memory adapter
  lock.toml                                  Exact versions, hashes, author pubkeys
  active                                     Name of the currently active persona
  automate.json  automate-prefs.json         Automate mode + learned selection biases
  automate-audit.jsonl  automate-lock.json   Switch audit log + lock marker
  selection-history.jsonl                    Local record of past selections
  personas/<name>/
    source/                                  The pack's own files
    rendered/{claude,codex,gemini,generic}/  Per-agent rendered output
    growth.md  growth.jsonl                  Append-only growth log: markdown + JSONL
```

The lockfile records each installed persona as name, version, author handle, author pubkey, and canonical hash. Re-running `install`/`sync` rebuilds the per-project `personas/` tree from the content-addressed cache to match the lockfile.

### Conformance

A pack's `pack.toml` can ship a `[conformance_baseline]` -- a score from 0.0 to 1.0, plus the hash of the conformance bundle it was measured against. When `install` would overwrite an already-installed version of the same persona in the current project, the client compares the incoming pack's baseline against the installed one, without re-running any tests:

- **Pass** -- the incoming score meets or exceeds the installed score.
- **Regression** -- the incoming score is lower. Warn-only; the install proceeds.
- **MissingBaseline** -- either side ships no baseline. Non-fatal; baselines are optional.
- **InvalidScore** -- a score is non-finite or outside 0.0-1.0. Warn-only.
- **IntegrityFailure** -- the incoming pack's declared `bundle_hash` doesn't match the hash of its own shipped conformance bundle, or it ships none at all. This **hard-blocks the install** -- an unverifiable score can't be trusted regardless of what it claims. Override with `FRAMESHIFT_ALLOW_CONFORMANCE_INTEGRITY_FAILURE=1`.

A fresh install of a persona with no prior version in the project skips the comparison entirely. `frameshift verify` (see CLI, below) is what produces a baseline in the first place: it runs a persona's conformance bundle through a runner and scores the results.

### Rendering: one source, per-agent outputs

A persona's typed source is four TOML files -- `persona.toml` (identity, voice, anchors), `rules.toml`, `skills.toml`, and `patterns.toml`. Rules carry a **layer**: L1 (non-negotiable invariants), L2 (contextual defaults, overridable with explicit justification), L3 (preferences).

Rendering projects that source into Markdown, once per agent target, writing the file each agent expects into `rendered/<target>/`: `CLAUDE.md` for Claude, `AGENTS.md` for Codex and generic, `GEMINI.md` for Gemini. The targets differ in which sections they carry -- Claude and generic get the full document, Codex omits the Design Notes and Safety-Layer sections, Gemini omits Design Notes -- so the same source produces the idiom each agent reads best.

### Composition: extends and mixins

A pack can `extends` a single base persona and `mixin` a list of others. Composition merges in a fixed order -- base, then each mixin in turn, then the persona itself -- with later layers overriding earlier ones by rule or skill id (last write wins). One invariant is protected: a mixin can never override a base's **L1** rule, and a persona can override an inherited L1 rule only by explicitly opting in. A missing base or an illegal L1 override fails the install. Bases and mixins are resolved from the packs already installed in the same project.

### Capabilities

Each pack's `capability_manifest` declares the tools it expects, whether it needs network egress, its filesystem scope, and its memory requirement. Over MCP, Frameshift surfaces this contract as **advisory**: the `frameshift_capabilities` tool annotates a proposed tool list against the active persona's declared tools. It never blocks or hides the host agent's own tools -- the manifest names agent-side tools (Read, Bash, ...), a separate namespace from Frameshift's own MCP tools -- it only reports the contract.

### Memory

A persona can declare a memory requirement in its manifest, and it is enforced at activation: a persona with `memory_required = "hard"` refuses to activate unless the project declares a memory adapter (a `[memory]` table in the project's central `config.toml`), and a `"soft"` requirement activates with a warning. Frameshift defines a pluggable `MemoryAdapter` (store, search, recall, list, forget, health) with backends for HTTP APIs and local SQLite full-text search. Any knowledge system exposing those operations works; [Kleos](https://github.com/Ghost-Frame/Kleos) is the reference integration. The registry server can be configured with a backend via `MEMORY_BACKEND` and reports its status at `/v1/memory/health`.

### Growth

Each persona keeps an append-only local growth log -- things learned, mistakes caught, patterns discovered over a working session. Entries are dual-written to the legacy `personas/<name>/growth.md` and a structured `growth.jsonl`; `grow log` and `grow summary` read the structured form back.

```bash
frameshift grow append --persona rust --text "orphan rules prevent implementing foreign traits on foreign types"
frameshift grow log --persona rust --limit 5
frameshift grow summary --persona rust --scope project
```

### Tokens and the vault

A pack can ship a `pack.template.toml` manifest declaring `{{token}}` placeholders its markdown uses -- personal values like how the agent should address you that belong to the user, not the pack:

```toml
[tokens.principal_address]
type = "string"
required = true
description = "How the agent should address you"
```

Token values live in a per-project **vault**: a single age-encrypted file in the central store (never in the project root, never in the pack). When install/activate/use/sync write a persona's `rendered/<target>/` outputs, every `{{token}}` is substituted from the vault (the separate `frameshift render` debug command renders typed source directly and does not substitute tokens). A missing `required = true` token fails the render with one error naming every missing token; an optional token without a value keeps its literal `{{name}}` placeholder. Packs that ship no `pack.template.toml` -- every pack today -- render byte-identically to how they always have; the vault is never opened for them.

The vault passphrase comes from `FRAMESHIFT_VAULT_PASSPHRASE`, or a hidden interactive prompt when the CLI runs in a terminal. Only the CLI ever prompts. The daemon and MCP server resolve the passphrase from the environment variable alone: rendering a templated pack there without it set fails with an error rather than degrading silently (packs without `pack.template.toml` are unaffected either way). There is no built-in passphrase recovery -- losing the passphrase means losing the vault's contents, so keep your own backup.

```bash
frameshift vault init                     # create this project's empty vault
frameshift vault set principal_address    # prompts for the value, hidden
frameshift vault list                     # keys only, never values
```

### Interfaces

The same selection engine backs every surface:

- **CLI** -- `frameshift <command>` (see below).
- **Stdio MCP server** -- a JSON-RPC server exposing tools (install, activate, list, select, use, automate, prefs, grow, capabilities, search) and prompts (`active_persona`, `select_persona`, `automate_status`) as slash commands in any MCP-capable agent.
- **Watch daemon** -- an optional background service over a peer-authenticated Unix socket, offering install/activate/sync/gc operations to editor integrations.
- **Registry / marketplace HTTP server** -- publish, search, download, and author/handle registration.

Automate mode itself is applied by the host integration: a session hook (or equivalent) reads the per-project automate flag, calls `frameshift select` for the current task, and activates the best-fit persona.

### Semantic selection

Selection blends language, lexical, intent, capability, and context signals. Built with the optional `embeddings` cargo feature, it adds a semantic channel: a local sentence-embedding model (all-MiniLM-L6-v2 on pure-Rust [candle](https://github.com/huggingface/candle), ~23 MB, downloaded on first use and cached) scores the task description against each persona's description and keywords by cosine similarity. The bonus is additive and capped -- it can lift a meaning-matching persona, never penalize one -- and everything degrades to the lexical channels when the feature is off or the model is unavailable. Default builds ship none of the ML stack.

## CLI

Persona lifecycle:

```
frameshift install <name>[@<version>] [--from-path <dir>]  Install a pack (a bare name resolves the latest registry version)
frameshift uninstall <persona>                             Remove a persona from this project (cache is kept for gc)
frameshift activate <name>                                 Set the active persona for this project
frameshift use <name> --from <library>                     Install + activate + print rendered output
frameshift list                                            List installed personas and mark the active one
frameshift sync                                            Reconcile the central store with the lockfile
frameshift gc                                              Remove unreferenced cache entries
frameshift migrate                                         Move legacy files into the central store (also migrates growth logs to JSONL)
```

Selection and automate mode:

```
frameshift select [--task TEXT] [--library DIR] [--format table|json]   Rank personas by score/confidence/rationale
frameshift automate on [--sensitivity 0.0-1.0]                          Enable automatic persona switching
frameshift automate off | status | lock | unlock                        Disable / inspect / pin / unpin
frameshift feedback --chosen <name> [--auto-pick <name>]                Record a selection override
           [--intent <intent>] [--reason <text>]
frameshift prefs show                                                   View current per-persona bias values
frameshift prefs bump <persona>                                         Increase a persona's bias
frameshift prefs decay <persona>                                        Decrease a persona's bias
frameshift prefs reset                                                  Clear all recorded preferences
```

Vault and project config:

```
frameshift vault init                                    Create this project's vault (refuses if one exists)
frameshift vault set <key> [--value <v>]                 Set a token value (prompts hidden when --value is omitted;
                                                         prefer the prompt -- --value lands in shell history)
frameshift vault get <key>                               Print a token's raw value
frameshift vault rm <key>                                Remove a token
frameshift vault list                                    List token keys (never values)
frameshift config get <key>                              Print a key from the project's central config.toml
frameshift config set <key> <value>                      Set a key (e.g. telemetry_opt_in true)
```

Authoring and registry:

```
frameshift rule add <persona> --id <id> --layer <L1|L2|L3> --text <text>   Add a rule to a persona
frameshift rule remove <persona> --id <id>                                 Remove a rule
frameshift skill add <persona> --id <id> --text <when>                     Add a skill entry to a persona
frameshift skill remove <persona> --id <id>                                Remove a skill entry
frameshift grow append --persona <name> --text <text>                      Append to a persona's growth log
frameshift grow log --persona <name> [--limit <n>]                         Show recent structured growth entries (default limit: 10)
frameshift grow summary --persona <name> [--scope project|global]          Summarize growth entries (default scope: project)
frameshift diff <a> <b>                                                    Semantic diff between two personas
frameshift render <persona>                                                Render persona source to markdown
frameshift verify (--persona <name> | --bundle <dir>)                      Run conformance checks (exactly one of the two)
           [--runner mock|cli] [--model <name>] [--threshold <0.0-1.0>]
frameshift register --server <url> --handle <handle> [--display-name <name>]   Claim an author handle
frameshift publish --persona <name> [--out <dir>]                          Build a persona pack (add --server + --handle to sign and upload)
           [--server <url> --handle <handle>]
frameshift search [QUERY] [--tag <tag>] [--limit <n>]                      Search the registry
frameshift project-id                                                      Print the hashed project ID
```

`verify` defaults to `--runner mock` (canned, offline responses, used by CI) with `--threshold 0.5`; pass `--runner cli` to drive the subscription-backed `agy` runner against `--model` (default `Gemini 3.1 Pro (High)`), which needs a logged-in `agy`. `publish` writes the pack to `--out` (default `publish-output/<persona>`) unconditionally; the upload step only runs when `--server` is set, and `--handle` is then required.

## What this repo contains

- `crates/` -- Rust workspace: CLI, client engine, pack tooling, composition, conformance, catalog, memory, vault, object storage, HTTP server, MCP server, watch daemon, orchestrator, embeddings, growth
- `personas/` -- pack manifests for the persona library

## Building

Requires `libpq` (the PostgreSQL client library) for the diesel/pq-sys-backed catalog crate -- install it before building the workspace:

```bash
# Debian/Ubuntu
sudo apt-get install libpq-dev

# macOS
brew install libpq
```

```bash
cargo build
cargo test
```

To include the semantic-selection channel (downloads a ~23 MB embedding model on first use):

```bash
cargo build -p frameshift-cli --features embeddings
```

### Running from source

```bash
cargo run -p frameshift-cli -- use cryptographic --from ./personas
cargo run -p frameshift-cli -- select --task "optimize a hot loop" --format json
```

## Configuration

### Server

All variables are read with no prefix (e.g. `BIND_ADDR`, not `FRAMESHIFT_BIND_ADDR`) -- except `FRAMESHIFT_ADMIN_PUBKEYS`, deliberately prefixed so it can't be confused with an unrelated `ADMIN_PUBKEYS` some other tool in the deployment might own; see `crates/frameshift-server/src/config.rs` for the authoritative parser.

| Variable | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:3000` | HTTP bind address |
| `POSTGRES_URL` | `""` | PostgreSQL connection URL (production must override) |
| `OBJECT_STORE_ROOT` | `/tmp/frameshift-objects` | Filesystem object store root |
| `LOG_LEVEL` | `info` | `tracing` subscriber filter string |
| `LOG_FORMAT` | `text` | `text` or `json` |
| `MAX_REQUEST_BYTES` | `1048576` | Max request body size |
| `MAX_SEARCH_LIMIT` | `200` | Max search `limit` |
| `SHUTDOWN_GRACE` | `30` | Grace period in seconds |
| `CORS_ALLOWED_ORIGINS` | `""` | Comma-separated allowed CORS origins; empty disables CORS |
| `DOWNLOAD_SECRET` | `""` | 64-char hex (32 bytes) HMAC key for signed download URLs; empty disables the signed-download endpoints |
| `DOWNLOAD_TOKEN_TTL` | `300` | Default TTL (seconds) for newly minted download tokens |
| `DOWNLOAD_MAX_TOKEN_TTL` | `1800` | Hard cap (seconds) on token TTL accepted by the verifier |
| `DOWNLOAD_RATE_PER_MIN` | `10` | Per-IP rate limit on the mint endpoint (requests/minute); `0` disables |
| `OBJECT_STORE_BACKEND` | `fs` | `fs` (filesystem) or `r2` (S3-compatible / Cloudflare R2) |
| `R2_ENDPOINT` | `""` | S3 endpoint URL for R2 (required when backend is `r2`) |
| `R2_BUCKET` | `""` | Bucket name (required when backend is `r2`) |
| `R2_PREFIX` | `objects` | Key prefix for pack blobs inside the bucket |
| `R2_REGION` | `auto` | S3 region (R2 always uses `auto`) |
| `R2_ACCESS_KEY_ID` | `""` | Access key ID for the bucket |
| `R2_SECRET_ACCESS_KEY` | `""` | Secret access key |
| `TRUST_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate-limit key extraction; set `true` only behind a trusted proxy |
| `SIGNED_REQUEST_MAX_SKEW_SECS` | `300` | Max clock skew (seconds) allowed between a signed write request's timestamp and server time |
| `FRAMESHIFT_ADMIN_PUBKEYS` | `""` | Comma-separated base64url-no-pad Ed25519 public keys allowed to call `/v1/admin/*` endpoints; empty disables all admin endpoints (404) |
| `MEMORY_BACKEND` | `none` | `none`, `http`, or `sqlite` |
| `MEMORY_HTTP_ENDPOINT` | `""` | Base URL for the HTTP memory endpoint; used when `MEMORY_BACKEND=http` |
| `MEMORY_HTTP_AUTH` | `none` | `none` or `bearer:<token>`; used when `MEMORY_BACKEND=http` |
| `MEMORY_HTTP_TIMEOUT_SECS` | `30` | Per-attempt request timeout for the HTTP memory adapter |
| `MEMORY_SQLITE_PATH` | `""` | Path to the SQLite database file; required when `MEMORY_BACKEND=sqlite` |

## License

Elastic License 2.0. See [LICENSE](LICENSE) for details.

### Commercial licensing

The Elastic License 2.0 prohibits offering Frameshift to third parties as a
hosted or managed service. To sell, host, or distribute Frameshift on your own
platform, contact us for a commercial license: support@syntheos.dev.

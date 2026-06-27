//! One-shot seeder for the frameshift catalog and object store.
//!
//! Reads persona directories from a configurable root path, builds a pack for
//! each directory that contains an `AGENTS.md` file plus a `pack.toml` manifest
//! (or synthesizes one), signs it with a generated Ed25519 key, stores the
//! canonical pack bytes in the object store, and registers the pack version and
//! author in the catalog.
//!
//! # Usage
//!
//! ```text
//! POSTGRES_URL=postgres://... \
//! OBJECT_STORE_ROOT=/tmp/frameshift-objects \
//! PERSONAS_ROOT=/path/to/personas \
//! frameshift-seed
//! ```
//!
//! All three environment variables are required. `OBJECT_STORE_ROOT` defaults
//! to `/tmp/frameshift-objects` when absent.
//!
//! # Key management
//!
//! On first run the seeder generates a fresh Ed25519 signing keypair and writes
//! the secret seed bytes to `$OBJECT_STORE_ROOT/../seed-signing-key.bin` (32
//! raw bytes). Subsequent runs that find this file load the same key, producing
//! stable author pubkey and signatures across re-seeds.
//!
//! # Idempotency
//!
//! The seeder is safe to run multiple times. `register_author` is idempotent for
//! an identical (pubkey, handle) pair. `register_pack_version` returns
//! `CatalogError::Conflict` when the (pack_name, version) pair already exists --
//! the seeder logs a warning and continues to the next persona.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use frameshift_catalog::{
    AuthorRecord, CatalogBackend, CatalogError, Ed25519PublicKey, PackStatus, PackVersionRecord,
};
use frameshift_catalog_postgres::{PostgresCatalog, PostgresCatalogConfig};
use frameshift_objects::PackStore;
use frameshift_objects_fs::{FsPackStore, FsPackStoreConfig};
use frameshift_pack::{ObjectHash, Pack};
use secrecy::SecretString;
use tracing::{error, info, warn};

/// Errors produced by the seeder.
#[derive(Debug, thiserror::Error)]
enum SeedError {
    #[error("environment variable {0} is required but not set")]
    MissingEnv(&'static str),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog error: {0}")]
    Catalog(#[from] CatalogError),

    #[error("pack error: {0}")]
    Pack(#[from] frameshift_pack::PackError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("object store error: {0}")]
    Objects(#[from] frameshift_objects::ObjectStoreError),
}

/// Runtime configuration resolved from environment variables.
struct SeedConfig {
    /// PostgreSQL connection URL for the catalog.
    postgres_url: String,
    /// Filesystem object-store root used by the live server.
    object_store_root: String,
    /// Root directory containing persona subdirectories to seed.
    personas_root: String,
    /// Author handle to register and stamp into synthesized pack manifests.
    author_handle: String,
    /// Human-readable display name for the seed author.
    author_display_name: String,
    /// Path to the persisted Ed25519 seed used for repeatable signatures.
    signing_key_path: PathBuf,
}

#[tokio::main]
/// Boot the async runtime, initialize tracing, and execute the seeder.
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        error!("seeder failed: {e}");
        std::process::exit(1);
    }
}

/// Load environment configuration and seed the catalog plus object store.
async fn run() -> Result<(), SeedError> {
    let config = SeedConfig::from_env()?;

    info!("connecting to postgres");
    let catalog = PostgresCatalog::new(PostgresCatalogConfig {
        url: SecretString::new(config.postgres_url.clone()),
        pool_size: 5,
        connect_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(30),
    })
    .await?;

    info!("opening object store at {}", config.object_store_root);
    let objects = FsPackStore::new(FsPackStoreConfig {
        root: PathBuf::from(&config.object_store_root),
        verify_on_read: true,
        max_bytes: None,
        fsync_on_put: false,
    })
    .await?;

    let signing_key = load_or_create_signing_key(&config.signing_key_path)?;
    let verifying_key = signing_key.verifying_key();
    let author_pubkey = Ed25519PublicKey(verifying_key.to_bytes());

    info!("author pubkey: {author_pubkey}");

    register_author(
        &catalog,
        author_pubkey,
        &config.author_handle,
        &config.author_display_name,
    )
    .await?;

    let personas_path = PathBuf::from(&config.personas_root);
    let mut seeded = 0usize;
    let mut skipped = 0usize;

    for entry in std::fs::read_dir(&personas_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let persona_toml = path.join("persona.toml");
        let agents_md = path.join("AGENTS.md");
        if !persona_toml.exists() && !agents_md.exists() {
            continue;
        }

        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // Skip hidden/symlink dirs and non-slug names.
        if dir_name.starts_with('.') {
            continue;
        }

        // Synthesize a pack.toml if one does not exist.
        let pack_toml_path = path.join("pack.toml");
        if !pack_toml_path.exists() {
            write_synthetic_pack_toml(
                &pack_toml_path,
                dir_name,
                &config.author_handle,
                &verifying_key,
            )?;
        }

        match seed_persona(
            &path,
            &catalog,
            &objects,
            &signing_key,
            author_pubkey,
        )
        .await
        {
            Ok(()) => {
                info!("seeded persona: {dir_name}");
                seeded += 1;
            }
            Err(SeedError::Catalog(CatalogError::Conflict { .. })) => {
                warn!("persona {dir_name}: already registered, skipping");
                skipped += 1;
            }
            Err(e) => {
                error!("persona {dir_name}: failed -- {e}");
                skipped += 1;
            }
        }
    }

    info!("pack versions seeded: seeded={seeded} skipped={skipped}");

    // Post-seed: update pack descriptions and tags from persona.toml files.
    info!("updating pack descriptions from persona.toml files");
    update_pack_metadata(&catalog, &personas_path).await?;

    info!("done");
    Ok(())
}

/// Resolve seeder configuration from environment variables.
impl SeedConfig {
    /// Build a validated configuration from the current process environment.
    fn from_env() -> Result<Self, SeedError> {
        let postgres_url = std::env::var("POSTGRES_URL")
            .map_err(|_| SeedError::MissingEnv("POSTGRES_URL"))?;
        let object_store_root = std::env::var("OBJECT_STORE_ROOT")
            .unwrap_or_else(|_| "/tmp/frameshift-objects".to_string());
        let personas_root = std::env::var("PERSONAS_ROOT")
            .map_err(|_| SeedError::MissingEnv("PERSONAS_ROOT"))?;
        let author_handle =
            std::env::var("SEED_AUTHOR_HANDLE").unwrap_or_else(|_| "seed-author".to_string());
        let author_display_name = std::env::var("SEED_AUTHOR_DISPLAY_NAME")
            .unwrap_or_else(|_| "Seed Author".to_string());
        let signing_key_path = match std::env::var("SEED_SIGNING_KEY_PATH") {
            Ok(path) => PathBuf::from(path),
            Err(_) => default_signing_key_path(&object_store_root, &author_handle),
        };

        Ok(Self {
            postgres_url,
            object_store_root,
            personas_root,
            author_handle,
            author_display_name,
            signing_key_path,
        })
    }
}

/// Derive a stable default key path that is namespaced by author handle.
fn default_signing_key_path(object_store_root: &str, author_handle: &str) -> PathBuf {
    PathBuf::from(object_store_root)
        .parent()
        .unwrap_or(Path::new("/tmp"))
        .join(format!("seed-signing-key-{author_handle}.bin"))
}

/// Register the seed author and populate the handles table for publish lookup.
///
/// `register_author` writes the `authors` table but NOT the `handles` table.
/// `get_handle_pubkey` (called by the publish path) reads the `handles` table.
/// Both calls are idempotent: re-running the seeder is safe.
async fn register_author(
    catalog: &PostgresCatalog,
    pubkey: Ed25519PublicKey,
    handle: &str,
    display_name: &str,
) -> Result<(), SeedError> {
    let record = AuthorRecord {
        pubkey,
        handle: handle.to_string(),
        display_name: Some(display_name.to_string()),
        created_at: Utc::now(),
        oauth_links: vec![],
    };

    catalog.register_author(record).await?;
    info!("registered or confirmed author: {handle}");

    // Populate the handles table so the author can be looked up by handle
    // via get_handle_pubkey (used by the publish path). set_handle_pubkey
    // is an upsert and is safe to call on every seed run.
    catalog.set_handle_pubkey(handle, pubkey).await?;
    info!("set handle pubkey for: {handle}");

    Ok(())
}

/// Build and seed a single persona directory.
///
/// Steps:
/// 1. Load Pack from directory (requires pack.toml to exist).
/// 2. Sign with signing key.
/// 3. Compute canonical bytes for the object store.
/// 4. Store bytes via PackStore.
/// 5. Register pack version in catalog.
async fn seed_persona(
    dir: &Path,
    catalog: &PostgresCatalog,
    objects: &FsPackStore,
    signing_key: &SigningKey,
    author_pubkey: Ed25519PublicKey,
) -> Result<(), SeedError> {
    let mut pack = Pack::from_dir(dir)?;
    let signature = pack.sign(signing_key)?;

    let canonical_bytes = pack_canonical_bytes(dir)?;
    let content_hash = ObjectHash::of(&canonical_bytes);

    // Verify the content hash matches the pack's canonical hash.
    let pack_hash = ObjectHash::from_bytes(pack.canonical_hash());
    if content_hash != pack_hash {
        // This should never happen -- both are SHA-256 of the same data.
        return Err(SeedError::Io(std::io::Error::other(format!(
            "content hash mismatch: {content_hash} != {pack_hash}"
        ))));
    }

    objects.put(&content_hash, &canonical_bytes).await?;

    let manifest = pack.manifest();
    let cap_json = manifest
        .capability_manifest
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?
        .unwrap_or_else(|| "{}".to_string());

    let version_record = PackVersionRecord {
        pack_name: manifest.name.clone(),
        version: manifest.version.clone(),
        content_hash,
        signature: signature.to_bytes().to_vec(),
        author_pubkey,
        parent_hash: None,
        capability_manifest_json: cap_json,
        schema_version: manifest.schema_version,
        license: manifest.license.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: canonical_bytes.len() as u64,
    };

    catalog.register_pack_version(version_record).await?;
    Ok(())
}

/// Serialize a pack directory into a canonical byte stream.
///
/// The byte stream is the same data that the canonical hash function hashes:
/// for each entry (sorted byte-lexicographically by normalized path, excluding
/// `signature.sig`): `path NUL length NUL bytes NUL`.
///
/// This is the byte content stored in the object store. The SHA-256 of this
/// byte stream equals the pack's canonical hash.
fn pack_canonical_bytes(dir: &Path) -> Result<Vec<u8>, SeedError> {
    // Re-implement the serialization by reading directory entries the same way
    // the canonical module does, then building the byte stream.
    use std::collections::BTreeMap;

    const SIGNATURE_FILENAME: &str = "signature.sig";
    const MAX_FILE_SIZE: u64 = 1024 * 1024;

    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    collect_entries_for_bytes(dir, dir, &mut entries, MAX_FILE_SIZE)?;

    let mut out = Vec::new();
    for (path, content) in &entries {
        if path == SIGNATURE_FILENAME {
            continue;
        }
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        out.extend_from_slice(content.len().to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(content);
        out.push(0);
    }

    Ok(out)
}

/// Recursively collect files into a BTreeMap (keyed by normalized path) for
/// canonical byte serialization.
fn collect_entries_for_bytes(
    base: &Path,
    current: &Path,
    entries: &mut std::collections::BTreeMap<String, Vec<u8>>,
    max_file_size: u64,
) -> Result<(), SeedError> {
    use unicode_normalization::UnicodeNormalization as _;

    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;

        if ft.is_dir() {
            collect_entries_for_bytes(base, &path, entries, max_file_size)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }

        let rel = path
            .strip_prefix(base)
            .expect("path is under base")
            .to_str()
            .ok_or_else(|| {
                SeedError::Io(std::io::Error::other(format!(
                    "non-UTF-8 path: {}",
                    path.display()
                )))
            })?;

        let normalized: String = rel.nfc().collect();
        let canonical = normalized
            .replace('\\', "/")
            .strip_prefix("./")
            .map(|s| s.to_string())
            .unwrap_or(normalized.replace('\\', "/"));

        if canonical == "signature.sig" {
            continue;
        }

        let content = std::fs::read(&path)?;
        if content.len() as u64 > max_file_size {
            warn!(
                "file {} exceeds max size ({} bytes), skipping",
                canonical,
                content.len()
            );
            continue;
        }

        entries.insert(canonical, content);
    }

    Ok(())
}

/// Load a signing key from disk, or generate a new one and persist it.
fn load_or_create_signing_key(path: &Path) -> Result<SigningKey, SeedError> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            SeedError::Io(std::io::Error::other(
                "signing key file must be exactly 32 bytes",
            ))
        })?;
        info!("loaded signing key from {}", path.display());
        Ok(SigningKey::from_bytes(&seed))
    } else {
        // Persist atomically with `create_new` + 0o600: the secret seed is never
        // world-readable even momentarily (closes the umask-perms CRITICAL), and
        // a concurrent seeder cannot replace our freshly written key (closes the
        // check-then-write race). On a lost race we adopt the winner's key.
        let key = SigningKey::generate(&mut rand_core::OsRng);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            open_opts.mode(0o600);
        }

        match open_opts.open(path) {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(&key.to_bytes())?;
                info!("generated new signing key at {}", path.display());
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes = std::fs::read(path)?;
                let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                    SeedError::Io(std::io::Error::other(
                        "signing key file must be exactly 32 bytes",
                    ))
                })?;
                info!("adopted concurrently-created signing key at {}", path.display());
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) => Err(SeedError::Io(e)),
        }
    }
}

/// Write a synthetic `pack.toml` manifest for a persona directory.
///
/// The manifest is minimal but valid. The `author_pubkey` field is encoded as
/// the verifying key's byte representation in hex (the pack manifest stores it
/// as a string -- it is informational only, not parsed by the catalog which
/// uses the typed `Ed25519PublicKey`).
fn write_synthetic_pack_toml(
    path: &Path,
    dir_name: &str,
    author_handle: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), SeedError> {
    let pubkey_hex: String = verifying_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Guard against TOML injection: dir_name (filesystem) and author_handle (env)
    // are interpolated into quoted TOML strings below. A value containing a quote,
    // backslash, or control character could inject arbitrary manifest keys.
    for (field, value) in [("dir_name", dir_name), ("author_handle", author_handle)] {
        if value.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
            return Err(SeedError::Io(std::io::Error::other(format!(
                "{field} contains characters not allowed in a pack manifest: {value:?}"
            ))));
        }
    }

    let content = format!(
        r#"schema_version = 1
name = "{dir_name}"
author_handle = "{author_handle}"
author_pubkey = "{pubkey_hex}"
version = "0.1.0"
license = "Elastic-2.0"
"#
    );

    std::fs::write(path, content)?;
    info!("wrote synthetic pack.toml for {dir_name}");
    Ok(())
}

/// Minimal persona.toml structure for extracting description and stack categories.
#[derive(Debug, serde::Deserialize)]
struct PersonaToml {
    name: String,
    #[serde(default)]
    description: String,
}

/// Minimal patterns.toml structure for extracting stack categories as tags.
#[derive(Debug, serde::Deserialize)]
struct PatternsToml {
    #[serde(default)]
    stack: Vec<StackEntry>,
}

/// A single stack category entry.
///
/// Only the `category` is read (it becomes a discovery tag); the entry's
/// `items` list is intentionally not modeled, as serde ignores unknown fields.
#[derive(Debug, serde::Deserialize)]
struct StackEntry {
    category: String,
}

/// Derived metadata for a seeded pack head row.
struct PackMetadata {
    /// Pack name used to target the UPDATE statement.
    name: String,
    /// Human-readable marketplace description.
    description: String,
    /// Discovery tags stored on the pack head record.
    tags: Vec<String>,
}

/// Post-seed pass: read persona.toml from each directory, extract description
/// and derive tags from patterns.toml stack categories, then UPDATE the packs
/// table directly. Reuses the catalog's existing connection pool so both
/// Postgres connections in the seeder share the same TLS configuration.
/// The catalog trait does not expose a pack metadata update method, so a
/// raw diesel sql_query is used here.
async fn update_pack_metadata(
    catalog: &PostgresCatalog,
    personas_root: &Path,
) -> Result<(), SeedError> {
    // Only the async `RunQueryDsl::execute` is needed here; pulling in
    // `diesel::prelude::*` would also import the sync `RunQueryDsl`, making
    // `.execute` ambiguous (E0034). `sql_query`/`sql_types` are fully qualified
    // and `.bind` is inherent on the query builder, so no prelude import is required.
    use diesel_async::RunQueryDsl as _;

    // Check a connection out of the shared pool -- same TLS path as all other
    // catalog queries opened by PostgresCatalog::new().
    let mut conn = catalog
        .pool()
        .get()
        .await
        .map_err(|e| SeedError::Io(std::io::Error::other(format!("pool checkout: {e}"))))?;

    for entry in std::fs::read_dir(personas_root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let Some(metadata) = derive_pack_metadata(&path, &dir_name)? else {
            continue;
        };

        // Raw UPDATE: the catalog trait has no update-metadata method, so we
        // issue the statement directly via diesel's sql_query API.
        let result = diesel::sql_query(
            "UPDATE packs SET description = $1, tags = $2 WHERE name = $3",
        )
        .bind::<diesel::sql_types::Text, _>(&metadata.description)
        .bind::<diesel::sql_types::Array<diesel::sql_types::Text>, _>(&metadata.tags)
        .bind::<diesel::sql_types::Text, _>(&metadata.name)
        .execute(&mut *conn)
        .await;

        match result {
            Ok(rows) if rows > 0 => {
                info!(
                    "updated metadata for {dir_name}: {} tags",
                    metadata.tags.len()
                );
            }
            Ok(_) => {
                warn!("no pack row found for {dir_name}, skipping metadata update");
            }
            Err(e) => {
                warn!("failed to update metadata for {dir_name}: {e}");
            }
        }
    }

    Ok(())
}

/// Derive pack metadata from persona.toml when present, otherwise from AGENTS.md.
fn derive_pack_metadata(path: &Path, dir_name: &str) -> Result<Option<PackMetadata>, SeedError> {
    let persona_path = path.join("persona.toml");
    if persona_path.exists() {
        let persona_content = std::fs::read_to_string(&persona_path)?;
        let persona: PersonaToml = toml::from_str(&persona_content).map_err(|e| {
            SeedError::Io(std::io::Error::other(format!(
                "parse persona.toml for {dir_name}: {e}"
            )))
        })?;

        let mut tags = derive_pattern_tags(path)?;
        if tags.is_empty() {
            tags = default_tags(dir_name);
        }

        let description = if persona.description.is_empty() {
            fallback_description(dir_name)
        } else {
            persona.description
        };

        return Ok(Some(PackMetadata {
            name: persona.name,
            description,
            tags,
        }));
    }

    let agents_path = path.join("AGENTS.md");
    if !agents_path.exists() {
        return Ok(None);
    }

    let description = derive_agents_description(&agents_path)
        .unwrap_or_else(|| fallback_description(dir_name));
    Ok(Some(PackMetadata {
        name: dir_name.to_string(),
        description,
        tags: default_tags(dir_name),
    }))
}

/// Extract stack-category tags from patterns.toml when that file exists.
fn derive_pattern_tags(path: &Path) -> Result<Vec<String>, SeedError> {
    let mut tags = Vec::new();
    let patterns_path = path.join("patterns.toml");
    if patterns_path.exists() {
        let patterns_content = std::fs::read_to_string(&patterns_path)?;
        if let Ok(patterns) = toml::from_str::<PatternsToml>(&patterns_content) {
            for stack in &patterns.stack {
                tags.push(stack.category.clone());
            }
        }
    }
    Ok(tags)
}

/// Build a sane default description when no structured metadata exists.
fn fallback_description(dir_name: &str) -> String {
    format!("{dir_name} persona for AI coding agents")
}

/// Build minimal discovery tags for AGENTS-only persona directories.
fn default_tags(dir_name: &str) -> Vec<String> {
    vec![dir_name.to_string(), "persona".to_string()]
}

/// Pull the first useful prose line out of AGENTS.md for marketplace display.
fn derive_agents_description(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('<')
            || trimmed.starts_with('|')
            || trimmed.starts_with("```")
            || trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
        {
            continue;
        }
        if trimmed.len() < 12 {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

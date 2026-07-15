//! One-shot seeder for the frameshift catalog and object store.
//!
//! Reads persona directories from a configurable root path, builds a pack for
//! each directory that carries a `pack.toml` manifest, a legacy `persona.toml`,
//! or an `AGENTS.md` file. A missing `pack.toml` is synthesized; a `pack.toml`
//! that already exists (as every curated `personas/*` directory does) has its
//! placeholder `author_pubkey` repaired in place so the strict manifest parser
//! can load it. The pack is then signed with the seed Ed25519 key, packaged into
//! a gzipped tar archive stored in the object store, and the pack version and
//! author are registered in the catalog.
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
use frameshift_pack::{ObjectHash, Pack, PackManifest};
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

        if !is_persona_dir(&path) {
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

        let pack_toml_path = path.join("pack.toml");
        if !pack_toml_path.exists() {
            // Synthesize a pack.toml if one does not exist.
            write_synthetic_pack_toml(
                &pack_toml_path,
                dir_name,
                &config.author_handle,
                &verifying_key,
            )?;
        } else {
            // Curated pack.toml files ship with a placeholder `author_pubkey`
            // (e.g. "UNSIGNED") that fails PackManifest's strict 64-hex-char
            // validator. Repair it in place with the real key so `Pack::from_dir`
            // below can parse the manifest; all other fields are left untouched.
            repair_placeholder_author_pubkey(&pack_toml_path, &verifying_key)?;
        }

        match seed_persona(&path, &catalog, &objects, &signing_key, author_pubkey).await {
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
        let postgres_url =
            std::env::var("POSTGRES_URL").map_err(|_| SeedError::MissingEnv("POSTGRES_URL"))?;
        let object_store_root = std::env::var("OBJECT_STORE_ROOT")
            .unwrap_or_else(|_| "/tmp/frameshift-objects".to_string());
        let personas_root =
            std::env::var("PERSONAS_ROOT").map_err(|_| SeedError::MissingEnv("PERSONAS_ROOT"))?;
        let author_handle =
            std::env::var("SEED_AUTHOR_HANDLE").unwrap_or_else(|_| "seed-author".to_string());
        let author_display_name =
            std::env::var("SEED_AUTHOR_DISPLAY_NAME").unwrap_or_else(|_| "Seed Author".to_string());
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

/// Whether a directory looks like a persona pack worth seeding.
///
/// Any of the three marker files is sufficient: `pack.toml` (curated
/// `personas/*` directories in this repo are pack.toml-only by design),
/// a legacy `persona.toml`, or an `AGENTS.md`. `pack.toml` is synthesized
/// from the legacy files when it is the only one absent.
fn is_persona_dir(path: &Path) -> bool {
    path.join("pack.toml").exists()
        || path.join("persona.toml").exists()
        || path.join("AGENTS.md").exists()
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
/// 2. Sign the pack's canonical hash with the signing key.
/// 3. Package the directory into a gzipped tar archive.
/// 4. Store the archive via PackStore (content-addressed by its SHA-256).
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

    // Store the pack as a gzipped tar archive -- the exact format the client's
    // registry install path (`extract_targz`) decompresses. The object-store
    // content_hash addresses these archive bytes and is deliberately independent
    // of the pack's canonical hash (which the signature above still covers).
    // Storing the raw canonical byte stream here instead made every registry
    // install fail with "invalid gzip header".
    let archive_bytes = targz_dir(dir)?;
    let content_hash = ObjectHash::of(&archive_bytes);

    objects.put(&content_hash, &archive_bytes).await?;

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
        license: manifest
            .license
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_string()),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: archive_bytes.len() as u64,
    };

    catalog.register_pack_version(version_record).await?;
    Ok(())
}

/// Package a persona directory into an in-memory gzipped tar archive.
///
/// Files are added at the archive root so the client's `find_pack_root` locates
/// `pack.toml` at the top level; `signature.sig` is never included (the pack
/// signature travels in the catalog record, not the archive), and non-regular
/// files (symlinks, devices) are skipped. This mirrors the publish path's
/// `targz_dir` so the seeder and CLI produce the identical on-the-wire format,
/// and the object-store content hash addresses these archive bytes.
fn targz_dir(dir: &Path) -> Result<Vec<u8>, SeedError> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_dir_files(&mut builder, dir, dir)?;

    let encoder = builder.into_inner()?;
    Ok(encoder.finish()?)
}

/// Recursively append regular files under `current` to `builder`, keyed by their
/// path relative to `base`. Skips `signature.sig` and any non-regular file.
fn append_dir_files<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    base: &Path,
    current: &Path,
) -> Result<(), SeedError> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            append_dir_files(builder, base, &path)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let rel = path.strip_prefix(base).unwrap_or(&path);
        if rel.to_string_lossy() == "signature.sig" {
            continue;
        }
        builder.append_path_with_name(&path, rel)?;
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
                info!(
                    "adopted concurrently-created signing key at {}",
                    path.display()
                );
                Ok(SigningKey::from_bytes(&seed))
            }
            Err(e) => Err(SeedError::Io(e)),
        }
    }
}

/// Encode an Ed25519 verifying key as the 64-lowercase-hex-character string
/// that `PackManifest::author_pubkey` requires.
fn verifying_key_hex(verifying_key: &VerifyingKey) -> String {
    verifying_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `s` matches the strict encoding `PackManifest` requires for
/// `author_pubkey`: exactly 64 lowercase hex characters. Mirrors
/// `frameshift_pack::manifest`'s private validator so the repair check here
/// never disagrees with what the real parser will accept.
fn is_valid_pubkey_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Repair a placeholder `author_pubkey` in an existing `pack.toml`.
///
/// Curated repo personas (`personas/*/pack.toml`) ship with a literal
/// `"UNSIGNED"` placeholder for `author_pubkey` -- fine for humans reading the
/// file, but rejected by `PackManifest`'s deserializer, which requires exactly
/// 64 lowercase hex characters. Left unrepaired, `Pack::from_dir` fails to
/// parse every one of them.
///
/// Curated pack.toml files are hand-written persona content: several carry
/// comments and deliberate key ordering that a parse-and-reserialize round
/// trip through `toml::Value` would destroy (comments dropped, keys
/// reordered). The rewrite is therefore a surgical single-line replacement:
/// only the root-table `author_pubkey = ...` line changes; every other byte
/// of the file is preserved verbatim. A no-op when the existing value already
/// satisfies the strict check; an error when the root table has no
/// `author_pubkey` key at all, since that file needs a human, not a seeder.
fn repair_placeholder_author_pubkey(
    path: &Path,
    verifying_key: &VerifyingKey,
) -> Result<(), SeedError> {
    let content = std::fs::read_to_string(path)?;
    let doc: toml::Value = toml::from_str(&content).map_err(|e| {
        SeedError::Io(std::io::Error::other(format!(
            "parse {} for author_pubkey repair: {e}",
            path.display()
        )))
    })?;

    let already_valid = doc
        .get("author_pubkey")
        .and_then(|v| v.as_str())
        .is_some_and(is_valid_pubkey_hex);
    if already_valid {
        return Ok(());
    }

    let hex = verifying_key_hex(verifying_key);
    let mut in_root_table = true;
    let mut replaced = false;
    let mut rewritten = String::with_capacity(content.len() + 80);
    for line in content.lines() {
        let trimmed = line.trim_start();
        // `author_pubkey` is a root-table key; a same-named key inside a
        // sub-table (however unlikely) must not be touched.
        if trimmed.starts_with('[') {
            in_root_table = false;
        }
        let is_pubkey_line = in_root_table
            && !replaced
            && trimmed
                .strip_prefix("author_pubkey")
                .is_some_and(|rest| rest.trim_start().starts_with('='));
        if is_pubkey_line {
            rewritten.push_str(&format!("author_pubkey = \"{hex}\""));
            replaced = true;
        } else {
            rewritten.push_str(line);
        }
        rewritten.push('\n');
    }
    if !replaced {
        return Err(SeedError::Io(std::io::Error::other(format!(
            "{}: no root-level author_pubkey key found to repair",
            path.display()
        ))));
    }
    if !content.ends_with('\n') {
        rewritten.pop();
    }
    std::fs::write(path, rewritten)?;
    info!("repaired placeholder author_pubkey in {}", path.display());
    Ok(())
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
    let pubkey_hex = verifying_key_hex(verifying_key);

    // Guard against TOML injection: dir_name (filesystem) and author_handle (env)
    // are interpolated into quoted TOML strings below. A value containing a quote,
    // backslash, or control character could inject arbitrary manifest keys.
    for (field, value) in [("dir_name", dir_name), ("author_handle", author_handle)] {
        if value
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
        {
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
/// and derive tags from patterns.toml stack categories, then write both onto
/// the pack head row via [`CatalogBackend::set_pack_metadata`].
async fn update_pack_metadata(
    catalog: &PostgresCatalog,
    personas_root: &Path,
) -> Result<(), SeedError> {
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

        let result = catalog
            .set_pack_metadata(&metadata.name, &metadata.description, &metadata.tags)
            .await;

        match result {
            Ok(()) => {
                info!(
                    "updated metadata for {dir_name}: {} tags",
                    metadata.tags.len()
                );
            }
            Err(CatalogError::NotFound { .. }) => {
                warn!("no pack row found for {dir_name}, skipping metadata update");
            }
            Err(e) => {
                warn!("failed to update metadata for {dir_name}: {e}");
            }
        }
    }

    Ok(())
}

/// Derive pack metadata for the marketplace listing.
///
/// Prefers the pack's own `pack.toml` `description`/`tags` fields -- first-class
/// since commit b75344d and present on every curated `personas/*` manifest --
/// and falls back to the legacy `persona.toml` (description + patterns.toml
/// stack tags) or `AGENTS.md` (first prose line) derivation for packs that
/// predate curated pack.toml metadata.
fn derive_pack_metadata(path: &Path, dir_name: &str) -> Result<Option<PackMetadata>, SeedError> {
    let pack_toml_path = path.join("pack.toml");
    if pack_toml_path.exists() {
        let pack_content = std::fs::read_to_string(&pack_toml_path)?;
        let manifest: PackManifest = toml::from_str(&pack_content).map_err(|e| {
            SeedError::Io(std::io::Error::other(format!(
                "parse pack.toml for {dir_name}: {e}"
            )))
        })?;

        let mut tags = manifest.tags.clone();
        if tags.is_empty() {
            tags = derive_pattern_tags(path)?;
        }
        if tags.is_empty() {
            tags = default_tags(dir_name);
        }

        let description = match manifest.description.filter(|d| !d.is_empty()) {
            Some(d) => d,
            None => derive_legacy_description(path, dir_name),
        };

        return Ok(Some(PackMetadata {
            name: manifest.name,
            description,
            tags,
        }));
    }

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

    let description =
        derive_agents_description(&agents_path).unwrap_or_else(|| fallback_description(dir_name));
    Ok(Some(PackMetadata {
        name: dir_name.to_string(),
        description,
        tags: default_tags(dir_name),
    }))
}

/// Fall back to legacy description sources when a `pack.toml` carries no
/// `description`: the directory's `persona.toml` description, then the first
/// prose line of its `AGENTS.md`, then a generic templated string.
fn derive_legacy_description(path: &Path, dir_name: &str) -> String {
    let persona_path = path.join("persona.toml");
    if let Ok(content) = std::fs::read_to_string(&persona_path) {
        if let Ok(persona) = toml::from_str::<PersonaToml>(&content) {
            if !persona.description.is_empty() {
                return persona.description;
            }
        }
    }

    let agents_path = path.join("AGENTS.md");
    if let Some(description) = derive_agents_description(&agents_path) {
        return description;
    }

    fallback_description(dir_name)
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

/// Unit tests for the seeder's persona gate, pack.toml repair, and
/// metadata derivation.
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    /// A pack.toml fixture shaped exactly like the curated `personas/*`
    /// directories in this repo: pack.toml-only, with the literal
    /// `"UNSIGNED"` author_pubkey placeholder and first-class
    /// description/tags (commit b75344d).
    const CURATED_PACK_TOML: &str = r#"# Curated persona pack manifest.
schema_version = 1
name = "agents"
author_handle = "ghost-frame"
author_pubkey = "UNSIGNED"
version = "0.1.0"
description = "Multi-agent coordination, delegation, and parallel execution workflows."
tags = ["agents", "coordination", "delegation", "parallel"]
license = "Elastic-2.0"

# Capability surface this persona expects from the host agent.
[capability_manifest]
required_tools = ["Read", "Edit", "Write", "Bash", "Grep", "Glob"]
network_egress = false
filesystem_scope = "project-only"
memory_required = "none"
memory_required_ops = []
"#;

    /// Deterministic test keypair (mirrors the pattern used in
    /// `frameshift_pack::pack::tests`).
    fn test_verifying_key() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[7u8; 32]).verifying_key()
    }

    #[test]
    /// A pack.toml-only directory (no persona.toml, no AGENTS.md) must pass
    /// the persona-directory gate -- this is the exact shape of every
    /// `personas/*` directory in the repo.
    fn is_persona_dir_accepts_pack_toml_only() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pack.toml"), CURATED_PACK_TOML).unwrap();
        assert!(is_persona_dir(tmp.path()));
    }

    #[test]
    /// A directory with none of the three marker files is not a persona dir
    /// (this is the shape of `personas/assets/`, which holds only images).
    fn is_persona_dir_rejects_directory_with_no_markers() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("banner.png"), b"not a persona").unwrap();
        assert!(!is_persona_dir(tmp.path()));
    }

    #[test]
    /// The strict-hex check must accept only exactly 64 lowercase hex chars,
    /// matching `frameshift_pack::manifest::deserialize_author_pubkey`.
    fn pubkey_hex_validation_matches_manifest_parser() {
        assert!(!is_valid_pubkey_hex("UNSIGNED"));
        assert!(!is_valid_pubkey_hex(""));
        assert!(!is_valid_pubkey_hex(&"a".repeat(63)));
        assert!(!is_valid_pubkey_hex(&"A".repeat(64))); // uppercase rejected
        assert!(is_valid_pubkey_hex(&"a".repeat(64)));
    }

    #[test]
    /// Repairing a curated pack.toml's placeholder author_pubkey must leave
    /// every other field -- including the first-class description/tags --
    /// untouched, and the result must parse as a valid `PackManifest`.
    fn repair_placeholder_author_pubkey_preserves_curated_fields() {
        let tmp = TempDir::new().unwrap();
        let pack_toml_path = tmp.path().join("pack.toml");
        std::fs::write(&pack_toml_path, CURATED_PACK_TOML).unwrap();

        // Before repair: the strict manifest parser must reject "UNSIGNED".
        let content = std::fs::read_to_string(&pack_toml_path).unwrap();
        assert!(toml::from_str::<PackManifest>(&content).is_err());

        repair_placeholder_author_pubkey(&pack_toml_path, &test_verifying_key()).unwrap();

        let repaired = std::fs::read_to_string(&pack_toml_path).unwrap();
        let manifest: PackManifest = toml::from_str(&repaired)
            .expect("repaired pack.toml must parse as a valid PackManifest");

        assert_eq!(manifest.name, "agents");
        assert_eq!(manifest.author_handle, "ghost-frame");
        assert!(is_valid_pubkey_hex(&manifest.author_pubkey));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Multi-agent coordination, delegation, and parallel execution workflows.")
        );
        assert_eq!(
            manifest.tags,
            vec!["agents", "coordination", "delegation", "parallel"]
        );
        assert_eq!(manifest.license.as_deref(), Some("Elastic-2.0"));
        assert_eq!(
            manifest.capability_manifest.unwrap().required_tools,
            vec!["Read", "Edit", "Write", "Bash", "Grep", "Glob"]
        );
    }

    #[test]
    /// The repair must be a surgical single-line rewrite: comments, blank
    /// lines, key order, and every byte outside the `author_pubkey` line are
    /// hand-written persona content and must survive verbatim (several real
    /// curated `personas/*/pack.toml` files carry comments).
    fn repair_placeholder_author_pubkey_preserves_comments_and_layout() {
        let tmp = TempDir::new().unwrap();
        let pack_toml_path = tmp.path().join("pack.toml");
        std::fs::write(&pack_toml_path, CURATED_PACK_TOML).unwrap();

        repair_placeholder_author_pubkey(&pack_toml_path, &test_verifying_key()).unwrap();

        let repaired = std::fs::read_to_string(&pack_toml_path).unwrap();
        let expected_line = format!(
            "author_pubkey = \"{}\"",
            verifying_key_hex(&test_verifying_key())
        );
        let expected = CURATED_PACK_TOML.replace("author_pubkey = \"UNSIGNED\"", &expected_line);
        assert_eq!(repaired, expected);
    }

    #[test]
    /// A pack.toml with no root-level author_pubkey key at all must fail the
    /// repair loudly rather than have a key silently invented for it.
    fn repair_placeholder_author_pubkey_errors_when_key_missing() {
        let tmp = TempDir::new().unwrap();
        let pack_toml_path = tmp.path().join("pack.toml");
        std::fs::write(
            &pack_toml_path,
            "schema_version = 1\nname = \"x\"\nauthor_handle = \"h\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let err = repair_placeholder_author_pubkey(&pack_toml_path, &test_verifying_key())
            .expect_err("missing author_pubkey key must be an error");
        assert!(err.to_string().contains("author_pubkey"));
    }

    #[test]
    /// A pack.toml whose author_pubkey is already valid hex must be left
    /// byte-for-byte unchanged.
    fn repair_placeholder_author_pubkey_is_noop_when_already_valid() {
        let tmp = TempDir::new().unwrap();
        let pack_toml_path = tmp.path().join("pack.toml");
        let valid_hex = "a".repeat(64);
        let content = format!(
            "schema_version = 1\nname = \"x\"\nauthor_handle = \"h\"\n\
             author_pubkey = \"{valid_hex}\"\nversion = \"0.1.0\"\n"
        );
        std::fs::write(&pack_toml_path, &content).unwrap();

        repair_placeholder_author_pubkey(&pack_toml_path, &test_verifying_key()).unwrap();

        let after = std::fs::read_to_string(&pack_toml_path).unwrap();
        assert_eq!(after, content);
    }

    #[test]
    /// End-to-end: a pack.toml-only persona directory shaped exactly like a
    /// curated `personas/*` entry must survive the full pre-seed pipeline --
    /// gate, pubkey repair, and `Pack::from_dir` + sign -- without the
    /// missing persona.toml/AGENTS.md ever being required.
    fn pack_toml_only_persona_seeds_end_to_end() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pack.toml"), CURATED_PACK_TOML).unwrap();

        // 1. Gate: must be recognized as a persona dir.
        assert!(is_persona_dir(tmp.path()));

        // 2. Repair: placeholder author_pubkey must be fixed in place.
        let pack_toml_path = tmp.path().join("pack.toml");
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        repair_placeholder_author_pubkey(&pack_toml_path, &verifying_key).unwrap();

        // 3. Load: Pack::from_dir must now succeed against the repaired manifest.
        let mut pack = Pack::from_dir(tmp.path()).expect("pack.toml-only persona must load");
        assert_eq!(pack.manifest().name, "agents");

        // 4. Sign: the loaded pack must be signable, exactly as seed_persona does.
        pack.sign(&signing_key).expect("signing must succeed");
        assert!(pack.verify(&verifying_key).is_ok());

        // 5. Archive: the object-store payload must build as a non-empty gzip.
        let bytes = targz_dir(tmp.path()).expect("gzip-tar archive must build");
        assert!(
            bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b,
            "object-store payload must be a gzip stream"
        );

        // 6. Metadata: the marketplace description/tags must come straight from
        //    pack.toml, not from a nonexistent persona.toml/AGENTS.md fallback.
        let metadata = derive_pack_metadata(tmp.path(), "agents")
            .expect("metadata derivation must not error")
            .expect("pack.toml-only dir must yield metadata");
        assert_eq!(metadata.name, "agents");
        assert_eq!(
            metadata.description,
            "Multi-agent coordination, delegation, and parallel execution workflows."
        );
        assert_eq!(
            metadata.tags,
            vec!["agents", "coordination", "delegation", "parallel"]
        );
    }

    #[test]
    /// The object-store payload must be a gzipped tar (not the raw canonical
    /// byte stream): valid gzip, `pack.toml` present at the archive root, and
    /// `signature.sig` excluded. Storing canonical bytes here was the defect
    /// that made every registry install fail with "invalid gzip header".
    fn targz_dir_produces_gzip_with_pack_toml_and_excludes_signature() {
        use flate2::read::GzDecoder;

        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pack.toml"), CURATED_PACK_TOML).unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), b"# body").unwrap();
        std::fs::write(tmp.path().join("signature.sig"), b"SIG").unwrap();

        let archive = targz_dir(tmp.path()).expect("archive must build");
        assert_eq!(&archive[..2], &[0x1f, 0x8b], "must be a gzip stream");

        let mut names = Vec::new();
        let mut ar = tar::Archive::new(GzDecoder::new(std::io::Cursor::new(&archive)));
        for entry in ar.entries().unwrap() {
            let entry = entry.unwrap();
            names.push(entry.path().unwrap().to_string_lossy().into_owned());
        }
        assert!(names.iter().any(|n| n == "pack.toml"), "pack.toml at root");
        assert!(
            names.iter().any(|n| n == "AGENTS.md"),
            "content file present"
        );
        assert!(
            !names.iter().any(|n| n == "signature.sig"),
            "signature.sig must be excluded from the archive"
        );
    }

    #[test]
    /// When a pack.toml carries no description/tags, `derive_pack_metadata`
    /// must fall back to the legacy AGENTS.md derivation rather than
    /// returning an empty description.
    fn derive_pack_metadata_falls_back_to_agents_md_when_pack_toml_has_no_description() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("pack.toml"),
            "schema_version = 1\nname = \"bare\"\nauthor_handle = \"h\"\n\
             author_pubkey = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
             version = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("AGENTS.md"),
            "# Bare Persona\n\nA persona description long enough to pass the filter.\n",
        )
        .unwrap();

        let metadata = derive_pack_metadata(tmp.path(), "bare")
            .unwrap()
            .expect("must yield metadata");
        assert_eq!(metadata.name, "bare");
        assert_eq!(
            metadata.description,
            "A persona description long enough to pass the filter."
        );
        // No tags anywhere -> falls back to the generic default tags.
        assert_eq!(metadata.tags, vec!["bare", "persona"]);
    }
}

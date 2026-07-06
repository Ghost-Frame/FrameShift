/// Cache-backed resolver for `extends`/`mixin` persona specs at render time.
mod compose_support;
mod error;
mod model;
/// Registry publish implementation: pack, sign, and HTTP upload.
mod publish;
/// Registry install implementation: HTTP fetch, extraction, and verification.
mod registry;
/// Persona-selection history (local JSONL) and opt-in telemetry.
mod selection;

pub use error::ClientError;
pub use model::{
    ClientOptions, GcReport, InstallReport, InstallRequest, InstallSource, LockedPersona, Lockfile,
    MemoryConfig, MemoryRequirementStatus, PersonaSpec, ProjectConfig, ProjectPaths, SyncReport,
    SCHEMA_VERSION,
};
pub use publish::PublishOutcome;
pub use registry::{RegistryPackSummary, RegistrySearchQuery, RegistrySearchResult};
pub use selection::{
    SelectionEvent, SelectionTelemetry, SELECTION_HISTORY_FILENAME, TELEMETRY_URL_ENV,
};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::VerifyingKey;
use frameshift_pack::Pack;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Legacy filename written to the project root by pre-WS-1 versions.
/// Detected by the migration shim and moved into the central store.
const LEGACY_CONFIG_FILENAME: &str = "frameshift.toml";
/// Legacy filename written to the project root by pre-WS-1 versions.
const LEGACY_LOCK_FILENAME: &str = "frameshift.lock";
/// Canonical config filename inside the central store: `projects/<id>/config.toml`.
const CENTRAL_CONFIG_FILENAME: &str = "config.toml";
/// Canonical lock filename inside the central store: `projects/<id>/lock.toml`.
const CENTRAL_LOCK_FILENAME: &str = "lock.toml";
const ACTIVE_FILENAME: &str = "active";
/// Env var to override the auto-derived path-hash project_id.
const PROJECT_ID_ENV: &str = "FRAMESHIFT_PROJECT_ID";

const RENDER_TARGETS: [(&str, &str); 4] = [
    ("claude", "CLAUDE.md"),
    ("codex", "AGENTS.md"),
    ("gemini", "GEMINI.md"),
    ("generic", "AGENTS.md"),
];

const RENDER_CANDIDATES: [&str; 4] = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", "README.md"];

/// Core Frameshift engine. Handles install, activate, sync, gc, and rendering.
pub struct Client {
    /// Root of the Frameshift data directory.
    data_root: PathBuf,
    /// Root of the XDG config directory (for infrastructure overlay).
    config_root: Option<PathBuf>,
}

impl Client {
    /// Construct a `Client` from the given options.
    pub fn new(options: ClientOptions) -> Self {
        Self {
            data_root: options.data_root,
            config_root: options.config_root,
        }
    }

    /// Construct a `Client` using the XDG data and config roots resolved from environment variables.
    pub fn with_default_data_root() -> Result<Self, ClientError> {
        Ok(Self::new(ClientOptions {
            data_root: default_data_root()?,
            config_root: Some(default_config_root()?),
        }))
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    /// Load (or create on first use) the managed author Ed25519 signing key from
    /// the central data root. See [`publish::load_or_create_signing_key`].
    pub fn author_signing_key(&self) -> Result<ed25519_dalek::SigningKey, ClientError> {
        publish::load_or_create_signing_key(&self.data_root)
    }

    /// The base64url-no-pad public key string for the managed author key -- the
    /// value the registry registers a handle against.
    pub fn author_pubkey_b64(&self) -> Result<String, ClientError> {
        Ok(publish::public_key_b64(&self.author_signing_key()?))
    }

    /// The lowercase-hex public key string for the managed author key, used to
    /// fill the `author_pubkey` field of a synthesized `pack.toml`.
    pub fn author_pubkey_hex(&self) -> Result<String, ClientError> {
        Ok(publish::public_key_hex(&self.author_signing_key()?))
    }

    /// Register the managed author key under `handle` at `server_url`
    /// (`POST /v1/authors`). Idempotent for the same key+handle; a different
    /// key claiming a taken handle yields [`ClientError::RegistryRejected`] 409.
    pub fn register_author(
        &self,
        server_url: &str,
        handle: &str,
        display_name: Option<&str>,
    ) -> Result<(), ClientError> {
        let key = self.author_signing_key()?;
        publish::register_author(server_url, &key, handle, display_name)
    }

    /// Pack, sign, and upload the pack directory at `pack_dir` to `server_url`
    /// under `author_handle` (`POST /v1/packs`). `pack_dir` must contain a
    /// `pack.toml`. Returns the server's [`PublishOutcome`].
    pub fn publish_pack_dir(
        &self,
        server_url: &str,
        pack_dir: &Path,
        author_handle: &str,
    ) -> Result<PublishOutcome, ClientError> {
        let key = self.author_signing_key()?;
        publish::publish_pack_dir(server_url, &key, pack_dir, author_handle)
    }

    /// Search the registry's pack catalog (`GET /v1/packs`) with optional
    /// query/tag/limit filters. Delegates to [`registry::search_registry`]
    /// against [`registry::registry_base_url`].
    pub fn search_registry(
        &self,
        query: &RegistrySearchQuery,
    ) -> Result<Vec<RegistrySearchResult>, ClientError> {
        registry::search_registry(&registry::registry_base_url(), query)
    }

    /// Resolve the latest published version for a bare pack name
    /// (`GET /v1/packs/{name}`). Used by the CLI `install` command to
    /// expand a version-less spec before installing from the registry.
    pub fn resolve_latest_version(&self, name: &str) -> Result<String, ClientError> {
        registry::resolve_latest_version(name)
    }

    pub fn project_id(&self, project_root: &Path) -> Result<String, ClientError> {
        if let Ok(explicit) = std::env::var(PROJECT_ID_ENV) {
            if !explicit.is_empty() {
                validate_explicit_project_id(&explicit)?;
                return Ok(explicit);
            }
        }

        hashed_project_id(project_root)
    }

    pub fn project_paths(&self, project_root: &Path) -> Result<ProjectPaths, ClientError> {
        let project_id = self.project_id(project_root)?;
        let cache_dir = self.data_root.join("cache");
        let project_state_dir = self.data_root.join("projects").join(&project_id);
        let personas_dir = project_state_dir.join("personas");

        let paths = ProjectPaths {
            project_root: project_root.to_path_buf(),
            project_id,
            config_path: project_state_dir.join(CENTRAL_CONFIG_FILENAME),
            lock_path: project_state_dir.join(CENTRAL_LOCK_FILENAME),
            cache_dir,
            active_path: project_state_dir.join(ACTIVE_FILENAME),
            personas_dir,
            project_state_dir,
        };

        migrate_legacy_project_files(project_root, &paths);
        Ok(paths)
    }

    pub fn install(&self, request: InstallRequest) -> Result<InstallReport, ClientError> {
        ensure_exists(&request.project_root)?;

        let paths = self.project_paths(&request.project_root)?;
        let locked = match &request.source {
            InstallSource::LocalPath(pack_dir) => {
                let pack = Pack::from_dir(pack_dir)?;
                validate_pack_request(&pack, &request.spec)?;
                verify_pack_signature_if_present(&pack)?;
                let hash = pack.canonical_hash_hex();
                let cache_path = paths.cache_dir.join(&hash);
                ensure_cached_pack(pack_dir, &cache_path)?;
                locked_persona_from_pack(&pack)
            }
            InstallSource::Registry => {
                // Fetch, extract, verify, and cache the pack from the HTTP registry.
                install_from_registry(&request.spec, &paths)?
            }
        };

        // Shared tail: upsert into lockfile and materialize project state.
        finish_install(self, &paths, locked)
    }

    pub fn activate(&self, project_root: &Path, persona: &str) -> Result<(), ClientError> {
        let report = self.sync(project_root)?;
        if !report.personas.iter().any(|installed| installed == persona) {
            return Err(ClientError::PersonaNotInstalled(persona.to_string()));
        }

        // Enforce the pack's declared memory contract: a hard requirement
        // refuses to activate when the project declares no memory adapter.
        // Soft requirements are surfaced as warnings by the CLI/MCP callers
        // via `memory_requirement_status`.
        let status = self.memory_requirement_status(project_root, persona)?;
        if status.hard_unmet() {
            return Err(ClientError::MemoryRequirementUnmet {
                persona: persona.to_string(),
                config_path: self.project_paths(project_root)?.config_path,
            });
        }

        let paths = self.project_paths(project_root)?;
        ensure_dir(&paths.project_state_dir)?;
        write_file(&paths.active_path, persona.as_bytes())
    }

    /// Report `persona`'s declared memory requirement against this project's
    /// declared memory adapter.
    ///
    /// The requirement comes from `capability_manifest.memory_required` in the
    /// persona's materialized `source/pack.toml`. A missing manifest file (e.g.
    /// a bare local install) or an absent `capability_manifest` table reports
    /// [`frameshift_pack::MemoryRequirement::None`]; an unreadable or invalid
    /// manifest propagates its error.
    pub fn memory_requirement_status(
        &self,
        project_root: &Path,
        persona: &str,
    ) -> Result<MemoryRequirementStatus, ClientError> {
        let paths = self.project_paths(project_root)?;
        let manifest_path = paths
            .personas_dir
            .join(persona)
            .join("source")
            .join("pack.toml");

        let requirement = match fs::read_to_string(&manifest_path) {
            Ok(raw) => toml::from_str::<frameshift_pack::PackManifest>(&raw)
                .map_err(|source| ClientError::TomlDeserialize {
                    path: manifest_path,
                    source,
                })?
                .capability_manifest
                .map(|cm| cm.memory_required)
                .unwrap_or_default(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                frameshift_pack::MemoryRequirement::None
            }
            Err(source) => {
                return Err(ClientError::Io {
                    path: manifest_path,
                    source,
                })
            }
        };

        let memory_declared = self.project_config(project_root)?.memory.is_some();
        Ok(MemoryRequirementStatus {
            requirement,
            memory_declared,
        })
    }

    /// Remove an installed persona from the project's lockfile and re-materialize
    /// project state.
    ///
    /// Fails with [`ClientError::PersonaNotInstalled`] when the project has no
    /// lockfile yet or the lockfile does not contain `persona`. On success, the
    /// persona is dropped from `lockfile.personas` and
    /// [`Client::materialize_project_state`] is called with the updated
    /// lockfile, which deletes `personas/<persona>` from the central store and
    /// clears the `active` marker file if it pointed at the removed persona.
    /// The content-addressed cache entry is deliberately left in place; use
    /// [`Client::gc`] to reclaim cache entries no longer referenced by any
    /// project's lockfile.
    pub fn uninstall(&self, project_root: &Path, persona: &str) -> Result<(), ClientError> {
        validate_persona_name(persona)?;
        let paths = self.project_paths(project_root)?;

        let Some((_, mut lockfile)) = load_lockfile_with_raw(&paths.lock_path)? else {
            return Err(ClientError::PersonaNotInstalled(persona.to_string()));
        };
        if !lockfile.personas.iter().any(|p| p.name == persona) {
            return Err(ClientError::PersonaNotInstalled(persona.to_string()));
        }

        lockfile.personas.retain(|p| p.name != persona);
        let raw_lock = toml::to_string_pretty(&lockfile)?;
        self.materialize_project_state(&paths, &lockfile, &raw_lock)
    }

    /// Read the central project config (`projects/<id>/config.toml`), returning
    /// `ProjectConfig::default()` when the file does not exist yet.
    pub fn project_config(&self, project_root: &Path) -> Result<ProjectConfig, ClientError> {
        let paths = self.project_paths(project_root)?;
        match fs::read_to_string(&paths.config_path) {
            Ok(raw) => toml::from_str(&raw).map_err(|source| ClientError::TomlDeserialize {
                path: paths.config_path.clone(),
                source,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProjectConfig::default())
            }
            Err(source) => Err(ClientError::Io {
                path: paths.config_path,
                source,
            }),
        }
    }

    /// Append a persona-selection event to the project's local selection history
    /// (`projects/<id>/selection-history.jsonl`). Local-only state that the
    /// intelligent-selection feature learns from; it is never sent anywhere.
    /// `auto` distinguishes automatic selections from explicit user choices, and
    /// `reason` is an optional rationale.
    pub fn record_selection_event(
        &self,
        project_root: &Path,
        persona: &str,
        session: &str,
        auto: bool,
        reason: Option<&str>,
    ) -> Result<(), ClientError> {
        validate_persona_name(persona)?;
        let paths = self.project_paths(project_root)?;
        ensure_dir(&paths.project_state_dir)?;
        let history_path = paths
            .project_state_dir
            .join(selection::SELECTION_HISTORY_FILENAME);
        let event = selection::SelectionEvent {
            persona: persona.to_string(),
            session: session.to_string(),
            auto,
            reason: reason.map(str::to_string),
            recorded_at_unix: selection::now_unix(),
        };
        selection::append_selection_event(&history_path, &event)
    }

    /// Send anonymous selection telemetry for `persona`, but only when the
    /// project has opted in (`ProjectConfig.telemetry_opt_in`). When opt-in is
    /// disabled this is a no-op returning `Ok(())`, so the client never sends
    /// anything by default. When enabled, the endpoint is derived from the
    /// registry base URL (overridable via `FRAMESHIFT_TELEMETRY_URL`). Network
    /// failures are returned for the caller to log.
    pub fn send_telemetry_for_persona(
        &self,
        project_root: &Path,
        persona: &str,
        session: &str,
    ) -> Result<(), ClientError> {
        let config = self.project_config(project_root)?;
        if !config.telemetry_opt_in {
            return Ok(());
        }
        let endpoint = selection::telemetry_endpoint();
        let paths = self.project_paths(project_root)?;
        let payload = selection::SelectionTelemetry {
            persona,
            session,
            project_id: &paths.project_id,
            recorded_at_unix: selection::now_unix(),
        };
        selection::post_selection_telemetry(&endpoint, &payload)
    }

    /// List the personas recorded in the project's lockfile, read-only.
    ///
    /// Unlike [`Client::sync`], this never re-materializes project state --
    /// it only reads `projects/<id>/lock.toml`. Returns an empty vec when the
    /// project has no lockfile yet.
    pub fn list_personas(&self, project_root: &Path) -> Result<Vec<LockedPersona>, ClientError> {
        let paths = self.project_paths(project_root)?;
        Ok(load_lockfile(&paths.lock_path)?
            .map(|lockfile| lockfile.personas)
            .unwrap_or_default())
    }

    /// Read the name of the currently active persona for this project, read-only.
    ///
    /// Returns `Ok(None)` when the `active` marker file does not exist or is
    /// empty after trimming whitespace. Any other I/O error is propagated as
    /// [`ClientError::Io`].
    pub fn active_persona(&self, project_root: &Path) -> Result<Option<String>, ClientError> {
        let paths = self.project_paths(project_root)?;
        match fs::read_to_string(&paths.active_path) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(trimmed.to_string()))
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ClientError::Io {
                path: paths.active_path,
                source,
            }),
        }
    }

    pub fn sync(&self, project_root: &Path) -> Result<SyncReport, ClientError> {
        let paths = self.project_paths(project_root)?;
        let Some((raw_lock, lockfile)) = load_lockfile_with_raw(&paths.lock_path)? else {
            return Ok(SyncReport {
                project_id: paths.project_id,
                personas: Vec::new(),
            });
        };

        self.materialize_project_state(&paths, &lockfile, &raw_lock)?;
        Ok(SyncReport {
            project_id: paths.project_id,
            personas: lockfile
                .personas
                .iter()
                .map(|persona| persona.name.clone())
                .collect(),
        })
    }

    pub fn gc(&self) -> Result<GcReport, ClientError> {
        let mut referenced_hashes = BTreeSet::new();
        let projects_root = self.data_root.join("projects");

        if projects_root.exists() {
            for entry in read_dir_sorted(&projects_root)? {
                let project_dir = entry.path();
                if !entry
                    .file_type()
                    .map_err(|source| ClientError::Io {
                        path: project_dir.clone(),
                        source,
                    })?
                    .is_dir()
                {
                    continue;
                }

                let central_lock = project_dir.join(CENTRAL_LOCK_FILENAME);
                if let Some(lockfile) = load_lockfile(&central_lock)? {
                    for persona in lockfile.personas {
                        referenced_hashes.insert(persona.hash);
                    }
                }
            }
        }

        let mut removed_hashes = Vec::new();
        let cache_root = self.data_root.join("cache");
        if cache_root.exists() {
            for entry in read_dir_sorted(&cache_root)? {
                let path = entry.path();
                if !entry
                    .file_type()
                    .map_err(|source| ClientError::Io {
                        path: path.clone(),
                        source,
                    })?
                    .is_dir()
                {
                    continue;
                }

                let hash = entry.file_name().to_string_lossy().to_string();
                if !referenced_hashes.contains(&hash) {
                    debug!(hash, "removing unreferenced cache entry");
                    remove_dir_all(&path)?;
                    removed_hashes.push(hash);
                }
            }
        }

        Ok(GcReport { removed_hashes })
    }

    /// Return the `personas/<name>/source` directories that currently exist for a project.
    ///
    /// These directories feed `frameshift_orchestrator::PersonaIndex::from_dirs`.
    /// Only directories whose `source` subdirectory exists on disk are returned;
    /// personas that are declared in the lock but whose source has not yet been
    /// materialized are silently skipped.
    pub fn installed_persona_source_dirs(
        &self,
        project_root: &Path,
    ) -> Result<Vec<std::path::PathBuf>, ClientError> {
        let paths = self.project_paths(project_root)?;

        if !paths.personas_dir.exists() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for entry in read_dir_sorted(&paths.personas_dir)? {
            let persona_dir = entry.path();
            if !entry
                .file_type()
                .map_err(|source| ClientError::Io {
                    path: persona_dir.clone(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }

            let source_dir = persona_dir.join("source");
            if source_dir.is_dir() {
                result.push(source_dir);
            }
        }

        Ok(result)
    }

    /// Read the rendered markdown for a specific persona and target.
    ///
    /// Resolves the target's output filename via `RENDER_TARGETS` (e.g. target
    /// `"claude"` maps to `CLAUDE.md`) and reads
    /// `personas/<persona>/rendered/<target>/<file>` from the project's central
    /// state directory. Defaults to target `"claude"` if an empty string is
    /// passed (callers should pass `"claude"` explicitly).
    ///
    /// Returns `ClientError::UnknownRenderTarget` when `target` is not in
    /// `RENDER_TARGETS`, and `ClientError::RenderedPersonaNotFound` when the
    /// file is absent.
    pub fn rendered_persona(
        &self,
        project_root: &Path,
        persona: &str,
        target: &str,
    ) -> Result<String, ClientError> {
        validate_persona_name(persona)?;
        let effective_target = if target.is_empty() { "claude" } else { target };

        let filename = RENDER_TARGETS
            .iter()
            .find(|(t, _)| *t == effective_target)
            .map(|(_, f)| *f)
            .ok_or_else(|| ClientError::UnknownRenderTarget(effective_target.to_string()))?;

        let paths = self.project_paths(project_root)?;
        let rendered_path = paths
            .personas_dir
            .join(persona)
            .join("rendered")
            .join(effective_target)
            .join(filename);

        if !rendered_path.exists() {
            return Err(ClientError::RenderedPersonaNotFound {
                persona: persona.to_string(),
                target: effective_target.to_string(),
                path: rendered_path,
            });
        }

        read_to_string(&rendered_path)
    }

    /// Return the project state directory where orchestrator state files are placed.
    ///
    /// Callers should write `automate.json`, `automate-audit.jsonl`, and
    /// `automate-prefs.json` here to keep all per-project state co-located.
    pub fn orchestrator_state_dir(
        &self,
        project_root: &Path,
    ) -> Result<std::path::PathBuf, ClientError> {
        let paths = self.project_paths(project_root)?;
        Ok(paths.project_state_dir)
    }

    fn materialize_project_state(
        &self,
        paths: &ProjectPaths,
        lockfile: &Lockfile,
        raw_lock: &str,
    ) -> Result<(), ClientError> {
        // Validate every persona name before it is joined into the central
        // store. A name like `../../x` would otherwise escape personas_dir and
        // drive remove_dir_all/copy against an arbitrary directory below.
        for persona in &lockfile.personas {
            validate_persona_name(&persona.name)?;
        }

        ensure_dir(&paths.cache_dir)?;
        ensure_dir(&paths.personas_dir)?;
        // Lock file lives only in the central store -- nothing is written to the project root.
        write_file(&paths.lock_path, raw_lock.as_bytes())?;

        let expected_names: BTreeSet<&str> =
            lockfile.personas.iter().map(|p| p.name.as_str()).collect();
        for entry in read_dir_sorted(&paths.personas_dir)? {
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|source| ClientError::Io {
                    path: path.clone(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();
            if !expected_names.contains(name.as_str()) {
                remove_dir_all(&path)?;
            }
        }

        for persona in &lockfile.personas {
            let cache_path = paths.cache_dir.join(&persona.hash);
            if !cache_path.exists() {
                return Err(ClientError::MissingCacheEntry {
                    hash: persona.hash.clone(),
                    path: cache_path,
                });
            }

            let persona_dir = paths.personas_dir.join(&persona.name);
            if persona_dir.exists() {
                remove_dir_all(&persona_dir)?;
            }
            ensure_dir(&persona_dir)?;

            let source_dir = persona_dir.join("source");
            copy_dir_recursive(&cache_path, &source_dir)?;

            let rendered_root = persona_dir.join("rendered");
            self.materialize_persona_rendered_outputs(
                &paths.cache_dir,
                &cache_path,
                &rendered_root,
                &persona.name,
                lockfile,
            )?;

            // Growth is local-only and append-only -- a single file per persona, never published upstream.
            touch_empty(&persona_dir.join("growth.md"))?;
        }

        if paths.active_path.exists() {
            let active_name = read_to_string(&paths.active_path)?.trim().to_string();
            if !active_name.is_empty()
                && !lockfile
                    .personas
                    .iter()
                    .any(|persona| persona.name == active_name)
            {
                remove_file_if_exists(&paths.active_path)?;
            }
        }

        Ok(())
    }

    /// Renders a single persona's output into `rendered_root`, composing with
    /// its declared `extends`/`mixin` bases when the pack has typed source.
    ///
    /// Reads `pack.toml` from `cache_path` to decide which of three paths to
    /// take:
    /// - No `extends`/`mixin` declared: unchanged behavior, delegates to
    ///   [`materialize_rendered_outputs`] (markdown render source).
    /// - `extends`/`mixin` declared AND `persona.toml` present: composes the
    ///   root with its resolved bases via `frameshift_compose::Composer`,
    ///   renders the composed result for every target, and applies the same
    ///   infra overlay as the non-composition path. Composition failures
    ///   (missing base, L1 override) propagate as `ClientError::Compose`.
    /// - `extends`/`mixin` declared but no `persona.toml`: warns and falls
    ///   back to the markdown-only render path, since there is no typed
    ///   source for the composer to operate on.
    fn materialize_persona_rendered_outputs(
        &self,
        cache_dir: &Path,
        cache_path: &Path,
        rendered_root: &Path,
        persona_name: &str,
        lockfile: &Lockfile,
    ) -> Result<(), ClientError> {
        let manifest_path = cache_path.join("pack.toml");
        let manifest_raw =
            fs::read_to_string(&manifest_path).map_err(|source| ClientError::Io {
                path: manifest_path.clone(),
                source,
            })?;
        let manifest: frameshift_pack::PackManifest =
            toml::from_str(&manifest_raw).map_err(|source| ClientError::TomlDeserialize {
                path: manifest_path,
                source,
            })?;

        let has_composition = manifest.extends.is_some() || !manifest.mixin.is_empty();
        let has_typed_source = cache_path.join("persona.toml").is_file();

        if has_composition && has_typed_source {
            let root = frameshift_source::PersonaSource::load_from_dir(cache_path)
                .map_err(frameshift_compose::ComposeError::from)?;
            let resolver = compose_support::CacheResolver::new(cache_dir, lockfile);
            let composed = frameshift_compose::Composer::new(resolver).compose(
                root,
                manifest.extends.clone(),
                &manifest.mixin,
            )?;

            for collision in &composed.rule_collisions {
                warn!(persona = persona_name, id = %collision.id, layers = ?collision.layers, "rule id collision during composition");
            }
            for collision in &composed.skill_collisions {
                warn!(persona = persona_name, id = %collision.id, layers = ?collision.layers, "skill id collision during composition");
            }

            let src = composed.into_source();
            for (target_dir, filename, target) in [
                (
                    "claude",
                    "CLAUDE.md",
                    frameshift_source::RenderTarget::Claude,
                ),
                ("codex", "AGENTS.md", frameshift_source::RenderTarget::Codex),
                (
                    "gemini",
                    "GEMINI.md",
                    frameshift_source::RenderTarget::Gemini,
                ),
                (
                    "generic",
                    "AGENTS.md",
                    frameshift_source::RenderTarget::Generic,
                ),
            ] {
                let markdown = frameshift_source::render_to_markdown(&src, target);
                let composed_content =
                    compose_rendered_content(persona_name, &markdown, self.config_root.as_deref());
                let dir = rendered_root.join(target_dir);
                ensure_dir(&dir)?;
                write_file(&dir.join(filename), composed_content.as_bytes())?;
            }

            return Ok(());
        }

        if has_composition {
            warn!(
                persona = persona_name,
                "pack declares extends/mixin but has no persona.toml; rendering markdown body without composition"
            );
        }

        materialize_rendered_outputs(
            cache_path,
            rendered_root,
            persona_name,
            self.config_root.as_deref(),
        )
    }
}

fn default_data_root() -> Result<PathBuf, ClientError> {
    if let Ok(xdg_data_home) = std::env::var("XDG_DATA_HOME") {
        if !xdg_data_home.is_empty() {
            return Ok(PathBuf::from(xdg_data_home).join("frameshift"));
        }
    }

    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|source| ClientError::Io {
            path: PathBuf::from("$HOME"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, source),
        })?;
    Ok(home.join(".local").join("share").join("frameshift"))
}

/// Resolve the XDG config home directory.
///
/// Returns an error when neither `XDG_CONFIG_HOME` nor `HOME` is set so the
/// caller fails closed rather than writing state to a world-traversable `/tmp`
/// path. Mirrors the error shape used by [`default_data_root`].
fn default_config_root() -> Result<PathBuf, ClientError> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }

    // Fail closed: no /tmp fallback when HOME is absent.
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|source| ClientError::Io {
            path: PathBuf::from("$HOME"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, source),
        })?;
    Ok(home.join(".config"))
}

fn validate_explicit_project_id(project_id: &str) -> Result<(), ClientError> {
    if project_id.is_empty() || project_id == "." || project_id == ".." || project_id.contains('/')
    {
        return Err(ClientError::InvalidProjectId(project_id.to_string()));
    }

    if project_id.contains('\\') {
        return Err(ClientError::InvalidProjectId(project_id.to_string()));
    }

    Ok(())
}

/// Validate that `name` is safe to use as a single path component before it is
/// joined into the central store (where the result is recursively removed and
/// repopulated). Rejects empty names, a leading `.` (catches `.`/`..`/hidden),
/// path separators, NUL/control characters, and any name that is not exactly
/// one normal path component.
///
/// This is the engine-level guard against a malicious pack or tampered lockfile
/// whose persona name (e.g. `../../etc`) would otherwise escape `personas_dir`
/// during install/sync.
pub fn validate_persona_name(name: &str) -> Result<(), ClientError> {
    use std::path::Component;

    let reject = |reason: &'static str| {
        Err(ClientError::InvalidPersonaName {
            name: name.to_string(),
            reason,
        })
    };

    if name.is_empty() {
        return reject("name must not be empty");
    }
    if name.starts_with('.') {
        return reject("name must not start with '.'");
    }
    if name.contains('\0') {
        return reject("name must not contain NUL");
    }
    if name.chars().any(|c| c.is_control()) {
        return reject("name must not contain control characters");
    }
    if name.contains('/') || name.contains('\\') {
        return reject("name must not contain path separators");
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => reject("name must be a single normal path component"),
    }
}

/// Best-effort migration: if a pre-WS-1 install left `frameshift.toml` or
/// `frameshift.lock` at the project root, copy each into the central store
/// (if the central equivalent does not yet exist) and remove the original.
///
/// Failures are logged via `tracing::warn!` and swallowed -- migration must
/// never panic or block the calling operation.
fn migrate_legacy_project_files(project_root: &Path, paths: &ProjectPaths) {
    let mut migrated_any = false;
    let pairs: [(&str, &Path); 2] = [
        (LEGACY_CONFIG_FILENAME, &paths.config_path),
        (LEGACY_LOCK_FILENAME, &paths.lock_path),
    ];

    for (legacy_name, central_path) in pairs {
        let legacy_path = project_root.join(legacy_name);
        if !legacy_path.exists() {
            continue;
        }

        if !central_path.exists() {
            if let Some(parent) = central_path.parent() {
                if let Err(error) = fs::create_dir_all(parent) {
                    warn!(
                        path = %parent.display(),
                        error = %error,
                        "failed to create central-store directory during legacy migration"
                    );
                    continue;
                }
            }

            match fs::read(&legacy_path) {
                Ok(bytes) => {
                    if let Err(error) = fs::write(central_path, &bytes) {
                        warn!(
                            path = %central_path.display(),
                            error = %error,
                            "failed to write central-store copy during legacy migration"
                        );
                        continue;
                    }
                }
                Err(error) => {
                    warn!(
                        path = %legacy_path.display(),
                        error = %error,
                        "failed to read legacy project-root file during migration"
                    );
                    continue;
                }
            }
        }

        match fs::remove_file(&legacy_path) {
            Ok(()) => {
                migrated_any = true;
            }
            Err(error) => {
                warn!(
                    path = %legacy_path.display(),
                    error = %error,
                    "failed to remove legacy project-root file after migration"
                );
            }
        }
    }

    if migrated_any {
        info!(
            project_root = %project_root.display(),
            "migrated legacy frameshift.toml/lock from project root to central store"
        );
    }
}

fn hashed_project_id(project_root: &Path) -> Result<String, ClientError> {
    let canonical_root = fs::canonicalize(project_root).map_err(|source| ClientError::Io {
        path: project_root.to_path_buf(),
        source,
    })?;
    let canonical_str = canonical_root
        .to_str()
        .ok_or_else(|| ClientError::NonUtf8Path(canonical_root.clone()))?;
    let digest = Sha256::digest(canonical_str.as_bytes());
    Ok(hex::encode(digest))
}

/// Verify that the pack manifest matches the requested spec (name and version).
pub(crate) fn validate_pack_request(pack: &Pack, spec: &PersonaSpec) -> Result<(), ClientError> {
    let manifest = pack.manifest();
    if manifest.name != spec.name || manifest.version != spec.version {
        return Err(ClientError::ManifestMismatch {
            expected_name: spec.name.clone(),
            expected_version: spec.version.clone(),
            actual_name: manifest.name.clone(),
            actual_version: manifest.version.clone(),
        });
    }
    Ok(())
}

fn verify_pack_signature_if_present(pack: &Pack) -> Result<(), ClientError> {
    if !pack.has_signature() {
        return Ok(());
    }

    let key_bytes = parse_verifying_key_bytes(&pack.manifest().author_pubkey)?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ClientError::InvalidAuthorPublicKey(pack.manifest().author_pubkey.clone()))?;
    pack.verify(&key)
        .map_err(|_| ClientError::SignatureVerification)
}

fn parse_verifying_key_bytes(encoded: &str) -> Result<[u8; 32], ClientError> {
    if let Ok(bytes) = hex::decode(encoded) {
        if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(array);
        }
    }

    if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(encoded) {
        if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(array);
        }
    }

    if let Ok(bytes) = general_purpose::STANDARD_NO_PAD.decode(encoded) {
        if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(array);
        }
    }

    Err(ClientError::InvalidAuthorPublicKey(encoded.to_string()))
}

/// Build a [`LockedPersona`] from the loaded pack's manifest fields and canonical hash.
pub(crate) fn locked_persona_from_pack(pack: &Pack) -> LockedPersona {
    let manifest = pack.manifest();
    LockedPersona {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        author_handle: manifest.author_handle.clone(),
        author_pubkey: manifest.author_pubkey.clone(),
        hash: pack.canonical_hash_hex(),
    }
}

fn upsert_locked_persona(lockfile: &mut Lockfile, persona: LockedPersona) {
    if let Some(existing) = lockfile
        .personas
        .iter_mut()
        .find(|existing| existing.name == persona.name)
    {
        *existing = persona;
        return;
    }

    lockfile.personas.push(persona);
    lockfile
        .personas
        .sort_by(|left, right| left.name.cmp(&right.name));
}

fn load_lockfile(path: &Path) -> Result<Option<Lockfile>, ClientError> {
    load_lockfile_with_raw(path).map(|maybe| maybe.map(|(_, lockfile)| lockfile))
}

fn load_lockfile_with_raw(path: &Path) -> Result<Option<(String, Lockfile)>, ClientError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = read_to_string(path)?;
    let lockfile = toml::from_str(&raw).map_err(|source| ClientError::TomlDeserialize {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some((raw, lockfile)))
}

/// Copy `source_dir` into the content-addressed cache at `cache_path` if it is not
/// already there. Uses a `.tmp` staging path + atomic rename.
pub(crate) fn ensure_cached_pack(source_dir: &Path, cache_path: &Path) -> Result<(), ClientError> {
    ensure_dir(
        cache_path
            .parent()
            .expect("cache paths are always nested under cache root"),
    )?;
    if cache_path.exists() {
        return Ok(());
    }

    let staging_path = cache_path.with_extension("tmp");
    if staging_path.exists() {
        remove_dir_all(&staging_path)?;
    }
    copy_dir_recursive(source_dir, &staging_path)?;

    match fs::rename(&staging_path, cache_path) {
        Ok(()) => Ok(()),
        Err(_source) if cache_path.exists() => {
            remove_dir_all(&staging_path)?;
            Ok(())
        }
        Err(source) => Err(ClientError::Io {
            path: cache_path.to_path_buf(),
            source,
        }),
    }
}

/// Render persona content into per-target markdown files, composing with
/// the infrastructure overlay if one exists under `config_root`.
fn materialize_rendered_outputs(
    cache_path: &Path,
    rendered_root: &Path,
    persona_name: &str,
    config_root: Option<&Path>,
) -> Result<(), ClientError> {
    let render_source = find_render_source(cache_path)?;
    let persona_content = fs::read_to_string(&render_source).map_err(|source| ClientError::Io {
        path: render_source.clone(),
        source,
    })?;

    let composed = compose_rendered_content(persona_name, &persona_content, config_root);

    for (target_dir, filename) in RENDER_TARGETS {
        let dir = rendered_root.join(target_dir);
        ensure_dir(&dir)?;
        write_file(&dir.join(filename), composed.as_bytes())?;
    }

    Ok(())
}

/// Compose the final rendered content from infrastructure overlay + persona context header + persona content.
/// If no infrastructure overlay exists, returns persona content unchanged.
fn compose_rendered_content(
    persona_name: &str,
    persona_content: &str,
    config_root: Option<&Path>,
) -> String {
    let infra_path = config_root.map(|root| root.join("frameshift").join("infrastructure.md"));
    let infra_content = infra_path
        .as_deref()
        .and_then(|p| fs::read_to_string(p).ok());

    let mut composed = String::new();

    if let Some(infra) = &infra_content {
        composed.push_str(infra);
        composed.push_str("\n\n## Persona Context\n\n");
        composed.push_str(&format!("Active persona: {}\n", persona_name));
        composed.push_str("\n---\n\n");
    }

    composed.push_str(persona_content);
    composed
}

fn find_render_source(pack_dir: &Path) -> Result<PathBuf, ClientError> {
    for candidate in RENDER_CANDIDATES {
        let path = pack_dir.join(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }

    for entry in read_dir_sorted(pack_dir)? {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            return Ok(path);
        }
    }

    Err(ClientError::MissingRenderSource(pack_dir.to_path_buf()))
}

fn ensure_exists(path: &Path) -> Result<(), ClientError> {
    if path.exists() {
        return Ok(());
    }

    Err(ClientError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "path does not exist"),
    })
}

fn ensure_dir(path: &Path) -> Result<(), ClientError> {
    fs::create_dir_all(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn touch_empty(path: &Path) -> Result<(), ClientError> {
    if path.exists() {
        return Ok(());
    }
    write_file(path, b"")
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    fs::write(path, bytes).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn read_to_string(path: &Path) -> Result<String, ClientError> {
    fs::read_to_string(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_dir_all(path: &Path) -> Result<(), ClientError> {
    fs::remove_dir_all(path).map_err(|source| ClientError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_file_if_exists(path: &Path) -> Result<(), ClientError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ClientError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), ClientError> {
    ensure_dir(destination)?;
    for entry in read_dir_sorted(source)? {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|source| ClientError::Io {
            path: source_path.clone(),
            source,
        })?;

        if file_type.is_dir() {
            copy_dir_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&source_path).map_err(|source| ClientError::Io {
                path: source_path.clone(),
                source,
            })?;
            write_file(&destination_path, &bytes)?;
        }
    }
    Ok(())
}

fn read_dir_sorted(path: &Path) -> Result<Vec<fs::DirEntry>, ClientError> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ClientError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

/// Shared install tail: upsert a [`LockedPersona`] into the lockfile, persist
/// the lockfile, and materialize project state. Both the LocalPath and Registry
/// arms call this after producing their locked persona.
///
/// Returns an [`InstallReport`] on success.
fn finish_install(
    client: &Client,
    paths: &ProjectPaths,
    locked: LockedPersona,
) -> Result<InstallReport, ClientError> {
    let mut lockfile = load_lockfile(&paths.lock_path)?.unwrap_or_default();
    upsert_locked_persona(&mut lockfile, locked.clone());
    let raw_lock = toml::to_string_pretty(&lockfile)?;
    client.materialize_project_state(paths, &lockfile, &raw_lock)?;

    Ok(InstallReport {
        project_id: paths.project_id.clone(),
        cache_path: paths.cache_dir.join(&locked.hash),
        persona: locked,
    })
}

/// Fetch a pack from the HTTP registry, verify its content hash, extract it,
/// write the signature, verify the Ed25519 signature, cache it by hash, and
/// return the [`LockedPersona`] to be committed into the lockfile.
///
/// This is the complete implementation for [`InstallSource::Registry`].
fn install_from_registry(
    spec: &PersonaSpec,
    paths: &ProjectPaths,
) -> Result<LockedPersona, ClientError> {
    registry::fetch_and_install(spec, paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// validate_persona_name accepts clean slugs and rejects traversal/separators.
    #[test]
    fn validate_persona_name_guards_traversal() {
        for ok in ["cryptographic", "rust-engineer", "my_persona1"] {
            assert!(validate_persona_name(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", ".", "..", "../etc", "a/b", "a\\b", ".hidden", "x\0y"] {
            assert!(
                matches!(
                    validate_persona_name(bad),
                    Err(ClientError::InvalidPersonaName { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    /// Helper: set up a minimal pack and install it, returning the client and project root.
    fn install_test_persona(tmp: &tempfile::TempDir, name: &str) -> (Client, std::path::PathBuf) {
        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"{}\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
                name
            ),
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), format!("# {}\n\nTest.\n", name)).unwrap();

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });

        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: name.to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        (client, project_root)
    }

    /// uninstall removes the persona from the lockfile and its materialized
    /// directory, leaves the cache entry in place, and gc then reclaims it.
    #[test]
    fn uninstall_removes_persona_and_gc_reclaims_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "keep-me");
        install_test_persona(&tmp, "drop-me");

        let paths = client.project_paths(&project_root).unwrap();
        let lockfile_before = load_lockfile(&paths.lock_path).unwrap().unwrap();
        assert_eq!(lockfile_before.personas.len(), 2);
        let dropped_hash = lockfile_before
            .personas
            .iter()
            .find(|p| p.name == "drop-me")
            .unwrap()
            .hash
            .clone();

        client.uninstall(&project_root, "drop-me").unwrap();

        let lockfile_after = load_lockfile(&paths.lock_path).unwrap().unwrap();
        assert_eq!(lockfile_after.personas.len(), 1);
        assert_eq!(lockfile_after.personas[0].name, "keep-me");
        assert!(!paths.personas_dir.join("drop-me").exists());

        // The cache entry for the removed persona is left in place until gc.
        let cache_path = paths.cache_dir.join(&dropped_hash);
        assert!(cache_path.exists(), "cache entry should survive uninstall");

        let report = client.gc().unwrap();
        assert!(report.removed_hashes.contains(&dropped_hash));
        assert!(
            !cache_path.exists(),
            "gc should reclaim the orphaned cache entry"
        );
    }

    /// uninstall of a persona that is not in the lockfile returns PersonaNotInstalled.
    #[test]
    fn uninstall_missing_persona_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "onlyone");
        let err = client.uninstall(&project_root, "ghost").unwrap_err();
        assert!(matches!(err, ClientError::PersonaNotInstalled(name) if name == "ghost"));
    }

    /// uninstall of the active persona clears the active marker file.
    #[test]
    fn uninstall_active_persona_clears_active_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "active-one");
        client.activate(&project_root, "active-one").unwrap();
        assert_eq!(
            client.active_persona(&project_root).unwrap(),
            Some("active-one".to_string())
        );

        client.uninstall(&project_root, "active-one").unwrap();
        assert_eq!(client.active_persona(&project_root).unwrap(), None);
    }

    /// list_personas returns one entry matching the installed persona.
    #[test]
    fn list_personas_returns_installed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "listed");
        let personas = client.list_personas(&project_root).unwrap();
        assert_eq!(personas.len(), 1);
        assert_eq!(personas[0].name, "listed");
        assert_eq!(personas[0].version, "0.1.0");
    }

    /// list_personas returns an empty vec for a project with no lockfile.
    #[test]
    fn list_personas_empty_for_new_project() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });
        assert!(client.list_personas(&project_root).unwrap().is_empty());
    }

    /// active_persona returns the activated persona's name after activate().
    #[test]
    fn active_persona_returns_name_after_activate() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "act-test");
        assert_eq!(client.active_persona(&project_root).unwrap(), None);
        client.activate(&project_root, "act-test").unwrap();
        assert_eq!(
            client.active_persona(&project_root).unwrap(),
            Some("act-test".to_string())
        );
    }

    /// installed_persona_source_dirs returns one entry per installed persona.
    #[test]
    fn installed_persona_source_dirs_returns_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "mypersona");
        let dirs = client.installed_persona_source_dirs(&project_root).unwrap();
        assert_eq!(dirs.len(), 1, "expected exactly one source dir");
        assert!(
            dirs[0].ends_with("source"),
            "source dir should end with 'source'"
        );
    }

    /// installed_persona_source_dirs returns empty vec when no personas installed.
    #[test]
    fn installed_persona_source_dirs_empty_when_no_personas() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });
        let dirs = client.installed_persona_source_dirs(&project_root).unwrap();
        assert!(dirs.is_empty());
    }

    /// rendered_persona returns the rendered markdown for the claude target.
    #[test]
    fn rendered_persona_returns_content() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "rendtest");
        let content = client
            .rendered_persona(&project_root, "rendtest", "claude")
            .unwrap();
        assert!(
            content.contains("rendtest") || content.contains("Rendtest") || !content.is_empty()
        );
    }

    /// rendered_persona returns an error for an unknown render target.
    #[test]
    fn rendered_persona_error_for_unknown_target() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "tgt-test");
        let err = client
            .rendered_persona(&project_root, "tgt-test", "nonexistent-target")
            .unwrap_err();
        assert!(
            matches!(err, ClientError::UnknownRenderTarget(_)),
            "expected UnknownRenderTarget, got {err}"
        );
    }

    /// rendered_persona returns RenderedPersonaNotFound for a non-installed persona.
    #[test]
    fn rendered_persona_error_for_missing_persona() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();
        let client = Client::new(ClientOptions {
            data_root: tmp.path().join("data"),
            config_root: None,
        });
        let err = client
            .rendered_persona(&project_root, "ghost", "claude")
            .unwrap_err();
        assert!(
            matches!(err, ClientError::RenderedPersonaNotFound { .. }),
            "expected RenderedPersonaNotFound, got {err}"
        );
    }

    /// orchestrator_state_dir returns the project state directory.
    #[test]
    fn orchestrator_state_dir_is_project_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let (client, project_root) = install_test_persona(&tmp, "statedirtest");
        let state_dir = client.orchestrator_state_dir(&project_root).unwrap();
        // Must exist because install creates it.
        assert!(state_dir.exists(), "state dir should exist after install");
        // The path should contain "projects" and the project id.
        let s = state_dir.to_string_lossy();
        assert!(
            s.contains("projects"),
            "state dir path must contain 'projects'"
        );
    }

    #[test]
    fn rejects_invalid_persona_specs() {
        assert!("cryptographic".parse::<PersonaSpec>().is_err());
        assert!("@0.3.1".parse::<PersonaSpec>().is_err());
        assert!("cryptographic@".parse::<PersonaSpec>().is_err());
    }

    #[test]
    fn explicit_project_id_rejects_path_separators() {
        assert!(validate_explicit_project_id("team/alpha").is_err());
        assert!(validate_explicit_project_id("team\\alpha").is_err());
        assert!(validate_explicit_project_id("valid-id").is_ok());
    }

    #[test]
    fn rendered_output_includes_infra_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");
        let config_root = tmp.path().join("config");

        // Set up infra overlay
        let infra_dir = config_root.join("frameshift");
        fs::create_dir_all(&infra_dir).unwrap();
        fs::write(
            infra_dir.join("infrastructure.md"),
            "# Infrastructure\n\nTest infra content.\n",
        )
        .unwrap();

        // Set up a minimal pack
        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"testpersona\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(
            pack_dir.join("AGENTS.md"),
            "# Test Persona\n\nBehavior rules here.\n",
        )
        .unwrap();

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = Client::new(ClientOptions {
            data_root: data_root.clone(),
            config_root: Some(config_root),
        });
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "testpersona".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        let project_id = client.project_id(&project_root).unwrap();
        let rendered = data_root
            .join("projects")
            .join(&project_id)
            .join("personas/testpersona/rendered/claude/CLAUDE.md");
        let content = fs::read_to_string(&rendered).unwrap();

        assert!(
            content.contains("# Infrastructure"),
            "missing infra overlay"
        );
        assert!(content.contains("Test infra content"), "missing infra body");
        assert!(
            content.contains("Active persona: testpersona"),
            "missing persona context header"
        );
        assert!(
            content.contains("# Test Persona"),
            "missing persona content"
        );

        // Infra must come before persona content
        let infra_pos = content.find("# Infrastructure").unwrap();
        let persona_pos = content.find("# Test Persona").unwrap();
        assert!(
            infra_pos < persona_pos,
            "infra overlay must precede persona content"
        );
    }

    #[test]
    fn rendered_output_works_without_infra_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let data_root = tmp.path().join("data");

        let pack_dir = tmp.path().join("pack");
        fs::create_dir_all(&pack_dir).unwrap();
        fs::write(
            pack_dir.join("pack.toml"),
            "schema_version = 1\nname = \"noinfratestp\"\nauthor_handle = \"test\"\nauthor_pubkey = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(pack_dir.join("AGENTS.md"), "# Bare Persona\n").unwrap();

        let project_root = tmp.path().join("project");
        fs::create_dir_all(&project_root).unwrap();

        let client = Client::new(ClientOptions {
            data_root: data_root.clone(),
            config_root: None,
        });
        client
            .install(InstallRequest {
                project_root: project_root.clone(),
                spec: PersonaSpec {
                    name: "noinfratestp".to_string(),
                    version: "0.1.0".to_string(),
                },
                source: InstallSource::LocalPath(pack_dir),
            })
            .unwrap();

        let project_id = client.project_id(&project_root).unwrap();
        let rendered = data_root
            .join("projects")
            .join(&project_id)
            .join("personas/noinfratestp/rendered/claude/CLAUDE.md");
        let content = fs::read_to_string(&rendered).unwrap();

        assert!(
            content.contains("# Bare Persona"),
            "persona content must be present"
        );
        assert!(
            !content.contains("Infrastructure"),
            "no infra overlay expected"
        );
    }
}

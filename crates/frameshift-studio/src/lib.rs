//! Secure local draft lifecycle for Creator Studio clients.
//!
//! Draft metadata is kept outside the publishable content directory. Every
//! review is bound to the deterministic publication inventory hash, and every
//! mutation invalidates review and submission state before content changes.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use frameshift_pack::{PackManifest, LOCAL_UNSIGNED_PUBKEY};
use frameshift_publication::{
    is_allowed_public_path, validate_directory, PublicationReport, MAX_FILE_SIZE,
};
use frameshift_source::{render_to_markdown, Author, Persona, PersonaSource, RenderTarget};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Current schema version for persisted draft metadata.
pub const DRAFT_SCHEMA_VERSION: u32 = 1;

/// Filename holding private Creator Studio draft metadata.
const METADATA_FILENAME: &str = "draft.json";

/// Directory holding the exact files eligible for publication.
const CONTENT_DIRECTORY: &str = "content";

/// Maximum user-facing title length in Unicode scalar values.
const MAX_TITLE_CHARS: usize = 200;

/// A local Creator Studio draft store rooted beneath managed Frameshift data.
#[derive(Debug, Clone)]
pub struct Studio {
    /// Canonical root that contains one directory per draft ID.
    root: PathBuf,
}

/// Persisted lifecycle state for one local draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    /// Version of this serialized metadata contract.
    pub schema_version: u32,
    /// Stable caller-selected identifier used as one filesystem component.
    pub id: String,
    /// User-facing draft title.
    pub title: String,
    /// Monotonic local mutation counter.
    pub revision: u64,
    /// Human confirmation bound to an exact valid file inventory.
    pub review: Option<ReviewConfirmation>,
    /// Explicit publish intent bound to the same reviewed inventory.
    pub submission_intent: Option<SubmissionIntent>,
}

/// Human confirmation of the exact files represented by an inventory hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewConfirmation {
    /// Draft revision presented during review.
    pub revision: u64,
    /// Deterministic hash of every reviewed public file.
    pub inventory_hash: String,
}

/// Explicit intent to submit a previously reviewed inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionIntent {
    /// Draft revision approved for submission.
    pub revision: u64,
    /// Deterministic hash of the approved public files.
    pub inventory_hash: String,
}

/// Current draft metadata paired with fresh deterministic validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftStatus {
    /// Persisted draft lifecycle state.
    pub draft: Draft,
    /// Fresh report over the exact current content.
    pub publication: PublicationReport,
    /// Whether the stored review still matches current revision and bytes.
    pub review_current: bool,
    /// Whether publish intent still matches the current review and bytes.
    pub submission_intent_current: bool,
}

/// Immutable path-free copy of one exact reviewed draft inventory.
pub struct DraftSnapshot {
    /// Draft revision frozen into this snapshot.
    revision: u64,
    /// Fresh validation report for the frozen file set.
    publication: PublicationReport,
    /// Exact public files in deterministic inventory order.
    files: Vec<SnapshotFile>,
}

/// One exact public file held by an immutable draft snapshot.
pub struct SnapshotFile {
    /// Normalized public relative path.
    path: String,
    /// Exact bounded file bytes.
    bytes: Vec<u8>,
}

/// Path-free deterministic renders of one exact current draft revision.
#[derive(Serialize)]
pub struct DraftPreview {
    /// Draft revision whose source bytes produced these renders.
    pub revision: u64,
    /// Exact current public inventory hash.
    pub inventory_hash: String,
    /// Shared validation report for the same inventory.
    pub publication: PublicationReport,
    /// Supported agent targets in stable order.
    pub targets: Vec<TargetPreview>,
}

/// One deterministic target render and its exact UTF-8 content digest.
#[derive(Serialize)]
pub struct TargetPreview {
    /// Stable target identifier.
    pub target: String,
    /// Filename used when materializing this target.
    pub install_filename: String,
    /// Exact rendered Markdown.
    pub content: String,
    /// SHA-256 digest of the exact rendered UTF-8 bytes.
    pub sha256: String,
}

/// Atomic built-in template selected for a new local draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DraftTemplate {
    /// Editable local-only skeleton with no publishable author identity.
    Blank,
    /// Valid typed skeleton populated from bounded public fields.
    Guided(GuidedTemplateInput),
}

/// Bounded public fields collected by a guided Creator Studio flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidedTemplateInput {
    /// Stable public pack and persona name.
    pub name: String,
    /// Initial semantic version.
    pub version: String,
    /// Public author or publisher handle.
    pub author_handle: String,
    /// Exact lowercase Ed25519 verifying key.
    pub author_pubkey: String,
    /// Short public purpose statement.
    pub description: String,
    /// Short deterministic voice direction.
    pub voice_tone: String,
    /// Optional SPDX license identifier.
    pub license: Option<String>,
    /// Whether published bytes explicitly permit forking.
    #[serde(default)]
    pub forkable: bool,
}

/// Read-only accessors for an immutable draft snapshot.
impl DraftSnapshot {
    /// Return the draft revision represented by this snapshot.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Return the validation report bound to the frozen file bytes.
    pub fn publication(&self) -> &PublicationReport {
        &self.publication
    }

    /// Return the frozen files in deterministic inventory order.
    pub fn files(&self) -> &[SnapshotFile] {
        &self.files
    }
}

/// Read-only accessors for one frozen public file.
impl SnapshotFile {
    /// Return the normalized public relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the exact public file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Errors returned by the local Creator Studio draft store.
#[derive(Debug, thiserror::Error)]
pub enum StudioError {
    /// The configured store root is not a real directory.
    #[error("draft store root must be a real directory")]
    InvalidRoot,
    /// A draft identifier is unsafe or outside the supported public contract.
    #[error("invalid draft id")]
    InvalidDraftId,
    /// A draft title is empty or exceeds the supported size.
    #[error("invalid draft title")]
    InvalidTitle,
    /// The requested draft already exists.
    #[error("draft already exists")]
    AlreadyExists,
    /// The requested draft does not exist.
    #[error("draft not found")]
    NotFound,
    /// Draft metadata is malformed, unsupported, or inconsistent.
    #[error("invalid draft metadata: {0}")]
    InvalidMetadata(String),
    /// A content path is not part of the public pack format.
    #[error("invalid public content path")]
    InvalidContentPath,
    /// A content write exceeds the public per-file size limit.
    #[error("content exceeds the public file-size limit")]
    ContentTooLarge,
    /// An import contains filesystem structures that cannot be copied safely.
    #[error("unsafe draft import: {0}")]
    UnsafeImport(String),
    /// Review requires a fully valid publication report.
    #[error("draft is not valid for review")]
    InvalidForReview,
    /// Confirmation did not match the exact inventory presented for review.
    #[error("review inventory hash does not match current content")]
    ReviewHashMismatch,
    /// Submission intent requires a current review of the exact content.
    #[error("draft review is not current")]
    ReviewNotCurrent,
    /// Snapshotting requires a current explicit submission intent.
    #[error("draft submission intent is not current")]
    SubmissionIntentNotCurrent,
    /// Draft content changed while an immutable snapshot was being built.
    #[error("draft content changed while it was being frozen")]
    SnapshotChanged,
    /// Target preview requires valid structured persona source.
    #[error("draft preview requires valid typed persona source")]
    InvalidPreviewSource,
    /// One guided template field violates its bounded public contract.
    #[error("invalid guided template field: {0}")]
    InvalidTemplateField(&'static str),
    /// Generated typed TOML could not be serialized.
    #[error("draft template serialization failed")]
    TemplateSerialization(#[source] toml::ser::Error),
    /// Generated guided content did not pass the shared publication policy.
    #[error("guided draft template failed shared validation")]
    InvalidGeneratedTemplate,
    /// Publication validation could not inspect the draft.
    #[error("draft validation failed: {0}")]
    Validation(#[from] frameshift_publication::PublicationIoError),
    /// A local filesystem operation failed.
    #[error("draft storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Draft metadata could not be serialized.
    #[error("draft metadata serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Internal resolved paths for one verified draft.
struct DraftPaths {
    /// Private metadata file.
    metadata: PathBuf,
    /// Exact public content directory.
    content: PathBuf,
}

/// Inherent operations for secure draft persistence and lifecycle transitions.
impl Studio {
    /// Open or create a draft store and retain its canonical root.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StudioError> {
        fs::create_dir_all(root.as_ref())?;
        let metadata = fs::symlink_metadata(root.as_ref())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StudioError::InvalidRoot);
        }
        Ok(Self {
            root: fs::canonicalize(root.as_ref())?,
        })
    }

    /// Create an empty draft using an atomically published directory.
    pub fn create(&self, id: &str, title: &str) -> Result<Draft, StudioError> {
        let (staging, draft) = self.prepare_staging(id, title)?;
        self.publish_staging(staging, id)?;
        Ok(draft)
    }

    /// Atomically create one editable blank or validated guided template draft.
    pub fn create_template(
        &self,
        id: &str,
        title: &str,
        template: DraftTemplate,
    ) -> Result<DraftStatus, StudioError> {
        let (manifest, persona, require_publication_validity) = match template {
            DraftTemplate::Blank => (
                blank_template_manifest(id),
                blank_template_persona(id),
                false,
            ),
            DraftTemplate::Guided(input) => {
                validate_guided_template(&input)?;
                (
                    guided_template_manifest(&input),
                    guided_template_persona(&input),
                    true,
                )
            }
        };
        let manifest_bytes =
            toml::to_string(&manifest).map_err(StudioError::TemplateSerialization)?;
        let persona_bytes =
            toml::to_string(&persona).map_err(StudioError::TemplateSerialization)?;

        let (staging, _) = self.prepare_staging(id, title)?;
        let content = staging.path().join(CONTENT_DIRECTORY);
        write_bytes_atomic(&content.join("pack.toml"), manifest_bytes.as_bytes(), false)?;
        write_bytes_atomic(
            &content.join("persona.toml"),
            persona_bytes.as_bytes(),
            false,
        )?;
        let report = validate_directory(&content)?;
        if require_publication_validity && !report.valid {
            return Err(StudioError::InvalidGeneratedTemplate);
        }
        sync_directory(&content);
        self.publish_staging(staging, id)?;
        self.status(id)
    }

    /// Import public pack files into a newly created draft.
    pub fn import(
        &self,
        id: &str,
        title: &str,
        source: impl AsRef<Path>,
    ) -> Result<DraftStatus, StudioError> {
        let source = source.as_ref();
        let source_metadata = fs::symlink_metadata(source).map_err(|_| {
            StudioError::UnsafeImport("source must be a real directory".to_string())
        })?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
            return Err(StudioError::UnsafeImport(
                "source must be a real directory".to_string(),
            ));
        }

        let source_report = validate_directory(source)?;
        if let Some(finding) = source_report
            .findings
            .iter()
            .find(|finding| import_blocking_code(&finding.code))
        {
            return Err(StudioError::UnsafeImport(finding.code.clone()));
        }

        let (staging, _) = self.prepare_staging(id, title)?;
        let content = staging.path().join(CONTENT_DIRECTORY);
        for entry in &source_report.inventory {
            let destination = content.join(path_from_public_string(&entry.path)?);
            let bytes = read_regular_nofollow(&source.join(&entry.path), MAX_FILE_SIZE)?;
            write_bytes_atomic(&destination, &bytes, false)?;
        }

        let copied_report = validate_directory(&content)?;
        if copied_report.inventory_hash != source_report.inventory_hash {
            return Err(StudioError::UnsafeImport(
                "source changed while it was imported".to_string(),
            ));
        }
        self.publish_staging(staging, id)?;
        self.status(id)
    }

    /// List draft metadata in stable ID order without exposing local paths.
    pub fn list(&self) -> Result<Vec<Draft>, StudioError> {
        let mut drafts = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = match entry.file_name().to_str() {
                Some(name) if validate_draft_id(name).is_ok() => name.to_string(),
                _ => continue,
            };
            let file_type = entry.file_type()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            drafts.push(self.load(&name)?);
        }
        drafts.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(drafts)
    }

    /// Load and validate persisted metadata for one draft.
    pub fn load(&self, id: &str) -> Result<Draft, StudioError> {
        let paths = self.draft_paths(id)?;
        let bytes = read_regular_nofollow(&paths.metadata, MAX_FILE_SIZE)?;
        let draft: Draft = serde_json::from_slice(&bytes)
            .map_err(|error| StudioError::InvalidMetadata(error.to_string()))?;
        if draft.schema_version != DRAFT_SCHEMA_VERSION {
            return Err(StudioError::InvalidMetadata(
                "unsupported schema version".to_string(),
            ));
        }
        if draft.id != id || validate_title(&draft.title).is_err() {
            return Err(StudioError::InvalidMetadata(
                "metadata does not match its draft directory".to_string(),
            ));
        }
        Ok(draft)
    }

    /// Read one bounded public draft file without exposing its absolute path.
    pub fn read_file(&self, id: &str, relative_path: &str) -> Result<Vec<u8>, StudioError> {
        let relative = path_from_public_string(relative_path)?;
        let paths = self.draft_paths(id)?;
        read_regular_nofollow(&paths.content.join(relative), MAX_FILE_SIZE)
    }

    /// Atomically replace one public file after invalidating prior approval.
    pub fn write_file(
        &self,
        id: &str,
        relative_path: &str,
        bytes: &[u8],
    ) -> Result<DraftStatus, StudioError> {
        if bytes.len() as u64 > MAX_FILE_SIZE {
            return Err(StudioError::ContentTooLarge);
        }
        let relative = path_from_public_string(relative_path)?;
        let paths = self.draft_paths(id)?;
        let mut draft = self.load(id)?;
        invalidate_before_mutation(&mut draft)?;
        write_json_atomic(&paths.metadata, &draft, true)?;
        write_bytes_atomic(&paths.content.join(relative), bytes, true)?;
        self.status(id)
    }

    /// Remove one public file after invalidating prior approval.
    pub fn remove_file(&self, id: &str, relative_path: &str) -> Result<DraftStatus, StudioError> {
        let relative = path_from_public_string(relative_path)?;
        let paths = self.draft_paths(id)?;
        let target = paths.content.join(relative);
        let metadata = fs::symlink_metadata(&target).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StudioError::NotFound
            } else {
                StudioError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StudioError::InvalidContentPath);
        }
        let mut draft = self.load(id)?;
        invalidate_before_mutation(&mut draft)?;
        write_json_atomic(&paths.metadata, &draft, true)?;
        fs::remove_file(&target)?;
        if let Some(parent) = target.parent() {
            sync_directory(parent);
        }
        self.status(id)
    }

    /// Validate a draft and compute current review and intent freshness.
    pub fn status(&self, id: &str) -> Result<DraftStatus, StudioError> {
        let paths = self.draft_paths(id)?;
        let draft = self.load(id)?;
        let publication = validate_directory(&paths.content)?;
        let review_current = review_matches(&draft, &publication);
        let submission_intent_current = review_current
            && draft.submission_intent.as_ref().is_some_and(|intent| {
                intent.revision == draft.revision
                    && intent.inventory_hash == publication.inventory_hash
            });
        Ok(DraftStatus {
            draft,
            publication,
            review_current,
            submission_intent_current,
        })
    }

    /// Render every supported agent target from one exact current source inventory.
    pub fn preview(&self, id: &str) -> Result<DraftPreview, StudioError> {
        let status = self.status(id)?;
        if !status
            .publication
            .inventory
            .iter()
            .any(|entry| entry.path == "persona.toml")
        {
            return Err(StudioError::InvalidPreviewSource);
        }

        let paths = self.draft_paths(id)?;
        let staged = tempfile::TempDir::new()?;
        for source_name in ["persona.toml", "rules.toml", "skills.toml", "patterns.toml"] {
            let Some(entry) = status
                .publication
                .inventory
                .iter()
                .find(|entry| entry.path == source_name)
            else {
                continue;
            };
            let bytes = read_regular_nofollow(&paths.content.join(source_name), MAX_FILE_SIZE)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            if bytes.len() as u64 != entry.size || digest != entry.sha256 {
                return Err(StudioError::SnapshotChanged);
            }
            fs::write(staged.path().join(source_name), bytes)?;
        }

        let source = PersonaSource::load_from_dir(staged.path())
            .map_err(|_| StudioError::InvalidPreviewSource)?;
        let targets = [
            ("claude", "CLAUDE.md", RenderTarget::Claude),
            ("codex", "AGENTS.md", RenderTarget::Codex),
            ("gemini", "GEMINI.md", RenderTarget::Gemini),
            ("generic", "AGENTS.md", RenderTarget::Generic),
        ]
        .into_iter()
        .map(|(target, install_filename, render_target)| {
            let content = render_to_markdown(&source, render_target);
            TargetPreview {
                target: target.to_string(),
                install_filename: install_filename.to_string(),
                sha256: hex::encode(Sha256::digest(content.as_bytes())),
                content,
            }
        })
        .collect();

        if validate_directory(&paths.content)? != status.publication {
            return Err(StudioError::SnapshotChanged);
        }
        Ok(DraftPreview {
            revision: status.draft.revision,
            inventory_hash: status.publication.inventory_hash.clone(),
            publication: status.publication,
            targets,
        })
    }

    /// Confirm human review of the exact current valid file inventory.
    pub fn confirm_review(
        &self,
        id: &str,
        expected_inventory_hash: &str,
    ) -> Result<DraftStatus, StudioError> {
        let mut status = self.status(id)?;
        if !status.publication.valid {
            return Err(StudioError::InvalidForReview);
        }
        if status.publication.inventory_hash != expected_inventory_hash {
            return Err(StudioError::ReviewHashMismatch);
        }
        status.draft.review = Some(ReviewConfirmation {
            revision: status.draft.revision,
            inventory_hash: status.publication.inventory_hash.clone(),
        });
        status.draft.submission_intent = None;
        let paths = self.draft_paths(id)?;
        write_json_atomic(&paths.metadata, &status.draft, true)?;
        self.status(id)
    }

    /// Record explicit publish intent only for the currently reviewed bytes.
    pub fn confirm_submission_intent(
        &self,
        id: &str,
        expected_inventory_hash: &str,
    ) -> Result<DraftStatus, StudioError> {
        let mut status = self.status(id)?;
        if !status.review_current {
            return Err(StudioError::ReviewNotCurrent);
        }
        if status.publication.inventory_hash != expected_inventory_hash {
            return Err(StudioError::ReviewHashMismatch);
        }
        status.draft.submission_intent = Some(SubmissionIntent {
            revision: status.draft.revision,
            inventory_hash: status.publication.inventory_hash.clone(),
        });
        let paths = self.draft_paths(id)?;
        write_json_atomic(&paths.metadata, &status.draft, true)?;
        self.status(id)
    }

    /// Freeze the exact reviewed and intent-confirmed public files into memory.
    pub fn snapshot_for_submission(
        &self,
        id: &str,
        expected_inventory_hash: &str,
    ) -> Result<DraftSnapshot, StudioError> {
        let status = self.status(id)?;
        if !status.submission_intent_current {
            return Err(StudioError::SubmissionIntentNotCurrent);
        }
        if status.publication.inventory_hash != expected_inventory_hash {
            return Err(StudioError::ReviewHashMismatch);
        }

        let paths = self.draft_paths(id)?;
        let mut files = Vec::with_capacity(status.publication.inventory.len());
        for entry in &status.publication.inventory {
            let relative = path_from_public_string(&entry.path)?;
            let bytes = read_regular_nofollow(&paths.content.join(relative), MAX_FILE_SIZE)?;
            let digest = hex::encode(Sha256::digest(&bytes));
            if bytes.len() as u64 != entry.size || digest != entry.sha256 {
                return Err(StudioError::SnapshotChanged);
            }
            files.push(SnapshotFile {
                path: entry.path.clone(),
                bytes,
            });
        }

        let final_report = validate_directory(&paths.content)?;
        if final_report != status.publication {
            return Err(StudioError::SnapshotChanged);
        }
        Ok(DraftSnapshot {
            revision: status.draft.revision,
            publication: status.publication,
            files,
        })
    }

    /// Resolve and verify the private and public paths for one draft.
    fn draft_paths(&self, id: &str) -> Result<DraftPaths, StudioError> {
        validate_draft_id(id)?;
        let draft = self.root.join(id);
        let draft_metadata = fs::symlink_metadata(&draft).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StudioError::NotFound
            } else {
                StudioError::Io(error)
            }
        })?;
        if draft_metadata.file_type().is_symlink() || !draft_metadata.is_dir() {
            return Err(StudioError::NotFound);
        }
        let content = draft.join(CONTENT_DIRECTORY);
        let content_metadata = fs::symlink_metadata(&content)?;
        if content_metadata.file_type().is_symlink() || !content_metadata.is_dir() {
            return Err(StudioError::InvalidMetadata(
                "content root must be a real directory".to_string(),
            ));
        }
        Ok(DraftPaths {
            metadata: draft.join(METADATA_FILENAME),
            content,
        })
    }

    /// Build one complete hidden draft directory without publishing its ID.
    fn prepare_staging(
        &self,
        id: &str,
        title: &str,
    ) -> Result<(tempfile::TempDir, Draft), StudioError> {
        validate_draft_id(id)?;
        validate_title(title)?;
        ensure_missing_draft(&self.root.join(id))?;
        let staging = tempfile::Builder::new()
            .prefix(".draft-staging-")
            .tempdir_in(&self.root)?;
        fs::create_dir(staging.path().join(CONTENT_DIRECTORY))?;
        let draft = Draft {
            schema_version: DRAFT_SCHEMA_VERSION,
            id: id.to_string(),
            title: title.to_string(),
            revision: 0,
            review: None,
            submission_intent: None,
        };
        write_json_atomic(&staging.path().join(METADATA_FILENAME), &draft, false)?;
        sync_directory(staging.path());
        Ok((staging, draft))
    }

    /// Atomically publish one complete hidden draft directory under its ID.
    fn publish_staging(&self, staging: tempfile::TempDir, id: &str) -> Result<(), StudioError> {
        let destination = self.root.join(id);
        ensure_missing_draft(&destination)?;
        match fs::rename(staging.path(), &destination) {
            Ok(()) => {
                let _ = staging.keep();
                sync_directory(&self.root);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(StudioError::AlreadyExists)
            }
            Err(error) => Err(StudioError::Io(error)),
        }
    }
}

/// Build the editable local-only manifest used by the blank template.
fn blank_template_manifest(name: &str) -> PackManifest {
    PackManifest {
        schema_version: 1,
        name: name.to_string(),
        author_handle: "local".to_string(),
        author_pubkey: LOCAL_UNSIGNED_PUBKEY.to_string(),
        version: "0.1.0".to_string(),
        parent_hash: None,
        license: None,
        forkable: false,
        forked_from: None,
        capability_manifest: None,
        requires: None,
        tokens_required: None,
        extends: None,
        mixin: Vec::new(),
        conformance_baseline: None,
        description: Some("Describe this persona before publishing.".to_string()),
        tags: Vec::new(),
    }
}

/// Build the minimal typed persona source used by the blank template.
fn blank_template_persona(name: &str) -> Persona {
    let mut persona = Persona::new(name);
    persona.version = Some("0.1.0".to_string());
    persona.description = Some("Describe this persona before publishing.".to_string());
    persona.voice.tone = "Define this persona's voice before publishing.".to_string();
    persona
}

/// Build a public manifest from already validated guided fields.
fn guided_template_manifest(input: &GuidedTemplateInput) -> PackManifest {
    PackManifest {
        schema_version: 1,
        name: input.name.clone(),
        author_handle: input.author_handle.clone(),
        author_pubkey: input.author_pubkey.clone(),
        version: input.version.clone(),
        parent_hash: None,
        license: input.license.clone(),
        forkable: input.forkable,
        forked_from: None,
        capability_manifest: None,
        requires: None,
        tokens_required: None,
        extends: None,
        mixin: Vec::new(),
        conformance_baseline: None,
        description: Some(input.description.clone()),
        tags: Vec::new(),
    }
}

/// Build typed persona source from already validated guided fields.
fn guided_template_persona(input: &GuidedTemplateInput) -> Persona {
    let mut persona = Persona::new(&input.name);
    persona.version = Some(input.version.clone());
    persona.description = Some(input.description.clone());
    persona.license = input.license.clone();
    persona.author = Some(Author {
        handle: input.author_handle.clone(),
        pubkey: Some(input.author_pubkey.clone()),
    });
    persona.voice.tone = input.voice_tone.clone();
    persona
}

/// Validate every guided public field before any staging directory is created.
fn validate_guided_template(input: &GuidedTemplateInput) -> Result<(), StudioError> {
    if !valid_portable_identifier(&input.name, 64) {
        return Err(StudioError::InvalidTemplateField("name"));
    }
    if semver::Version::parse(&input.version).is_err() || input.version.len() > 64 {
        return Err(StudioError::InvalidTemplateField("version"));
    }
    if !valid_portable_identifier(&input.author_handle, 64) {
        return Err(StudioError::InvalidTemplateField("author_handle"));
    }
    if input.author_pubkey.len() != 64
        || !input
            .author_pubkey
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StudioError::InvalidTemplateField("author_pubkey"));
    }
    if !valid_public_text(&input.description, 500) {
        return Err(StudioError::InvalidTemplateField("description"));
    }
    if !valid_public_text(&input.voice_tone, 500) {
        return Err(StudioError::InvalidTemplateField("voice_tone"));
    }
    if input.license.as_ref().is_some_and(|license| {
        !(1..=64).contains(&license.len())
            || !license
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    }) {
        return Err(StudioError::InvalidTemplateField("license"));
    }
    Ok(())
}

/// Return whether a value is one bounded portable public identifier.
fn valid_portable_identifier(value: &str, max_bytes: usize) -> bool {
    (1..=max_bytes).contains(&value.len())
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Return whether public prose is non-empty, bounded, and control-free.
fn valid_public_text(value: &str, max_chars: usize) -> bool {
    let count = value.chars().count();
    (1..=max_chars).contains(&count) && !value.chars().any(char::is_control)
}

/// Validate a draft identifier as one stable portable path component.
fn validate_draft_id(id: &str) -> Result<(), StudioError> {
    let valid_length = (1..=64).contains(&id.len());
    let mut bytes = id.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_rest = bytes
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte));
    if valid_length && valid_first && valid_rest {
        Ok(())
    } else {
        Err(StudioError::InvalidDraftId)
    }
}

/// Validate a bounded non-empty user-facing title.
fn validate_title(title: &str) -> Result<(), StudioError> {
    let length = title.chars().count();
    if title.trim().is_empty() || length > MAX_TITLE_CHARS {
        Err(StudioError::InvalidTitle)
    } else {
        Ok(())
    }
}

/// Require one draft destination to be absent without hiding inspection errors.
fn ensure_missing_draft(path: &Path) -> Result<(), StudioError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(StudioError::AlreadyExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StudioError::Io(error)),
    }
}

/// Convert one normalized public path string into a safe relative path.
fn path_from_public_string(raw: &str) -> Result<PathBuf, StudioError> {
    let path = Path::new(raw);
    if raw.is_empty()
        || raw.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || !is_allowed_public_path(raw)
    {
        return Err(StudioError::InvalidContentPath);
    }
    Ok(path.to_path_buf())
}

/// Return whether a publication finding means an import cannot be copied safely.
fn import_blocking_code(code: &str) -> bool {
    code.starts_with("entry.") || code.starts_with("limits.") || code.starts_with("path.")
}

/// Clear review state and increment revision before any content mutation.
fn invalidate_before_mutation(draft: &mut Draft) -> Result<(), StudioError> {
    draft.revision = draft
        .revision
        .checked_add(1)
        .ok_or_else(|| StudioError::InvalidMetadata("revision overflow".to_string()))?;
    draft.review = None;
    draft.submission_intent = None;
    Ok(())
}

/// Return whether review metadata binds to the exact fresh inventory.
fn review_matches(draft: &Draft, report: &PublicationReport) -> bool {
    report.valid
        && draft.review.as_ref().is_some_and(|review| {
            review.revision == draft.revision && review.inventory_hash == report.inventory_hash
        })
}

/// Read a bounded regular file without following a final symlink on Unix.
fn read_regular_nofollow(path: &Path, limit: u64) -> Result<Vec<u8>, StudioError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(StudioError::UnsafeImport(
            "source entry is not a bounded regular file".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit || bytes.len() as u64 != metadata.len() {
        return Err(StudioError::UnsafeImport(
            "source entry changed while it was read".to_string(),
        ));
    }
    Ok(bytes)
}

/// Serialize one value and atomically persist it as JSON.
fn write_json_atomic<T: Serialize>(
    path: &Path,
    value: &T,
    replace: bool,
) -> Result<(), StudioError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_bytes_atomic(path, &bytes, replace)
}

/// Atomically persist bytes using a same-directory temporary file.
fn write_bytes_atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<(), StudioError> {
    let parent = path.parent().ok_or(StudioError::InvalidContentPath)?;
    ensure_directory_chain(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if replace {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    }
    .map_err(|error| StudioError::Io(error.error))?;
    sync_directory(parent);
    Ok(())
}

/// Create missing directories one component at a time and reject symlinks.
fn ensure_directory_chain(path: &Path) -> Result<(), StudioError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_directory_chain(parent)?;
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(StudioError::InvalidContentPath),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            Ok(())
        }
        Err(error) => Err(StudioError::Io(error)),
    }
}

/// Best-effort sync a directory after publishing a filesystem entry.
fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
/// Focused tests for draft persistence and trust-boundary behavior.
mod tests {
    use super::*;

    /// Deterministic 32-byte public-key encoding used by publication fixtures.
    const TEST_PUBLIC_KEY: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    /// Write a minimal valid freeform pack into a directory.
    fn write_valid_pack(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"test\"\nauthor_handle = \"tester\"\nauthor_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"0.1.0\"\n"
            ),
        )
        .unwrap();
        fs::write(root.join("AGENTS.md"), "# Test\n\nPrecise behavior.\n").unwrap();
    }

    /// Write a minimal valid pack with structured source for target previews.
    fn write_typed_pack(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"preview\"\nauthor_handle = \"tester\"\nauthor_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"0.1.0\"\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join("persona.toml"),
            "schema_version = 1\nname = \"preview\"\nversion = \"0.1.0\"\n\
             description = \"Preview fixture\"\n\n[voice]\ntone = \"Precise and calm.\"\n",
        )
        .unwrap();
    }

    /// Build one valid guided template input with a real public-key shape.
    fn guided_template_input() -> GuidedTemplateInput {
        GuidedTemplateInput {
            name: "guided".to_string(),
            version: "0.1.0".to_string(),
            author_handle: "tester".to_string(),
            author_pubkey: TEST_PUBLIC_KEY.to_string(),
            description: "A precise guided persona.".to_string(),
            voice_tone: "Precise, calm, and evidence-driven.".to_string(),
            license: Some("MIT".to_string()),
            forkable: true,
        }
    }

    /// Blank templates are typed and previewable but remain local-only.
    #[test]
    fn blank_template_is_previewable_and_publication_invalid() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let status = studio
            .create_template("blank", "Blank", DraftTemplate::Blank)
            .unwrap();

        assert!(!status.publication.valid);
        assert!(status
            .publication
            .findings
            .iter()
            .any(|finding| finding.code == "manifest.local_unsigned"));
        assert_eq!(studio.preview("blank").unwrap().targets.len(), 4);
    }

    /// Guided templates atomically create valid typed public source.
    #[test]
    fn guided_template_is_valid_and_previewable() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let status = studio
            .create_template(
                "guided",
                "Guided",
                DraftTemplate::Guided(guided_template_input()),
            )
            .unwrap();

        assert!(status.publication.valid);
        let preview = studio.preview("guided").unwrap();
        assert_eq!(preview.targets.len(), 4);
        assert!(preview.targets[0]
            .content
            .contains("Precise, calm, and evidence-driven."));
        let manifest = studio.read_file("guided", "pack.toml").unwrap();
        let parsed: PackManifest = toml::from_str(std::str::from_utf8(&manifest).unwrap()).unwrap();
        assert!(parsed.forkable);
        assert_eq!(parsed.license.as_deref(), Some("MIT"));
    }

    /// Invalid guided fields fail before any destination draft is published.
    #[test]
    fn invalid_guided_template_leaves_no_draft() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let mut input = guided_template_input();
        input.version = "../mutable".to_string();

        assert!(matches!(
            studio.create_template("guided", "Guided", DraftTemplate::Guided(input)),
            Err(StudioError::InvalidTemplateField("version"))
        ));
        assert!(matches!(
            studio.status("guided"),
            Err(StudioError::NotFound)
        ));
    }

    /// Typed TOML serialization preserves quotes, backslashes, and Unicode safely.
    #[test]
    fn guided_template_serializes_public_text_without_injection() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let mut input = guided_template_input();
        input.description = "Quotes \"stay\" data, and Unicode stays café.".to_string();
        input.voice_tone = r"Literal backslashes \ remain prose.".to_string();
        studio
            .create_template("guided", "Guided", DraftTemplate::Guided(input.clone()))
            .unwrap();

        let persona = studio.read_file("guided", "persona.toml").unwrap();
        let parsed: Persona = toml::from_str(std::str::from_utf8(&persona).unwrap()).unwrap();
        assert_eq!(
            parsed.description.as_deref(),
            Some(input.description.as_str())
        );
        assert_eq!(parsed.voice.tone, input.voice_tone);
    }

    /// Create, reload, review, and submit a valid draft across store instances.
    #[test]
    fn lifecycle_persists_across_restarts() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.create("test-draft", "Test draft").unwrap();
        studio
            .write_file(
                "test-draft",
                "pack.toml",
                format!(
                    "schema_version = 1\nname = \"test\"\nauthor_handle = \"tester\"\nauthor_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"0.1.0\"\n"
                )
                .as_bytes(),
            )
            .unwrap();
        studio
            .write_file("test-draft", "AGENTS.md", b"# Test\n\nPrecise behavior.\n")
            .unwrap();
        let inventory_hash = studio
            .status("test-draft")
            .unwrap()
            .publication
            .inventory_hash;
        let reviewed = studio
            .confirm_review("test-draft", &inventory_hash)
            .unwrap();
        assert!(reviewed.review_current);
        let intended = studio
            .confirm_submission_intent("test-draft", &inventory_hash)
            .unwrap();
        assert!(intended.submission_intent_current);

        let reopened = Studio::open(temporary.path().join("studio")).unwrap();
        let status = reopened.status("test-draft").unwrap();
        assert!(status.review_current);
        assert!(status.submission_intent_current);
        assert_eq!(reopened.list().unwrap()[0].title, "Test draft");
    }

    /// Snapshotting requires current intent and returns only the reviewed public bytes.
    #[test]
    fn snapshot_requires_current_intent_and_freezes_public_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let inventory_hash = imported.publication.inventory_hash;

        let error = match studio.snapshot_for_submission("draft", &inventory_hash) {
            Ok(_) => panic!("unreviewed draft must not freeze"),
            Err(error) => error,
        };
        assert!(matches!(error, StudioError::SubmissionIntentNotCurrent));
        studio.confirm_review("draft", &inventory_hash).unwrap();
        studio
            .confirm_submission_intent("draft", &inventory_hash)
            .unwrap();

        let snapshot = studio
            .snapshot_for_submission("draft", &inventory_hash)
            .unwrap();
        assert_eq!(snapshot.publication().inventory_hash, inventory_hash);
        assert_eq!(snapshot.files().len(), 2);
        assert!(snapshot
            .files()
            .iter()
            .all(|file| !file.path().contains("draft.json")));
        assert_eq!(
            snapshot
                .files()
                .iter()
                .find(|file| file.path() == "AGENTS.md")
                .unwrap()
                .bytes(),
            b"# Test\n\nPrecise behavior.\n"
        );
    }

    /// Preview renders every target deterministically from one exact typed inventory.
    #[test]
    fn preview_renders_all_targets_with_exact_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_typed_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();

        let first = studio.preview("draft").unwrap();
        let second = studio.preview("draft").unwrap();
        assert_eq!(first.revision, imported.draft.revision);
        assert_eq!(first.inventory_hash, imported.publication.inventory_hash);
        assert_eq!(first.publication, imported.publication);
        assert_eq!(first.targets.len(), 4);
        assert_eq!(
            first
                .targets
                .iter()
                .map(|preview| preview.target.as_str())
                .collect::<Vec<_>>(),
            ["claude", "codex", "gemini", "generic"]
        );
        assert_eq!(
            first
                .targets
                .iter()
                .map(|preview| preview.install_filename.as_str())
                .collect::<Vec<_>>(),
            ["CLAUDE.md", "AGENTS.md", "GEMINI.md", "AGENTS.md"]
        );
        for (left, right) in first.targets.iter().zip(&second.targets) {
            assert_eq!(left.target, right.target);
            assert_eq!(left.content, right.content);
            assert_eq!(left.sha256, right.sha256);
            assert_eq!(
                left.sha256,
                hex::encode(Sha256::digest(left.content.as_bytes()))
            );
        }
        let claude = &first.targets[0].content;
        let codex = &first.targets[1].content;
        assert_ne!(claude, codex);
    }

    /// Missing or malformed typed source fails without exposing the managed root.
    #[test]
    fn preview_rejects_invalid_source_without_path_leak() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio_root = temporary.path().join("private-studio-root");
        let studio = Studio::open(&studio_root).unwrap();
        studio.import("draft", "Draft", &source).unwrap();

        let missing = match studio.preview("draft") {
            Ok(_) => panic!("preview without typed source must fail"),
            Err(error) => error.to_string(),
        };
        assert_eq!(missing, "draft preview requires valid typed persona source");
        assert!(!missing.contains(studio_root.to_str().unwrap()));

        studio
            .write_file("draft", "persona.toml", b"not valid typed source")
            .unwrap();
        let malformed = match studio.preview("draft") {
            Ok(_) => panic!("preview with malformed typed source must fail"),
            Err(error) => error.to_string(),
        };
        assert_eq!(
            malformed,
            "draft preview requires valid typed persona source"
        );
        assert!(!malformed.contains(studio_root.to_str().unwrap()));
    }

    /// Preview refuses a typed source file replaced by a symlink.
    #[cfg(unix)]
    #[test]
    fn preview_rejects_source_symlink_substitution() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_typed_pack(&source);
        let studio_root = temporary.path().join("studio");
        let studio = Studio::open(&studio_root).unwrap();
        studio.import("draft", "Draft", &source).unwrap();
        let persona_path = studio_root
            .join("draft")
            .join(CONTENT_DIRECTORY)
            .join("persona.toml");
        fs::remove_file(&persona_path).unwrap();
        symlink("/etc/passwd", &persona_path).unwrap();

        assert!(matches!(
            studio.preview("draft"),
            Err(StudioError::InvalidPreviewSource)
        ));
    }

    /// Any content mutation clears review and submission intent before saving.
    #[test]
    fn edit_invalidates_review_and_submission_intent() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();
        let inventory_hash = studio.status("draft").unwrap().publication.inventory_hash;
        studio.confirm_review("draft", &inventory_hash).unwrap();
        studio
            .confirm_submission_intent("draft", &inventory_hash)
            .unwrap();

        let status = studio
            .write_file("draft", "AGENTS.md", b"# Changed\n")
            .unwrap();
        assert!(!status.review_current);
        assert!(!status.submission_intent_current);
        assert!(status.draft.review.is_none());
        assert!(status.draft.submission_intent.is_none());
    }

    /// Traversal and non-public file paths never reach the filesystem.
    #[test]
    fn write_rejects_traversal_and_private_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.create("draft", "Draft").unwrap();
        assert!(matches!(
            studio.write_file("draft", "../secret", b"x"),
            Err(StudioError::InvalidContentPath)
        ));
        assert!(matches!(
            studio.write_file("draft", ".env", b"x"),
            Err(StudioError::InvalidContentPath)
        ));
        assert!(matches!(
            studio.write_file("draft", "/tmp/escape", b"x"),
            Err(StudioError::InvalidContentPath)
        ));
    }

    /// Import refuses a symlink instead of dereferencing outside content.
    #[cfg(unix)]
    #[test]
    fn import_rejects_nested_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        symlink("/etc/passwd", source.join("README.md")).unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        assert!(matches!(
            studio.import("draft", "Draft", &source),
            Err(StudioError::UnsafeImport(code)) if code == "entry.symlink"
        ));
        assert!(studio.list().unwrap().is_empty());
    }

    /// Stale temporary artifacts do not replace the last complete metadata.
    #[test]
    fn stale_temporary_file_does_not_affect_recovery() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let created = studio.create("draft", "Draft").unwrap();
        fs::write(
            temporary
                .path()
                .join("studio/draft/.draft.json.interrupted"),
            b"{",
        )
        .unwrap();

        assert_eq!(studio.load("draft").unwrap(), created);
    }

    /// Unsupported persisted schemas fail closed.
    #[test]
    fn unsupported_schema_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.create("draft", "Draft").unwrap();
        let metadata = temporary.path().join("studio/draft/draft.json");
        let raw = fs::read_to_string(&metadata).unwrap();
        fs::write(
            &metadata,
            raw.replace("\"schema_version\": 1", "\"schema_version\": 99"),
        )
        .unwrap();

        assert!(matches!(
            studio.load("draft"),
            Err(StudioError::InvalidMetadata(message)) if message == "unsupported schema version"
        ));
    }

    /// Review confirmation fails if content changed after the inventory was shown.
    #[test]
    fn review_requires_the_presented_inventory_hash() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        studio
            .write_file("draft", "AGENTS.md", b"# Changed after preview\n")
            .unwrap();

        assert!(matches!(
            studio.confirm_review("draft", &imported.publication.inventory_hash),
            Err(StudioError::ReviewHashMismatch)
        ));
    }
}

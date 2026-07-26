//! Secure local draft lifecycle for Creator Studio clients.
//!
//! Draft metadata is kept outside the publishable content directory. Every
//! review is bound to the deterministic publication inventory hash, and every
//! mutation invalidates review and submission state before content changes.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use frameshift_conformance::{
    bundle_hash, run_bundle, ConformanceError, ConformanceTestResult, Runner, TestBundle,
};
use frameshift_pack::{ForkOrigin, ObjectHash, PackManifest, LOCAL_UNSIGNED_PUBKEY};
use frameshift_publication::{
    is_allowed_public_path, validate_directory, FindingSeverity, PublicationReport, MAX_FILE_SIZE,
};
use frameshift_source::{render_to_markdown, Author, Persona, PersonaSource, RenderTarget};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// Current schema version for persisted draft metadata.
pub const DRAFT_SCHEMA_VERSION: u32 = 1;

/// Current schema version for serialized exact-draft validation reports.
pub const DRAFT_VALIDATION_SCHEMA_VERSION: u32 = 1;

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
    /// Exact prepared artifact and publisher selection shown during review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<PublicationReviewBinding>,
}

/// Explicit intent to submit a previously reviewed inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionIntent {
    /// Draft revision approved for submission.
    pub revision: u64,
    /// Deterministic hash of the approved public files.
    pub inventory_hash: String,
    /// Exact reviewed artifact and publisher selection approved for submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<PublicationReviewBinding>,
}

/// Public non-secret hashes that identify one exact prepared publication artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationBinding {
    /// SHA-256 digest of the exact deterministic gzip-tar bytes.
    pub archive_hash: ObjectHash,
    /// SHA-256 digest of the exact `pack.toml` bytes.
    pub manifest_hash: ObjectHash,
    /// SHA-256 digest of the normalized public file inventory.
    pub file_inventory_hash: ObjectHash,
    /// Version of the shared publication scanner contract.
    pub scan_schema_version: u32,
}

/// Exact artifact and account-owned publisher identity presented for human review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationReviewBinding {
    /// Public hashes of the exact prepared signed artifact.
    pub artifact: PublicationBinding,
    /// Server-assigned publisher selected for the release.
    pub publisher_id: Uuid,
    /// Active publisher key selected to sign the release.
    pub publisher_key_id: Uuid,
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

/// Scanner and conformance result bound to one exact draft revision and inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftValidationReport {
    /// Version of this serialized validation report contract.
    pub schema_version: u32,
    /// Draft revision whose exact bytes were validated.
    pub revision: u64,
    /// Deterministic hash of the exact validated public inventory.
    pub inventory_hash: String,
    /// Shared publication scanner report over the same bytes.
    pub publication: PublicationReport,
    /// Whether both publication policy and applicable conformance gates passed.
    pub valid: bool,
    /// Path-free conformance result for the exact frozen bundle.
    pub conformance: DraftConformanceReport,
}

/// Path-free final review data for one exact prepared publication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftReviewReport {
    /// Draft revision whose exact bytes produced the prepared artifact.
    pub revision: u64,
    /// Shared scanner report containing exact files, hashes, and warnings.
    pub publication: PublicationReport,
    /// Full typed public manifest containing identity, license, and capabilities.
    pub manifest: PackManifest,
    /// Exact artifact hashes and publisher selection requiring human approval.
    pub binding: PublicationReviewBinding,
}

/// Path-free conformance result for one exact frozen draft inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftConformanceReport {
    /// Lifecycle state reached by conformance validation.
    pub status: DraftConformanceStatus,
    /// Whether all applicable conformance gates passed.
    pub valid: bool,
    /// Canonical bundle hash when an executable bundle was present.
    pub bundle_hash: Option<String>,
    /// Aggregate score when the bundle completed.
    pub score: Option<f32>,
    /// Caller-selected minimum aggregate score.
    pub threshold: f32,
    /// Path-free per-test scores in authoritative bundle order.
    pub tests: Vec<ConformanceTestResult>,
    /// Stable path-free findings suitable for user interfaces and automation.
    pub findings: Vec<ConformanceFinding>,
}

/// Lifecycle state reached while validating a draft conformance bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftConformanceStatus {
    /// The pack declares no conformance bundle or baseline.
    NotProvided,
    /// The exact frozen bundle ran to completion.
    Completed,
    /// Publication policy or a conformance invariant prevented execution.
    Blocked,
}

/// One stable path-free conformance finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceFinding {
    /// Stable code for programmatic handling.
    pub code: String,
    /// Whether the finding blocks a valid result.
    pub severity: FindingSeverity,
    /// Optional public test identifier associated with the finding.
    pub test_id: Option<String>,
    /// Human-readable explanation containing no response or local path.
    pub message: String,
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

/// New public identity assigned to an explicitly permitted registry fork.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkIdentityInput {
    /// Stable public name for the distinct derived pack.
    pub name: String,
    /// Initial semantic version for the derived pack.
    pub version: String,
    /// Public author or publisher handle for the derived pack.
    pub author_handle: String,
    /// Exact lowercase Ed25519 verifying key for the derived pack.
    pub author_pubkey: String,
    /// Whether the derived release permits another Creator Studio fork.
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
    /// Prepared artifact or publisher selection does not match the exact current draft.
    #[error("publication review binding does not match current content")]
    ReviewBindingMismatch,
    /// Submission intent requires a current review of the exact content.
    #[error("draft review is not current")]
    ReviewNotCurrent,
    /// Snapshotting requires a current explicit submission intent.
    #[error("draft submission intent is not current")]
    SubmissionIntentNotCurrent,
    /// Draft content changed while an immutable snapshot was being built.
    #[error("draft content changed while it was being frozen")]
    SnapshotChanged,
    /// The requested conformance threshold is non-finite or outside `0.0..=1.0`.
    #[error("conformance threshold must be finite and within 0.0..=1.0")]
    InvalidConformanceThreshold,
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
    /// The signed source manifest did not explicitly permit Creator Studio forks.
    #[error("source pack does not explicitly permit forking")]
    SourceNotForkable,
    /// The verified registry provenance does not identify the signed source manifest.
    #[error("verified fork source identity does not match its signed manifest")]
    ForkSourceMismatch,
    /// Generated fork content did not pass the shared publication policy.
    #[error("forked draft failed shared validation")]
    InvalidGeneratedFork,
    /// Source typed TOML could not be deserialized for an identity rewrite.
    #[error("fork source TOML could not be parsed")]
    ForkSourceToml(#[source] toml::de::Error),
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

    /// Atomically copy and re-identify an explicitly permitted verified registry source.
    pub fn fork_import(
        &self,
        id: &str,
        title: &str,
        source: impl AsRef<Path>,
        origin: ForkOrigin,
        identity: ForkIdentityInput,
    ) -> Result<DraftStatus, StudioError> {
        validate_fork_identity(&identity)?;
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

        let manifest_bytes = read_regular_nofollow(&source.join("pack.toml"), MAX_FILE_SIZE)?;
        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|_| StudioError::InvalidMetadata("pack.toml is not UTF-8".to_string()))?;
        let mut manifest: PackManifest =
            toml::from_str(manifest_text).map_err(StudioError::ForkSourceToml)?;
        if !manifest.forkable {
            return Err(StudioError::SourceNotForkable);
        }
        if manifest.name != origin.name || manifest.version != origin.version {
            return Err(StudioError::ForkSourceMismatch);
        }

        let (staging, _) = self.prepare_staging(id, title)?;
        let content = staging.path().join(CONTENT_DIRECTORY);
        for entry in &source_report.inventory {
            let destination = content.join(path_from_public_string(&entry.path)?);
            let bytes = read_regular_nofollow(&source.join(&entry.path), MAX_FILE_SIZE)?;
            write_bytes_atomic(&destination, &bytes, false)?;
        }

        manifest.name = identity.name.clone();
        manifest.version = identity.version.clone();
        manifest.author_handle = identity.author_handle.clone();
        manifest.author_pubkey = identity.author_pubkey.clone();
        manifest.parent_hash = None;
        manifest.forkable = identity.forkable;
        manifest.forked_from = Some(origin);
        manifest.conformance_baseline = None;
        manifest
            .validate_fork_contract()
            .map_err(|error| StudioError::InvalidMetadata(error.to_string()))?;
        let rewritten_manifest =
            toml::to_string(&manifest).map_err(StudioError::TemplateSerialization)?;
        write_bytes_atomic(
            &content.join("pack.toml"),
            rewritten_manifest.as_bytes(),
            true,
        )?;

        let persona_path = content.join("persona.toml");
        if persona_path.is_file() {
            let persona_bytes = read_regular_nofollow(&persona_path, MAX_FILE_SIZE)?;
            let persona_text = std::str::from_utf8(&persona_bytes).map_err(|_| {
                StudioError::InvalidMetadata("persona.toml is not UTF-8".to_string())
            })?;
            let mut persona: Persona =
                toml::from_str(persona_text).map_err(StudioError::ForkSourceToml)?;
            persona.name = identity.name;
            persona.version = Some(identity.version);
            persona.author = Some(Author {
                handle: identity.author_handle,
                pubkey: Some(identity.author_pubkey),
            });
            persona.license = manifest.license.clone();
            let rewritten_persona =
                toml::to_string(&persona).map_err(StudioError::TemplateSerialization)?;
            write_bytes_atomic(&persona_path, rewritten_persona.as_bytes(), true)?;
        }

        let copied_report = validate_directory(&content)?;
        if !copied_report.valid {
            return Err(StudioError::InvalidGeneratedFork);
        }
        sync_directory(&content);
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
        let submission_intent_current = review_current && submission_matches(&draft, &publication);
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

    /// Freeze one exact valid inventory so a client can prepare it before review.
    pub fn snapshot_for_review(
        &self,
        id: &str,
        expected_inventory_hash: &str,
    ) -> Result<DraftSnapshot, StudioError> {
        let status = self.status(id)?;
        if !status.publication.valid {
            return Err(StudioError::InvalidForReview);
        }
        if status.publication.inventory_hash != expected_inventory_hash {
            return Err(StudioError::ReviewHashMismatch);
        }
        self.freeze_status(id, status)
    }

    /// Build path-free final review data for one exact prepared artifact.
    pub fn review_report(
        &self,
        id: &str,
        binding: PublicationReviewBinding,
    ) -> Result<DraftReviewReport, StudioError> {
        let status = self.status(id)?;
        validate_review_binding(&status.publication, &binding)?;
        let snapshot = self.freeze_status(id, status)?;
        let manifest_file = snapshot
            .files
            .iter()
            .find(|file| file.path == "pack.toml")
            .ok_or(StudioError::SnapshotChanged)?;
        let manifest = std::str::from_utf8(&manifest_file.bytes)
            .ok()
            .and_then(|raw| toml::from_str::<PackManifest>(raw).ok())
            .ok_or(StudioError::SnapshotChanged)?;
        Ok(DraftReviewReport {
            revision: snapshot.revision,
            publication: snapshot.publication,
            manifest,
            binding,
        })
    }

    /// Confirm human review of the exact prepared artifact and publisher selection.
    pub fn confirm_review(
        &self,
        id: &str,
        binding: PublicationReviewBinding,
    ) -> Result<DraftStatus, StudioError> {
        let mut status = self.status(id)?;
        if !status.publication.valid {
            return Err(StudioError::InvalidForReview);
        }
        validate_review_binding(&status.publication, &binding)?;
        status.draft.review = Some(ReviewConfirmation {
            revision: status.draft.revision,
            inventory_hash: status.publication.inventory_hash.clone(),
            binding: Some(binding),
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
        binding: PublicationReviewBinding,
    ) -> Result<DraftStatus, StudioError> {
        let mut status = self.status(id)?;
        if !status.review_current {
            return Err(StudioError::ReviewNotCurrent);
        }
        if status
            .draft
            .review
            .as_ref()
            .and_then(|review| review.binding)
            != Some(binding)
        {
            return Err(StudioError::ReviewBindingMismatch);
        }
        status.draft.submission_intent = Some(SubmissionIntent {
            revision: status.draft.revision,
            inventory_hash: status.publication.inventory_hash.clone(),
            binding: Some(binding),
        });
        let paths = self.draft_paths(id)?;
        write_json_atomic(&paths.metadata, &status.draft, true)?;
        self.status(id)
    }

    /// Freeze the exact reviewed and intent-confirmed public files into memory.
    pub fn snapshot_for_submission(
        &self,
        id: &str,
        binding: PublicationReviewBinding,
    ) -> Result<DraftSnapshot, StudioError> {
        let status = self.status(id)?;
        if !status.submission_intent_current {
            return Err(StudioError::SubmissionIntentNotCurrent);
        }
        if status
            .draft
            .submission_intent
            .as_ref()
            .and_then(|intent| intent.binding)
            != Some(binding)
        {
            return Err(StudioError::ReviewBindingMismatch);
        }

        self.freeze_status(id, status)
    }

    /// Run scanner and conformance validation against one exact frozen draft inventory.
    ///
    /// The caller-supplied runner must already be scoped to the persona under test.
    /// Raw responses are scored inside the shared executor and never enter the report.
    pub async fn validate_draft(
        &self,
        id: &str,
        threshold: f32,
        runner: &dyn Runner,
    ) -> Result<DraftValidationReport, StudioError> {
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            return Err(StudioError::InvalidConformanceThreshold);
        }

        let status = self.status(id)?;
        if !status.publication.valid {
            let report = validation_report(
                &status,
                blocked_conformance(
                    threshold,
                    "publication.invalid",
                    "publication policy must pass before conformance execution",
                ),
            );
            self.ensure_status_current(id, report.revision, &report.publication)?;
            return Ok(report);
        }

        let snapshot = self.freeze_status(id, status)?;
        let Some(manifest_file) = snapshot.files.iter().find(|file| file.path == "pack.toml")
        else {
            return Err(StudioError::SnapshotChanged);
        };
        let manifest = std::str::from_utf8(&manifest_file.bytes)
            .ok()
            .and_then(|raw| toml::from_str::<PackManifest>(raw).ok())
            .ok_or(StudioError::SnapshotChanged)?;
        let bundle_file = snapshot
            .files
            .iter()
            .find(|file| file.path == "conformance/bundle.toml");

        let conformance =
            match bundle_file {
                None => DraftConformanceReport {
                    status: DraftConformanceStatus::NotProvided,
                    valid: true,
                    bundle_hash: None,
                    score: None,
                    threshold,
                    tests: Vec::new(),
                    findings: vec![ConformanceFinding {
                        code: "conformance.not_provided".to_string(),
                        severity: FindingSeverity::Warning,
                        test_id: None,
                        message: "pack declares no conformance bundle or baseline".to_string(),
                    }],
                },
                Some(file) => {
                    let bundle = match std::str::from_utf8(&file.bytes)
                        .ok()
                        .and_then(|raw| toml::from_str::<TestBundle>(raw).ok())
                    {
                        Some(bundle) => bundle,
                        None => {
                            return Ok(validation_report_from_snapshot(
                                &snapshot,
                                blocked_conformance(
                                    threshold,
                                    "conformance.bundle_invalid",
                                    "conformance bundle does not match the shared schema",
                                ),
                            ));
                        }
                    };
                    if bundle.name != manifest.name || bundle.version != manifest.version {
                        blocked_conformance(
                            threshold,
                            "conformance.identity_mismatch",
                            "conformance bundle identity must match the pack manifest",
                        )
                    } else if bundle.tests.is_empty() {
                        blocked_conformance(
                            threshold,
                            "conformance.empty_bundle",
                            "conformance bundle must declare at least one test",
                        )
                    } else {
                        let exact_hash =
                            bundle_hash(&bundle).map_err(|_| StudioError::SnapshotChanged)?;
                        match run_bundle(&bundle, runner).await {
                        Ok(run) => completed_conformance(
                            threshold,
                            exact_hash,
                            run,
                            manifest.conformance_baseline.as_ref().map(|baseline| baseline.score),
                        ),
                        Err(ConformanceError::UnsupportedCallerScorer(_)) => blocked_conformance(
                            threshold,
                            "conformance.unsupported_caller_scorer",
                            "caller-scored tests require an explicit scoring implementation",
                        ),
                        Err(ConformanceError::Runner(_)) => blocked_conformance(
                            threshold,
                            "conformance.runner_failed",
                            "the conformance runner failed without producing a score",
                        ),
                        Err(_) => blocked_conformance(
                            threshold,
                            "conformance.execution_failed",
                            "conformance execution failed before producing a score",
                        ),
                    }
                    }
                }
            };

        self.ensure_status_current(id, snapshot.revision, &snapshot.publication)?;
        Ok(validation_report_from_snapshot(&snapshot, conformance))
    }

    /// Freeze every scanner-inventoried regular file from one fresh status.
    fn freeze_status(&self, id: &str, status: DraftStatus) -> Result<DraftSnapshot, StudioError> {
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

    /// Prove a previously observed revision and inventory still describe the draft.
    fn ensure_status_current(
        &self,
        id: &str,
        revision: u64,
        publication: &PublicationReport,
    ) -> Result<(), StudioError> {
        let current = self.status(id)?;
        if current.draft.revision != revision || current.publication != *publication {
            return Err(StudioError::SnapshotChanged);
        }
        Ok(())
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

/// Build a combined validation report from a scanner status.
fn validation_report(
    status: &DraftStatus,
    conformance: DraftConformanceReport,
) -> DraftValidationReport {
    DraftValidationReport {
        schema_version: DRAFT_VALIDATION_SCHEMA_VERSION,
        revision: status.draft.revision,
        inventory_hash: status.publication.inventory_hash.clone(),
        valid: status.publication.valid && conformance.valid,
        publication: status.publication.clone(),
        conformance,
    }
}

/// Build a combined validation report from an immutable scanner snapshot.
fn validation_report_from_snapshot(
    snapshot: &DraftSnapshot,
    conformance: DraftConformanceReport,
) -> DraftValidationReport {
    DraftValidationReport {
        schema_version: DRAFT_VALIDATION_SCHEMA_VERSION,
        revision: snapshot.revision,
        inventory_hash: snapshot.publication.inventory_hash.clone(),
        valid: snapshot.publication.valid && conformance.valid,
        publication: snapshot.publication.clone(),
        conformance,
    }
}

/// Build a stable blocked conformance result without exposing a local path or response.
fn blocked_conformance(threshold: f32, code: &str, message: &str) -> DraftConformanceReport {
    DraftConformanceReport {
        status: DraftConformanceStatus::Blocked,
        valid: false,
        bundle_hash: None,
        score: None,
        threshold,
        tests: Vec::new(),
        findings: vec![ConformanceFinding {
            code: code.to_string(),
            severity: FindingSeverity::Error,
            test_id: None,
            message: message.to_string(),
        }],
    }
}

/// Build a completed result and apply caller and manifest score gates.
fn completed_conformance(
    threshold: f32,
    exact_hash: String,
    run: frameshift_conformance::ConformanceRunReport,
    claimed_score: Option<f32>,
) -> DraftConformanceReport {
    let mut findings = run
        .tests
        .iter()
        .filter(|test| test.score < threshold)
        .map(|test| ConformanceFinding {
            code: "conformance.test_below_threshold".to_string(),
            severity: FindingSeverity::Warning,
            test_id: Some(test.id.clone()),
            message: "test score is below the selected aggregate threshold".to_string(),
        })
        .collect::<Vec<_>>();
    if run.score < threshold {
        findings.push(ConformanceFinding {
            code: "conformance.score_below_threshold".to_string(),
            severity: FindingSeverity::Error,
            test_id: None,
            message: "aggregate score is below the selected threshold".to_string(),
        });
    }
    if claimed_score.is_some_and(|score| run.score < score) {
        findings.push(ConformanceFinding {
            code: "conformance.baseline_score_unmet".to_string(),
            severity: FindingSeverity::Error,
            test_id: None,
            message: "aggregate score is below the score claimed by the pack manifest".to_string(),
        });
    }
    findings.sort_by(|left, right| {
        (&left.code, &left.test_id, &left.message).cmp(&(
            &right.code,
            &right.test_id,
            &right.message,
        ))
    });
    let valid = !findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Error);
    DraftConformanceReport {
        status: DraftConformanceStatus::Completed,
        valid,
        bundle_hash: Some(exact_hash),
        score: Some(run.score),
        threshold,
        tests: run.tests,
        findings,
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

/// Validate every new fork identity field before staging derived content.
fn validate_fork_identity(input: &ForkIdentityInput) -> Result<(), StudioError> {
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
            review.revision == draft.revision
                && review.inventory_hash == report.inventory_hash
                && review
                    .binding
                    .as_ref()
                    .is_some_and(|binding| validate_review_binding(report, binding).is_ok())
        })
}

/// Return whether submission metadata exactly repeats the current reviewed binding.
fn submission_matches(draft: &Draft, report: &PublicationReport) -> bool {
    let Some(review) = draft.review.as_ref() else {
        return false;
    };
    draft.submission_intent.as_ref().is_some_and(|intent| {
        intent.revision == draft.revision
            && intent.inventory_hash == report.inventory_hash
            && intent.binding.is_some()
            && intent.binding == review.binding
    })
}

/// Validate non-secret prepared hashes and publisher selection against a scanner report.
fn validate_review_binding(
    report: &PublicationReport,
    binding: &PublicationReviewBinding,
) -> Result<(), StudioError> {
    let manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok());
    let inventory_hash = ObjectHash::from_hex(&report.inventory_hash).ok();
    if !report.valid
        || binding.publisher_id.is_nil()
        || binding.publisher_key_id.is_nil()
        || manifest_hash != Some(binding.artifact.manifest_hash)
        || inventory_hash != Some(binding.artifact.file_inventory_hash)
        || report.schema_version != binding.artifact.scan_schema_version
    {
        return Err(StudioError::ReviewBindingMismatch);
    }
    Ok(())
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
    use std::sync::atomic::{AtomicBool, Ordering};

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

    /// Build a deterministic prepared-artifact and publisher selection for one report.
    fn review_binding(report: &PublicationReport) -> PublicationReviewBinding {
        let manifest = report
            .inventory
            .iter()
            .find(|entry| entry.path == "pack.toml")
            .unwrap();
        PublicationReviewBinding {
            artifact: PublicationBinding {
                archive_hash: ObjectHash::of(b"prepared signed archive"),
                manifest_hash: ObjectHash::from_hex(&manifest.sha256).unwrap(),
                file_inventory_hash: ObjectHash::from_hex(&report.inventory_hash).unwrap(),
                scan_schema_version: report.schema_version,
            },
            publisher_id: Uuid::from_u128(1),
            publisher_key_id: Uuid::from_u128(2),
        }
    }

    /// Write one valid pack with a single built-in conformance test.
    fn write_conformance_pack(
        root: &Path,
        bundle_name: &str,
        bundle_version: &str,
        scorer: &str,
        baseline_score: Option<f32>,
    ) {
        fs::create_dir_all(root.join("conformance")).unwrap();
        let expected = if scorer == "caller" {
            "[tests.expected]\nkind = \"custom\"\nid = \"external-judge\""
        } else {
            "[tests.expected]\nkind = \"contains\"\nvalue = \"hello\""
        };
        let bundle_raw = format!(
            "name = \"{bundle_name}\"\nversion = \"{bundle_version}\"\n\n\
             [[tests]]\nid = \"greets\"\nprompt = \"Return a greeting.\"\n\
             scorer = \"{scorer}\"\n\n{expected}\n"
        );
        fs::write(root.join("conformance/bundle.toml"), &bundle_raw).unwrap();
        let bundle: TestBundle = toml::from_str(&bundle_raw).unwrap();
        let baseline = baseline_score.map(|score| {
            format!(
                "\n[conformance_baseline]\nscore = {score}\nbundle_hash = \"{}\"\n",
                bundle_hash(&bundle).unwrap()
            )
        });
        fs::write(
            root.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"test\"\nauthor_handle = \"tester\"\n\
                 author_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"0.1.0\"\n{}",
                baseline.unwrap_or_default()
            ),
        )
        .unwrap();
        fs::write(root.join("AGENTS.md"), "# Test\n\nPrecise behavior.\n").unwrap();
    }

    /// Runner that mutates its draft during the first conformance prompt.
    struct MutatingRunner {
        /// Draft store changed while conformance execution is in flight.
        studio: Studio,
        /// Ensures only the first prompt mutates the draft.
        changed: AtomicBool,
    }

    /// Mutate the source inventory before returning one otherwise passing response.
    #[async_trait::async_trait]
    impl Runner for MutatingRunner {
        /// Change the draft once and then return a passing response.
        async fn run(&self, _prompt: &str) -> Result<String, ConformanceError> {
            if !self.changed.swap(true, Ordering::SeqCst) {
                self.studio
                    .write_file("draft", "AGENTS.md", b"# Changed during validation\n")
                    .map_err(|error| ConformanceError::Runner(error.to_string()))?;
            }
            Ok("hello".to_string())
        }
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

    /// Write one explicitly forkable typed source with attribution and an ignored signature file.
    fn write_forkable_source(root: &Path, forkable: bool) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"source\"\nauthor_handle = \"original\"\n\
                 author_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"1.2.3\"\nlicense = \"MIT\"\n\
                 forkable = {forkable}\ndescription = \"Original purpose\"\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join("persona.toml"),
            format!(
                "schema_version = 1\nname = \"source\"\nversion = \"1.2.3\"\n\
                 description = \"Original purpose\"\nlicense = \"MIT\"\n\
                 \n[author]\nhandle = \"original\"\npubkey = \"{TEST_PUBLIC_KEY}\"\n\
                 \n[voice]\ntone = \"Original voice.\"\n"
            ),
        )
        .unwrap();
        fs::write(root.join("signature.sig"), [7_u8; 64]).unwrap();
    }

    /// Build a valid distinct identity for a derived fork.
    fn fork_identity_input() -> ForkIdentityInput {
        ForkIdentityInput {
            name: "derived".to_string(),
            version: "0.1.0".to_string(),
            author_handle: "new-author".to_string(),
            author_pubkey: TEST_PUBLIC_KEY.to_string(),
            forkable: false,
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

    /// Validation runs the exact frozen bundle and excludes raw responses.
    #[tokio::test]
    async fn validation_returns_path_free_exact_bundle_scores() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_conformance_pack(&source, "test", "0.1.0", "substring", Some(1.0));
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();

        let report = studio
            .validate_draft(
                "draft",
                0.5,
                &frameshift_conformance::MockRunner::new("hello private response"),
            )
            .await
            .unwrap();

        assert!(report.valid);
        assert_eq!(report.revision, imported.draft.revision);
        assert_eq!(report.inventory_hash, imported.publication.inventory_hash);
        assert_eq!(report.conformance.status, DraftConformanceStatus::Completed);
        assert_eq!(report.conformance.score, Some(1.0));
        assert_eq!(report.conformance.tests[0].id, "greets");
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("private response"));
        assert!(!serialized.contains(temporary.path().to_string_lossy().as_ref()));
    }

    /// Packs without a conformance contract remain explicit and non-blocking.
    #[tokio::test]
    async fn validation_reports_conformance_not_provided() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();

        let report = studio
            .validate_draft(
                "draft",
                0.5,
                &frameshift_conformance::MockRunner::new("unused"),
            )
            .await
            .unwrap();

        assert!(report.valid);
        assert_eq!(
            report.conformance.status,
            DraftConformanceStatus::NotProvided
        );
        assert_eq!(
            report.conformance.findings[0].code,
            "conformance.not_provided"
        );
    }

    /// Bundle identity must match the exact pack manifest identity.
    #[tokio::test]
    async fn validation_blocks_bundle_identity_mismatch() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_conformance_pack(&source, "other", "0.1.0", "substring", None);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();

        let report = studio
            .validate_draft(
                "draft",
                0.5,
                &frameshift_conformance::MockRunner::new("hello"),
            )
            .await
            .unwrap();

        assert!(!report.valid);
        assert_eq!(
            report.conformance.findings[0].code,
            "conformance.identity_mismatch"
        );
    }

    /// A run below the signed manifest claim blocks a valid report.
    #[tokio::test]
    async fn validation_enforces_claimed_baseline_score() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_conformance_pack(&source, "test", "0.1.0", "substring", Some(1.0));
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();

        let report = studio
            .validate_draft(
                "draft",
                0.0,
                &frameshift_conformance::MockRunner::new("goodbye"),
            )
            .await
            .unwrap();

        assert!(!report.valid);
        assert!(report
            .conformance
            .findings
            .iter()
            .any(|finding| finding.code == "conformance.baseline_score_unmet"));
    }

    /// Caller scorers fail closed when no explicit scoring implementation exists.
    #[tokio::test]
    async fn validation_rejects_implicit_caller_scorer() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_conformance_pack(&source, "test", "0.1.0", "caller", None);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();

        let report = studio
            .validate_draft(
                "draft",
                0.5,
                &frameshift_conformance::MockRunner::new("unused"),
            )
            .await
            .unwrap();

        assert!(!report.valid);
        assert_eq!(
            report.conformance.findings[0].code,
            "conformance.unsupported_caller_scorer"
        );
    }

    /// A draft mutation during runner execution makes the result stale.
    #[tokio::test]
    async fn validation_rejects_concurrent_draft_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_conformance_pack(&source, "test", "0.1.0", "substring", None);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        studio.import("draft", "Draft", &source).unwrap();
        let runner = MutatingRunner {
            studio: studio.clone(),
            changed: AtomicBool::new(false),
        };

        let result = studio.validate_draft("draft", 0.5, &runner).await;

        assert!(matches!(result, Err(StudioError::SnapshotChanged)));
    }

    /// Invalid thresholds fail before draft I/O or runner execution.
    #[tokio::test]
    async fn validation_rejects_non_finite_threshold() {
        let temporary = tempfile::tempdir().unwrap();
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let result = studio
            .validate_draft(
                "missing",
                f32::NAN,
                &frameshift_conformance::MockRunner::new("unused"),
            )
            .await;

        assert!(matches!(
            result,
            Err(StudioError::InvalidConformanceThreshold)
        ));
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

    /// Fork import preserves license and provenance while replacing public identity atomically.
    #[test]
    fn fork_import_rewrites_identity_and_preserves_attribution() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        let studio_root = temporary.path().join("studio");
        write_forkable_source(&source, true);
        let studio = Studio::open(&studio_root).unwrap();
        let origin = ForkOrigin {
            name: "source".to_string(),
            version: "1.2.3".to_string(),
            content_hash: "a".repeat(64),
        };

        let status = studio
            .fork_import(
                "derived",
                "Derived",
                &source,
                origin.clone(),
                fork_identity_input(),
            )
            .unwrap();

        assert!(status.publication.valid);
        let manifest = studio.read_file("derived", "pack.toml").unwrap();
        let manifest: PackManifest =
            toml::from_str(std::str::from_utf8(&manifest).unwrap()).unwrap();
        assert_eq!(manifest.name, "derived");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.author_handle, "new-author");
        assert_eq!(manifest.license.as_deref(), Some("MIT"));
        assert_eq!(manifest.forked_from, Some(origin));
        assert!(!manifest.forkable);
        assert!(manifest.conformance_baseline.is_none());

        let persona = studio.read_file("derived", "persona.toml").unwrap();
        let persona: Persona = toml::from_str(std::str::from_utf8(&persona).unwrap()).unwrap();
        assert_eq!(persona.name, "derived");
        assert_eq!(persona.version.as_deref(), Some("0.1.0"));
        assert_eq!(
            persona.author.as_ref().map(|author| author.handle.as_str()),
            Some("new-author")
        );
        assert_eq!(persona.license.as_deref(), Some("MIT"));
        assert!(!studio_root
            .join("derived")
            .join(CONTENT_DIRECTORY)
            .join("signature.sig")
            .exists());
    }

    /// A legacy or denied source cannot create even a partial destination draft.
    #[test]
    fn non_forkable_source_leaves_no_draft() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_forkable_source(&source, false);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();

        let error = studio
            .fork_import(
                "derived",
                "Derived",
                &source,
                ForkOrigin {
                    name: "source".to_string(),
                    version: "1.2.3".to_string(),
                    content_hash: "b".repeat(64),
                },
                fork_identity_input(),
            )
            .unwrap_err();

        assert!(matches!(error, StudioError::SourceNotForkable));
        assert!(matches!(
            studio.status("derived"),
            Err(StudioError::NotFound)
        ));
    }

    /// Provenance that differs from the signed source identity fails before staging.
    #[test]
    fn fork_source_identity_mismatch_leaves_no_draft() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_forkable_source(&source, true);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();

        let error = studio
            .fork_import(
                "derived",
                "Derived",
                &source,
                ForkOrigin {
                    name: "different".to_string(),
                    version: "1.2.3".to_string(),
                    content_hash: "c".repeat(64),
                },
                fork_identity_input(),
            )
            .unwrap_err();

        assert!(matches!(error, StudioError::ForkSourceMismatch));
        assert!(matches!(
            studio.status("derived"),
            Err(StudioError::NotFound)
        ));
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
        let status = studio.status("test-draft").unwrap();
        let binding = review_binding(&status.publication);
        let reviewed = studio.confirm_review("test-draft", binding).unwrap();
        assert!(reviewed.review_current);
        let intended = studio
            .confirm_submission_intent("test-draft", binding)
            .unwrap();
        assert!(intended.submission_intent_current);

        let reopened = Studio::open(temporary.path().join("studio")).unwrap();
        let status = reopened.status("test-draft").unwrap();
        assert!(status.review_current);
        assert!(status.submission_intent_current);
        assert_eq!(reopened.list().unwrap()[0].title, "Test draft");
    }

    /// Final review data exposes the full public manifest and exact artifact without local paths.
    #[test]
    fn review_report_exposes_path_free_exact_artifact_details() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        fs::write(
            source.join("pack.toml"),
            format!(
                "schema_version = 1\nname = \"test\"\nauthor_handle = \"tester\"\n\
                 author_pubkey = \"{TEST_PUBLIC_KEY}\"\nversion = \"0.1.0\"\n\
                 license = \"MIT\"\n\n[capability_manifest]\n\
                 required_tools = [\"Read\"]\nnetwork_egress = false\n"
            ),
        )
        .unwrap();
        let studio_root = temporary.path().join("private-studio-root");
        let studio = Studio::open(&studio_root).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let binding = review_binding(&imported.publication);
        let snapshot = studio
            .snapshot_for_review("draft", &imported.publication.inventory_hash)
            .unwrap();
        assert_eq!(
            snapshot.publication().inventory_hash,
            imported.publication.inventory_hash
        );

        let report = studio.review_report("draft", binding).unwrap();
        assert_eq!(report.revision, imported.draft.revision);
        assert_eq!(report.publication, imported.publication);
        assert_eq!(report.manifest.license.as_deref(), Some("MIT"));
        assert_eq!(
            report
                .manifest
                .capability_manifest
                .as_ref()
                .unwrap()
                .required_tools,
            ["Read"]
        );
        assert_eq!(report.binding, binding);
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(studio_root.to_str().unwrap()));
    }

    /// Submission intent and snapshots reject any artifact or publisher substitution.
    #[test]
    fn reviewed_binding_rejects_artifact_and_publisher_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let binding = review_binding(&imported.publication);
        studio.confirm_review("draft", binding).unwrap();

        let mut changed_archive = binding;
        changed_archive.artifact.archive_hash = ObjectHash::of(b"substituted archive");
        assert!(matches!(
            studio.confirm_submission_intent("draft", changed_archive),
            Err(StudioError::ReviewBindingMismatch)
        ));

        let mut changed_publisher = binding;
        changed_publisher.publisher_id = Uuid::from_u128(99);
        assert!(matches!(
            studio.confirm_submission_intent("draft", changed_publisher),
            Err(StudioError::ReviewBindingMismatch)
        ));

        let mut changed_key = binding;
        changed_key.publisher_key_id = Uuid::from_u128(100);
        assert!(matches!(
            studio.confirm_submission_intent("draft", changed_key),
            Err(StudioError::ReviewBindingMismatch)
        ));

        studio.confirm_submission_intent("draft", binding).unwrap();
        assert!(matches!(
            studio.snapshot_for_submission("draft", changed_archive),
            Err(StudioError::ReviewBindingMismatch)
        ));
    }

    /// Legacy inventory-only confirmations load safely but never count as current authority.
    #[test]
    fn legacy_inventory_only_confirmation_is_stale() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio_root = temporary.path().join("studio");
        let studio = Studio::open(&studio_root).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let binding = review_binding(&imported.publication);
        studio.confirm_review("draft", binding).unwrap();
        studio.confirm_submission_intent("draft", binding).unwrap();

        let metadata = studio_root.join("draft").join(METADATA_FILENAME);
        let mut persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&metadata).unwrap()).unwrap();
        persisted["review"]
            .as_object_mut()
            .unwrap()
            .remove("binding");
        persisted["submission_intent"]
            .as_object_mut()
            .unwrap()
            .remove("binding");
        fs::write(&metadata, serde_json::to_vec_pretty(&persisted).unwrap()).unwrap();

        let reopened = Studio::open(&studio_root).unwrap();
        let status = reopened.status("draft").unwrap();
        assert!(status.draft.review.is_some());
        assert!(status.draft.submission_intent.is_some());
        assert!(!status.review_current);
        assert!(!status.submission_intent_current);
    }

    /// Nil publisher identities cannot be presented as a valid final review selection.
    #[test]
    fn review_rejects_nil_publisher_identifiers() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let mut binding = review_binding(&imported.publication);
        binding.publisher_id = Uuid::nil();
        assert!(matches!(
            studio.review_report("draft", binding),
            Err(StudioError::ReviewBindingMismatch)
        ));

        binding = review_binding(&imported.publication);
        binding.publisher_key_id = Uuid::nil();
        assert!(matches!(
            studio.confirm_review("draft", binding),
            Err(StudioError::ReviewBindingMismatch)
        ));
    }

    /// Snapshotting requires current intent and returns only the reviewed public bytes.
    #[test]
    fn snapshot_requires_current_intent_and_freezes_public_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let binding = review_binding(&imported.publication);
        let inventory_hash = imported.publication.inventory_hash;

        let error = match studio.snapshot_for_submission("draft", binding) {
            Ok(_) => panic!("unreviewed draft must not freeze"),
            Err(error) => error,
        };
        assert!(matches!(error, StudioError::SubmissionIntentNotCurrent));
        studio.confirm_review("draft", binding).unwrap();
        studio.confirm_submission_intent("draft", binding).unwrap();

        let snapshot = studio.snapshot_for_submission("draft", binding).unwrap();
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
        let imported = studio.import("draft", "Draft", &source).unwrap();
        let binding = review_binding(&imported.publication);
        studio.confirm_review("draft", binding).unwrap();
        studio.confirm_submission_intent("draft", binding).unwrap();

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

    /// Review confirmation fails if content changed after preparation.
    #[test]
    fn review_requires_the_prepared_artifact_binding() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        write_valid_pack(&source);
        let studio = Studio::open(temporary.path().join("studio")).unwrap();
        let imported = studio.import("draft", "Draft", &source).unwrap();
        studio
            .write_file("draft", "AGENTS.md", b"# Changed after preview\n")
            .unwrap();

        assert!(matches!(
            studio.confirm_review("draft", review_binding(&imported.publication)),
            Err(StudioError::ReviewBindingMismatch)
        ));
    }
}

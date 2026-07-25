//! Secure local draft lifecycle for Creator Studio clients.
//!
//! Draft metadata is kept outside the publishable content directory. Every
//! review is bound to the deterministic publication inventory hash, and every
//! mutation invalidates review and submission state before content changes.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use frameshift_publication::{
    is_allowed_public_path, validate_directory, PublicationReport, MAX_FILE_SIZE,
};
use serde::{Deserialize, Serialize};

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

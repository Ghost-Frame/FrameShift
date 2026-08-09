//! Internal server boundary for inspecting and quarantining publication archives.
//!
//! This module deliberately exposes no HTTP route and performs no public object
//! promotion. Callers must inject a store dedicated to quarantine objects.

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::Utc;
use frameshift_catalog::{
    CatalogBackend, CatalogError, Ed25519PublicKey, PackStatus, PackVersionRecord,
    PublicationIntentClaim, PublicationPromotionRecord, PublicationPromotionRequest,
    PublicationSubmissionRecord, PublicationSubmissionRequest, PublicationSubmissionState,
    PublishQuota, PublisherKeyState,
};
use frameshift_objects::{ObjectHash, ObjectStoreError, PackStore};
use frameshift_publication::archive::{
    inspect_public_archive, ArchiveError, InspectedPublicArchive, PublicArchiveExpectation,
    VerifiedPublicPack,
};
use frameshift_publication::{FindingSeverity, PublicationReport};
use uuid::Uuid;

/// Failures while inspecting or admitting a publication archive.
#[derive(Debug, thiserror::Error)]
pub enum PublicationAdmissionError {
    /// The uploaded archive does not match the hash authorized by the intent.
    #[error("publication archive hash does not match the intent")]
    ArchiveHashMismatch,
    /// The archive could not be safely decoded or did not contain one pack root.
    #[error("invalid publication archive: {0}")]
    InvalidArchive(&'static str),
    /// The server-side deterministic scan emitted blocking findings.
    #[error("publication validation failed: {codes}")]
    Validation {
        /// Bounded stable finding codes without local paths.
        codes: String,
    },
    /// A server-observed binding does not match the exact publication intent.
    #[error("publication {field} does not match the intent")]
    IntentMismatch {
        /// Stable name of the mismatched binding.
        field: &'static str,
    },
    /// The quarantine object store rejected or failed the write.
    #[error("publication quarantine write failed")]
    Quarantine(#[source] ObjectStoreError),
    /// The catalog rejected or failed the atomic submission transaction.
    #[error("publication catalog persistence failed")]
    Catalog(#[source] CatalogError),
    /// The archive signature or signing identity is not valid for this publication.
    #[error("publication archive signature is not authorized")]
    Signature,
    /// Internal temporary-file or task execution failed.
    #[error("publication inspection failed")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Route-free application service that admits exact archives to quarantine.
///
/// The injected [`PackStore`] must be isolated from the public download store.
/// This type cannot promote objects or create active catalog versions.
#[derive(Clone)]
pub struct PublicationAdmissionService {
    /// Catalog boundary that atomically consumes intents and creates submissions.
    catalog: Arc<dyn CatalogBackend>,
    /// Non-public object store dedicated to quarantine bytes.
    quarantine: Arc<dyn PackStore>,
}

/// Construction and admission operations for [`PublicationAdmissionService`].
impl PublicationAdmissionService {
    /// Construct a service over an explicit catalog and quarantine-only store.
    pub fn new(catalog: Arc<dyn CatalogBackend>, quarantine: Arc<dyn PackStore>) -> Self {
        Self {
            catalog,
            quarantine,
        }
    }

    /// Validate, quarantine, and persist one exact publication submission.
    ///
    /// All deterministic checks finish before either backend is mutated.
    /// Quarantine storage happens before catalog persistence, so a catalog
    /// failure can leave only an unreachable content-addressed quarantine blob.
    pub async fn admit(
        &self,
        submission_id: Uuid,
        intent: PublicationIntentClaim,
        archive_bytes: Vec<u8>,
    ) -> Result<PublicationSubmissionRecord, PublicationAdmissionError> {
        let archive_hash = ObjectHash::of(&archive_bytes);
        if archive_hash != intent.archive_hash {
            return Err(PublicationAdmissionError::ArchiveHashMismatch);
        }

        let inspected = inspect_publication_archive(&archive_bytes).await?;
        let report = inspected.report().clone();
        enforce_publication_report(&report)?;
        validate_intent_bindings(&intent, &report)?;
        verify_signed_publication(
            &*self.catalog,
            intent.publisher_id,
            intent.publisher_key_id,
            inspected,
            archive_hash,
            true,
        )
        .await?;

        self.quarantine
            .put(&archive_hash, &archive_bytes)
            .await
            .map_err(PublicationAdmissionError::Quarantine)?;

        self.catalog
            .create_publication_submission(PublicationSubmissionRequest {
                id: submission_id,
                intent,
                scan_report: report,
            })
            .await
            .map_err(PublicationAdmissionError::Catalog)
    }
}

/// Failures while promoting one approved quarantine artifact.
#[derive(Debug, thiserror::Error)]
pub enum PublicationPromotionError {
    /// The selected submission does not exist or cannot be read.
    #[error("publication submission lookup failed")]
    Catalog(#[source] CatalogError),
    /// The selected submission has not completed human approval.
    #[error("publication submission is not approved")]
    NotApproved,
    /// The exact quarantine object is absent or unreadable.
    #[error("publication quarantine read failed")]
    Quarantine(#[source] ObjectStoreError),
    /// The quarantine object violates the configured size or hash boundary.
    #[error("publication quarantine artifact failed integrity bounds")]
    Integrity,
    /// Fresh inspection or signature verification failed.
    #[error("publication quarantine verification failed")]
    Verification(#[source] PublicationAdmissionError),
    /// The fresh deterministic report differs from the approved evidence.
    #[error("publication quarantine report differs from approved evidence")]
    ReportMismatch,
    /// The verified manifest contains an invalid catalog field.
    #[error("publication manifest field is invalid: {0}")]
    Manifest(&'static str),
    /// The public object store rejected or failed the write.
    #[error("publication public-object write failed")]
    PublicStore(#[source] ObjectStoreError),
}

/// Route-free service that verifies and activates approved quarantine artifacts.
#[derive(Clone)]
pub struct PublicationPromotionService {
    /// Catalog authority for submission selection and atomic activation.
    catalog: Arc<dyn CatalogBackend>,
    /// Non-public object store containing admitted archive bytes.
    quarantine: Arc<dyn PackStore>,
    /// Public object store used by ordinary pack downloads.
    public: Arc<dyn PackStore>,
    /// Maximum accepted archive size in bytes.
    max_archive_bytes: usize,
    /// Per-publisher and registry limits applied during activation.
    quota: PublishQuota,
}

/// Construction and activation operations for [`PublicationPromotionService`].
impl PublicationPromotionService {
    /// Construct a promotion service over explicitly separated object stores.
    pub fn new(
        catalog: Arc<dyn CatalogBackend>,
        quarantine: Arc<dyn PackStore>,
        public: Arc<dyn PackStore>,
        max_archive_bytes: usize,
        quota: PublishQuota,
    ) -> Self {
        Self {
            catalog,
            quarantine,
            public,
            max_archive_bytes,
            quota,
        }
    }

    /// Re-verify and atomically activate one approved quarantine submission.
    pub async fn promote(
        &self,
        promotion_id: Uuid,
        submission_id: Uuid,
        actor_account_id: Uuid,
        request_id: Uuid,
    ) -> Result<PublicationPromotionRecord, PublicationPromotionError> {
        let submission = self
            .catalog
            .get_publication_submission(submission_id)
            .await
            .map_err(PublicationPromotionError::Catalog)?;
        if !matches!(
            submission.state,
            PublicationSubmissionState::Approved | PublicationSubmissionState::Promoted
        ) {
            return Err(PublicationPromotionError::NotApproved);
        }

        let archive_bytes = self
            .quarantine
            .get(&submission.archive_hash)
            .await
            .map_err(PublicationPromotionError::Quarantine)?;
        if archive_bytes.len() > self.max_archive_bytes
            || ObjectHash::of(&archive_bytes) != submission.archive_hash
        {
            return Err(PublicationPromotionError::Integrity);
        }

        let inspected = inspect_publication_archive(&archive_bytes)
            .await
            .map_err(PublicationPromotionError::Verification)?;
        let report = inspected.report().clone();
        enforce_publication_report(&report).map_err(PublicationPromotionError::Verification)?;
        validate_submission_bindings(&submission, &report)
            .map_err(PublicationPromotionError::Verification)?;
        if report != submission.scan_report {
            return Err(PublicationPromotionError::ReportMismatch);
        }
        let verified = verify_signed_publication(
            &*self.catalog,
            submission.publisher_id,
            submission.publisher_key_id,
            inspected,
            submission.archive_hash,
            submission.state != PublicationSubmissionState::Promoted,
        )
        .await
        .map_err(PublicationPromotionError::Verification)?;

        let version = promotion_version(
            &verified,
            submission.publisher_key_id,
            submission.archive_hash,
            archive_bytes.len(),
        )?;
        self.public
            .put(&submission.archive_hash, &archive_bytes)
            .await
            .map_err(PublicationPromotionError::PublicStore)?;
        self.catalog
            .promote_publication_submission(
                PublicationPromotionRequest {
                    id: promotion_id,
                    submission_id,
                    actor_account_id,
                    request_id,
                    version,
                    description: verified.manifest().description.clone().unwrap_or_default(),
                    tags: verified.manifest().tags.clone(),
                    extends: verified.manifest().extends.clone(),
                },
                self.quota,
            )
            .await
            .map_err(PublicationPromotionError::Catalog)
    }
}

/// Load and verify one signed pack against its catalog-enrolled publisher key.
async fn verify_signed_publication(
    catalog: &dyn CatalogBackend,
    publisher_id: Uuid,
    publisher_key_id: Uuid,
    inspected: InspectedPublicArchive,
    archive_hash: ObjectHash,
    require_active_key: bool,
) -> Result<VerifiedPublicPack, PublicationAdmissionError> {
    let key = catalog
        .get_publisher_key(publisher_key_id)
        .await
        .map_err(PublicationAdmissionError::Catalog)?;
    if key.publisher_id != publisher_id
        || (require_active_key && key.state != PublisherKeyState::Active)
    {
        return Err(PublicationAdmissionError::Signature);
    }
    let signature = inspected
        .embedded_signature()
        .ok_or(PublicationAdmissionError::Signature)?;
    let name = inspected.unverified_manifest().name.clone();
    let version = inspected.unverified_manifest().version.clone();
    inspected
        .verify(PublicArchiveExpectation {
            name: &name,
            version: &version,
            archive_sha256: *archive_hash.as_bytes(),
            author_public_key: key.public_key.0,
            signature,
        })
        .map_err(map_public_archive_error)
}

/// Derive the immutable active catalog version exclusively from verified bytes.
fn promotion_version(
    verified: &VerifiedPublicPack,
    publisher_key_id: Uuid,
    archive_hash: ObjectHash,
    archive_size: usize,
) -> Result<PackVersionRecord, PublicationPromotionError> {
    let manifest = verified.manifest();
    let provenance = verified.provenance();
    let parent_hash = verified
        .manifest()
        .parent_hash
        .as_deref()
        .map(|value| value.strip_prefix("sha256:").unwrap_or(value))
        .map(ObjectHash::from_hex)
        .transpose()
        .map_err(|_| PublicationPromotionError::Manifest("parent_hash"))?;
    let capability_manifest_json = verified
        .manifest()
        .capability_manifest
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| PublicationPromotionError::Manifest("capability_manifest"))?
        .unwrap_or_else(|| "{}".to_string());
    Ok(PackVersionRecord {
        pack_name: manifest.name.clone(),
        version: manifest.version.clone(),
        content_hash: archive_hash,
        signature: provenance.signature.to_vec(),
        author_pubkey: Ed25519PublicKey(provenance.author_public_key),
        publisher_key_id: Some(publisher_key_id),
        parent_hash,
        capability_manifest_json,
        schema_version: manifest.schema_version,
        license: manifest.license.clone().unwrap_or_default(),
        published_at: Utc::now(),
        status: PackStatus::Active,
        size_bytes: u64::try_from(archive_size)
            .map_err(|_| PublicationPromotionError::Integrity)?,
    })
}

/// Inspect a bounded gzip-tar archive without exposing its retained extraction root.
pub(crate) async fn inspect_publication_archive(
    archive_bytes: &[u8],
) -> Result<InspectedPublicArchive, PublicationAdmissionError> {
    let archive_bytes = archive_bytes.to_vec();
    tokio::task::spawn_blocking(move || inspect_public_archive(&archive_bytes))
        .await
        .map_err(|error| PublicationAdmissionError::Internal(Box::new(error)))?
        .map_err(map_public_archive_error)
}

/// Convert shared archive failures into the server's stable admission contract.
pub(crate) fn map_public_archive_error(error: ArchiveError) -> PublicationAdmissionError {
    match error {
        ArchiveError::CompressedSizeLimit => {
            PublicationAdmissionError::InvalidArchive("archive exceeds compressed size limit")
        }
        ArchiveError::DecompressedSizeLimit => {
            PublicationAdmissionError::InvalidArchive("archive exceeds decompressed size limit")
        }
        ArchiveError::InvalidFraming => {
            PublicationAdmissionError::InvalidArchive("archive framing is invalid")
        }
        ArchiveError::EntryLimit => {
            PublicationAdmissionError::InvalidArchive("too many archive entries")
        }
        ArchiveError::UnsupportedEntryType => {
            PublicationAdmissionError::InvalidArchive("non-regular archive entry")
        }
        ArchiveError::UnsafePath | ArchiveError::NonNfcPath => {
            PublicationAdmissionError::InvalidArchive("unsafe archive path")
        }
        ArchiveError::DuplicatePath | ArchiveError::PathTypeCollision => {
            PublicationAdmissionError::InvalidArchive("duplicate archive path")
        }
        ArchiveError::Extraction => {
            PublicationAdmissionError::InvalidArchive("archive extraction failed")
        }
        ArchiveError::InvalidPackRoot => {
            PublicationAdmissionError::InvalidArchive("pack.toml is not at one pack root")
        }
        ArchiveError::ArchiveHashMismatch => PublicationAdmissionError::ArchiveHashMismatch,
        ArchiveError::PublicationRejected { codes } => PublicationAdmissionError::Validation {
            codes: if codes.is_empty() {
                "unknown".to_string()
            } else {
                codes.join(", ")
            },
        },
        ArchiveError::ManifestNameMismatch
        | ArchiveError::ManifestVersionMismatch
        | ArchiveError::SignerKeyMismatch
        | ArchiveError::InvalidVerifyingKey
        | ArchiveError::EmbeddedSignatureMalformed
        | ArchiveError::EmbeddedSignatureMismatch
        | ArchiveError::SignatureMismatch => PublicationAdmissionError::Signature,
        ArchiveError::InvalidPack
        | ArchiveError::InvalidTypedSource
        | ArchiveError::InvalidTemplateManifest
        | ArchiveError::MissingRenderSource => {
            PublicationAdmissionError::InvalidArchive("invalid pack")
        }
        error @ (ArchiveError::TemporaryStorage | ArchiveError::PublicationInspection) => {
            PublicationAdmissionError::Internal(Box::new(error))
        }
    }
}

/// Compare every server-observed report binding with the authorized intent.
fn validate_intent_bindings(
    intent: &PublicationIntentClaim,
    report: &PublicationReport,
) -> Result<(), PublicationAdmissionError> {
    if report.schema_version != intent.scan_schema_version {
        return Err(PublicationAdmissionError::IntentMismatch {
            field: "scan schema",
        });
    }

    let inventory_hash = ObjectHash::from_hex(&report.inventory_hash).map_err(|_| {
        PublicationAdmissionError::IntentMismatch {
            field: "file inventory",
        }
    })?;
    if inventory_hash != intent.file_inventory_hash {
        return Err(PublicationAdmissionError::IntentMismatch {
            field: "file inventory",
        });
    }

    let manifest_hash = report
        .inventory
        .iter()
        .find(|entry| entry.path == "pack.toml")
        .and_then(|entry| ObjectHash::from_hex(&entry.sha256).ok())
        .ok_or(PublicationAdmissionError::IntentMismatch { field: "manifest" })?;
    if manifest_hash != intent.manifest_hash {
        return Err(PublicationAdmissionError::IntentMismatch { field: "manifest" });
    }
    Ok(())
}

/// Compare fresh report bindings with immutable approved submission evidence.
fn validate_submission_bindings(
    submission: &PublicationSubmissionRecord,
    report: &PublicationReport,
) -> Result<(), PublicationAdmissionError> {
    validate_intent_bindings(
        &PublicationIntentClaim {
            id: submission.intent_id,
            account_id: submission.account_id,
            publisher_id: submission.publisher_id,
            publisher_key_id: submission.publisher_key_id,
            archive_hash: submission.archive_hash,
            manifest_hash: submission.manifest_hash,
            file_inventory_hash: submission.file_inventory_hash,
            scan_schema_version: submission.scan_schema_version,
        },
        report,
    )
}

/// Reject a report while exposing only bounded stable finding codes.
pub(crate) fn enforce_publication_report(
    report: &PublicationReport,
) -> Result<(), PublicationAdmissionError> {
    if report.valid {
        return Ok(());
    }
    let codes = report
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::Error)
        .map(|finding| finding.code.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(8)
        .collect::<Vec<_>>()
        .join(", ");
    Err(PublicationAdmissionError::Validation {
        codes: if codes.is_empty() {
            "unknown".to_string()
        } else {
            codes
        },
    })
}

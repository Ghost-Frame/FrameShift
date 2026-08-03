//! Secure local persistence for provider-neutral authenticated sessions.
//!
//! Non-secret configuration is stored in a bounded, versioned, owner-only JSON
//! file. Access and refresh tokens are stored only in the native operating
//! system credential store and are verified by an immediate read-back.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::session::AuthenticatedSession;

/// Current non-secret session metadata schema version.
const SESSION_METADATA_SCHEMA_VERSION: u32 = 2;
/// Legacy OIDC-only metadata schema version accepted during migration.
const LEGACY_SESSION_METADATA_SCHEMA_VERSION: u32 = 1;
/// Current secret payload schema version.
const SESSION_SECRET_SCHEMA_VERSION: u32 = 1;
/// Native credential-store service namespace.
const SESSION_KEYRING_SERVICE: &str = "org.frameshift.account-sessions";
/// Stable relative path for the one active CLI session.
const SESSION_METADATA_REL: &str = "identity/account-session.json";
/// Cross-process session mutation lock.
const SESSION_LOCK_REL: &str = "identity/account-session.lock";
/// Maximum metadata or credential payload size.
const MAX_SESSION_STORAGE_BYTES: u64 = 1024 * 1024;

/// Versioned public metadata for one stored authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSessionMetadata {
    /// On-disk schema version.
    pub schema_version: u32,
    /// Provider-specific public authentication metadata.
    pub authentication: SessionAuthentication,
    /// FrameShift registry API base URL.
    pub registry_url: Url,
    /// Derived native credential-store account.
    pub credential_id: String,
    /// Unix timestamp when this session was saved.
    pub saved_at: u64,
}

/// Loaded metadata plus secret session values.
pub struct StoredSession {
    /// Non-secret session metadata.
    pub metadata: StoredSessionMetadata,
    /// Secret-bearing authenticated session.
    pub session: AuthenticatedSession,
}

/// Redacted stored-session diagnostics.
impl std::fmt::Debug for StoredSession {
    /// Render metadata and the session's redacted representation.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredSession")
            .field("metadata", &self.metadata)
            .field("session", &self.session)
            .finish()
    }
}

/// Inputs used to persist one newly authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStoreMetadata {
    /// Provider-specific public authentication metadata.
    pub authentication: SessionAuthentication,
    /// FrameShift registry API base URL.
    pub registry_url: Url,
}

/// Public metadata needed to manage one authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionAuthentication {
    /// OIDC discovery, refresh, and revocation configuration.
    Oidc {
        /// Exact OIDC issuer.
        issuer: Url,
        /// Public OAuth client identifier.
        client_id: String,
        /// Boxed registered callback URI that keeps the provider enum compact.
        redirect_uri: Box<Url>,
        /// Requested OIDC scopes.
        scopes: Vec<String>,
    },
    /// First-party opaque bearer session managed by the registry.
    FirstParty,
}

/// Schema-v1 OIDC metadata accepted without changing its keyring binding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyStoredSessionMetadata {
    /// Legacy on-disk schema version.
    schema_version: u32,
    /// Exact OIDC issuer.
    issuer: Url,
    /// Public OAuth client identifier.
    client_id: String,
    /// Registered callback URI.
    redirect_uri: Url,
    /// Requested OIDC scopes.
    scopes: Vec<String>,
    /// FrameShift registry API base URL.
    registry_url: Url,
    /// Derived native credential-store account.
    credential_id: String,
    /// Unix timestamp when this session was saved.
    saved_at: u64,
}

/// Current or legacy metadata wire representation.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredSessionMetadataWire {
    /// Current provider-tagged metadata.
    Current(StoredSessionMetadata),
    /// Legacy OIDC-only metadata.
    Legacy(LegacyStoredSessionMetadata),
}

/// Local session persistence manager.
#[derive(Debug, Clone)]
pub struct SessionStore {
    /// FrameShift central data root.
    data_root: PathBuf,
}

/// Session persistence or credential-store failure.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    /// No active session metadata exists.
    #[error("no authenticated FrameShift session is stored")]
    NotFound,
    /// The exact metadata file failed an I/O operation.
    #[error("session metadata operation failed at {path}: {detail}")]
    Io {
        /// Exact affected path.
        path: PathBuf,
        /// Sanitized failure detail.
        detail: String,
    },
    /// Metadata or secret payload validation failed.
    #[error("stored FrameShift session is invalid: {0}")]
    Invalid(String),
    /// Native credential storage failed.
    #[error("native session credential storage failed: {0}")]
    Credential(String),
}

/// Serializable secret payload stored only in the native credential store.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSecretPayload {
    /// Payload schema version.
    schema_version: u32,
    /// Bearer access token.
    access_token: String,
    /// Optional refresh token.
    refresh_token: Option<String>,
    /// Provider-reported lifetime in seconds.
    expires_in: Option<u64>,
    /// Granted scope string.
    scope: Option<String>,
    /// Local token acquisition timestamp.
    acquired_at: u64,
}

/// Wipe deserialized token strings when the payload leaves scope.
impl Drop for SessionSecretPayload {
    /// Zero every secret string.
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = &mut self.refresh_token {
            refresh_token.zeroize();
        }
    }
}

/// Native credential-store boundary.
trait SessionCredentialStore {
    /// Read an existing secret payload.
    fn get(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// Store and read back one secret payload.
    fn put(&self, credential_id: &str, payload: &[u8]) -> Result<(), String>;
    /// Remove one exact credential, returning whether it existed.
    fn delete(&self, credential_id: &str) -> Result<bool, String>;
}

/// Production native credential-store adapter.
struct SystemSessionCredentialStore;

/// Native credential-store operations.
impl SessionCredentialStore for SystemSessionCredentialStore {
    /// Read one credential without rendering its bytes.
    fn get(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, credential_id)
            .map_err(|error| format!("credential entry unavailable: {error}"))?;
        match entry.get_secret() {
            Ok(payload) => Ok(Some(Zeroizing::new(payload))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(format!("credential read failed: {error}")),
        }
    }

    /// Persist one credential and verify exact read-back bytes.
    fn put(&self, credential_id: &str, payload: &[u8]) -> Result<(), String> {
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, credential_id)
            .map_err(|error| format!("credential entry unavailable: {error}"))?;
        entry
            .set_secret(payload)
            .map_err(|error| format!("credential write failed: {error}"))?;
        let stored = Zeroizing::new(
            entry
                .get_secret()
                .map_err(|error| format!("credential read-back failed: {error}"))?,
        );
        if stored.as_slice() != payload {
            return Err("credential read-back did not match stored bytes".to_string());
        }
        Ok(())
    }

    /// Delete one exact native credential.
    fn delete(&self, credential_id: &str) -> Result<bool, String> {
        let entry = keyring::Entry::new(SESSION_KEYRING_SERVICE, credential_id)
            .map_err(|error| format!("credential entry unavailable: {error}"))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(format!("credential deletion failed: {error}")),
        }
    }
}

/// Session-store operations.
impl SessionStore {
    /// Create a store rooted at the FrameShift central data directory.
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }

    /// Return the exact non-secret metadata path.
    pub fn metadata_path(&self) -> PathBuf {
        self.data_root.join(SESSION_METADATA_REL)
    }

    /// Persist a session with native secret storage and atomic metadata replacement.
    pub fn save(
        &self,
        metadata: SessionStoreMetadata,
        session: &AuthenticatedSession,
    ) -> Result<StoredSessionMetadata, SessionStoreError> {
        self.save_with_store(metadata, session, &SystemSessionCredentialStore)
    }

    /// Load and validate the active session.
    pub fn load(&self) -> Result<StoredSession, SessionStoreError> {
        self.load_with_store(&SystemSessionCredentialStore)
    }

    /// Remove the exact active credential and metadata file.
    pub fn remove(&self) -> Result<bool, SessionStoreError> {
        self.remove_with_store(&SystemSessionCredentialStore)
    }

    /// Save through an injected credential boundary.
    fn save_with_store(
        &self,
        metadata: SessionStoreMetadata,
        session: &AuthenticatedSession,
        credentials: &dyn SessionCredentialStore,
    ) -> Result<StoredSessionMetadata, SessionStoreError> {
        validate_store_metadata(&metadata)?;
        validate_session_authentication(&metadata.authentication, session)?;
        let _lock = self.acquire_lock()?;
        let prior_metadata = self.load_metadata_optional()?;
        let credential_id = credential_id(&metadata);
        let prior_secret = credentials
            .get(&credential_id)
            .map_err(SessionStoreError::Credential)?;
        let payload = serialize_session(session)?;
        credentials
            .put(&credential_id, &payload)
            .map_err(SessionStoreError::Credential)?;

        let stored = StoredSessionMetadata {
            schema_version: SESSION_METADATA_SCHEMA_VERSION,
            authentication: metadata.authentication,
            registry_url: metadata.registry_url,
            credential_id: credential_id.clone(),
            saved_at: unix_now(),
        };
        if let Err(error) = self.write_metadata(&stored) {
            rollback_credential(
                credentials,
                &credential_id,
                prior_secret.as_deref().map(Vec::as_slice),
            );
            return Err(error);
        }
        if let Some(prior) = prior_metadata {
            if prior.credential_id != credential_id {
                credentials
                    .delete(&prior.credential_id)
                    .map_err(SessionStoreError::Credential)?;
            }
        }
        Ok(stored)
    }

    /// Load through an injected credential boundary.
    fn load_with_store(
        &self,
        credentials: &dyn SessionCredentialStore,
    ) -> Result<StoredSession, SessionStoreError> {
        let metadata = self
            .load_metadata_optional()?
            .ok_or(SessionStoreError::NotFound)?;
        let payload = credentials
            .get(&metadata.credential_id)
            .map_err(SessionStoreError::Credential)?
            .ok_or_else(|| {
                SessionStoreError::Invalid(
                    "metadata exists but its native credential is missing".to_string(),
                )
            })?;
        let session = deserialize_session(&payload)?;
        validate_session_authentication(&metadata.authentication, &session)?;
        Ok(StoredSession { metadata, session })
    }

    /// Remove through an injected credential boundary.
    fn remove_with_store(
        &self,
        credentials: &dyn SessionCredentialStore,
    ) -> Result<bool, SessionStoreError> {
        let _lock = self.acquire_lock()?;
        let Some(metadata) = self.load_metadata_optional()? else {
            return Ok(false);
        };
        credentials
            .delete(&metadata.credential_id)
            .map_err(SessionStoreError::Credential)?;
        let path = self.metadata_path();
        fs::remove_file(&path).map_err(|error| SessionStoreError::Io {
            path,
            detail: error.to_string(),
        })?;
        Ok(true)
    }

    /// Load optional metadata with symlink and size rejection.
    fn load_metadata_optional(&self) -> Result<Option<StoredSessionMetadata>, SessionStoreError> {
        let path = self.metadata_path();
        let file = match private_open_options().read(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(SessionStoreError::Io {
                    path,
                    detail: error.to_string(),
                });
            }
        };
        let file_metadata = file.metadata().map_err(|error| SessionStoreError::Io {
            path: path.clone(),
            detail: error.to_string(),
        })?;
        if !file_metadata.file_type().is_file() || file_metadata.len() > MAX_SESSION_STORAGE_BYTES {
            return Err(SessionStoreError::Invalid(
                "metadata must be a bounded regular file".to_string(),
            ));
        }
        validate_private_file_permissions(&file_metadata)?;
        let mut bytes = Vec::new();
        file.take(MAX_SESSION_STORAGE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| SessionStoreError::Io {
                path: path.clone(),
                detail: error.to_string(),
            })?;
        if bytes.len() as u64 > MAX_SESSION_STORAGE_BYTES {
            return Err(SessionStoreError::Invalid(
                "metadata exceeded the size limit".to_string(),
            ));
        }
        let metadata: StoredSessionMetadataWire = serde_json::from_slice(&bytes)
            .map_err(|_| SessionStoreError::Invalid("metadata JSON is malformed".to_string()))?;
        let metadata = match metadata {
            StoredSessionMetadataWire::Current(metadata) => metadata,
            StoredSessionMetadataWire::Legacy(metadata) => migrate_legacy_metadata(metadata)?,
        };
        validate_stored_metadata(&metadata)?;
        Ok(Some(metadata))
    }

    /// Atomically replace non-secret metadata with owner-only permissions.
    fn write_metadata(&self, metadata: &StoredSessionMetadata) -> Result<(), SessionStoreError> {
        let path = self.metadata_path();
        let parent = path
            .parent()
            .ok_or_else(|| SessionStoreError::Invalid("metadata path has no parent".to_string()))?;
        ensure_private_directory(parent)?;
        let bytes = serde_json::to_vec_pretty(metadata)
            .map_err(|_| SessionStoreError::Invalid("metadata serialization failed".to_string()))?;
        let temporary = parent.join(format!(".account-session.{}.tmp", random_suffix()));
        write_private_file(&temporary, &bytes)?;
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(SessionStoreError::Io {
                path,
                detail: error.to_string(),
            });
        }
        Ok(())
    }

    /// Acquire the exact cross-process session lock.
    fn acquire_lock(&self) -> Result<fs::File, SessionStoreError> {
        let path = self.data_root.join(SESSION_LOCK_REL);
        let parent = path.parent().ok_or_else(|| {
            SessionStoreError::Invalid("session lock path has no parent".to_string())
        })?;
        ensure_private_directory(parent)?;
        let file = private_open_options()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|error| SessionStoreError::Io {
                path: path.clone(),
                detail: error.to_string(),
            })?;
        fs2::FileExt::lock_exclusive(&file).map_err(|error| SessionStoreError::Io {
            path,
            detail: error.to_string(),
        })?;
        Ok(file)
    }
}

/// Validate caller-supplied non-secret metadata.
fn validate_store_metadata(metadata: &SessionStoreMetadata) -> Result<(), SessionStoreError> {
    validate_https_url(&metadata.registry_url, "registry URL")?;
    if let SessionAuthentication::Oidc {
        issuer,
        client_id,
        redirect_uri,
        scopes,
    } = &metadata.authentication
    {
        if client_id.trim().is_empty()
            || scopes.is_empty()
            || !scopes.iter().any(|scope| scope == "openid")
            || scopes
                .iter()
                .any(|scope| scope.trim().is_empty() || scope.chars().any(char::is_whitespace))
        {
            return Err(SessionStoreError::Invalid(
                "client ID and valid openid scope are required".to_string(),
            ));
        }
        let mut unique_scopes = std::collections::BTreeSet::new();
        if !scopes.iter().all(|scope| unique_scopes.insert(scope)) {
            return Err(SessionStoreError::Invalid(
                "session scopes must not contain duplicates".to_string(),
            ));
        }
        validate_https_url(issuer, "issuer")?;
        validate_redirect_uri(redirect_uri)?;
    }
    Ok(())
}

/// Require secret-session fields that match the persisted provider kind.
fn validate_session_authentication(
    authentication: &SessionAuthentication,
    session: &AuthenticatedSession,
) -> Result<(), SessionStoreError> {
    let summary = session.summary();
    if matches!(authentication, SessionAuthentication::FirstParty)
        && (summary.scope.is_some() || summary.expires_in.is_none())
    {
        return Err(SessionStoreError::Invalid(
            "first-party sessions must have an expiry and no OIDC scope metadata".to_string(),
        ));
    }
    Ok(())
}

/// Require one credential-free HTTPS URL without query or fragment state.
fn validate_https_url(url: &Url, label: &str) -> Result<(), SessionStoreError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SessionStoreError::Invalid(format!(
            "{label} must be a credential-free HTTPS URL"
        )));
    }
    Ok(())
}

/// Require a credential-free HTTPS or exact loopback HTTP callback URL.
fn validate_redirect_uri(redirect_uri: &Url) -> Result<(), SessionStoreError> {
    let loopback_http = redirect_uri.scheme() == "http"
        && redirect_uri
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if !(redirect_uri.scheme() == "https" || loopback_http)
        || redirect_uri.host_str().is_none()
        || !redirect_uri.username().is_empty()
        || redirect_uri.password().is_some()
        || redirect_uri.query().is_some()
        || redirect_uri.fragment().is_some()
    {
        return Err(SessionStoreError::Invalid(
            "redirect URI must be credential-free HTTPS or loopback HTTP without query or fragment"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate persisted metadata and its credential binding.
fn validate_stored_metadata(metadata: &StoredSessionMetadata) -> Result<(), SessionStoreError> {
    if metadata.schema_version != SESSION_METADATA_SCHEMA_VERSION {
        return Err(SessionStoreError::Invalid(format!(
            "unsupported metadata schema version {}",
            metadata.schema_version
        )));
    }
    validate_store_metadata(&SessionStoreMetadata {
        authentication: metadata.authentication.clone(),
        registry_url: metadata.registry_url.clone(),
    })?;
    let expected = credential_id(&SessionStoreMetadata {
        authentication: metadata.authentication.clone(),
        registry_url: metadata.registry_url.clone(),
    });
    if metadata.credential_id != expected {
        return Err(SessionStoreError::Invalid(
            "credential binding does not match metadata".to_string(),
        ));
    }
    Ok(())
}

/// Convert schema-v1 OIDC metadata into the provider-tagged in-memory shape.
fn migrate_legacy_metadata(
    metadata: LegacyStoredSessionMetadata,
) -> Result<StoredSessionMetadata, SessionStoreError> {
    if metadata.schema_version != LEGACY_SESSION_METADATA_SCHEMA_VERSION {
        return Err(SessionStoreError::Invalid(format!(
            "unsupported legacy metadata schema version {}",
            metadata.schema_version
        )));
    }
    Ok(StoredSessionMetadata {
        schema_version: SESSION_METADATA_SCHEMA_VERSION,
        authentication: SessionAuthentication::Oidc {
            issuer: metadata.issuer,
            client_id: metadata.client_id,
            redirect_uri: Box::new(metadata.redirect_uri),
            scopes: metadata.scopes,
        },
        registry_url: metadata.registry_url,
        credential_id: metadata.credential_id,
        saved_at: metadata.saved_at,
    })
}

/// Derive a stable credential account without embedding user identifiers.
fn credential_id(metadata: &SessionStoreMetadata) -> String {
    let mut hasher = Sha256::new();
    let values = match &metadata.authentication {
        SessionAuthentication::Oidc {
            issuer,
            client_id,
            redirect_uri,
            ..
        } => vec![
            issuer.as_str(),
            client_id.as_str(),
            redirect_uri.as_str(),
            metadata.registry_url.as_str(),
        ],
        SessionAuthentication::FirstParty => {
            vec!["first_party", metadata.registry_url.as_str()]
        }
    };
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!("session-{}", hex::encode(hasher.finalize()))
}

/// Serialize only secret-bearing session fields for native storage.
fn serialize_session(
    session: &AuthenticatedSession,
) -> Result<Zeroizing<Vec<u8>>, SessionStoreError> {
    let payload = SessionSecretPayload {
        schema_version: SESSION_SECRET_SCHEMA_VERSION,
        access_token: session.access_token.expose_secret().to_owned(),
        refresh_token: session
            .refresh_token
            .as_ref()
            .map(|token| token.expose_secret().to_owned()),
        expires_in: session.expires_in,
        scope: session.scope.clone(),
        acquired_at: session.acquired_at,
    };
    serde_json::to_vec(&payload)
        .map(Zeroizing::new)
        .map_err(|_| SessionStoreError::Invalid("secret serialization failed".to_string()))
}

/// Decode and validate a native credential payload.
fn deserialize_session(payload: &[u8]) -> Result<AuthenticatedSession, SessionStoreError> {
    if payload.len() as u64 > MAX_SESSION_STORAGE_BYTES {
        return Err(SessionStoreError::Invalid(
            "credential payload exceeded the size limit".to_string(),
        ));
    }
    let payload: SessionSecretPayload = serde_json::from_slice(payload)
        .map_err(|_| SessionStoreError::Invalid("credential payload is malformed".to_string()))?;
    let invalid_access_token = invalid_token_value(&payload.access_token);
    let invalid_refresh_token = payload
        .refresh_token
        .as_deref()
        .is_some_and(invalid_token_value);
    if payload.schema_version != SESSION_SECRET_SCHEMA_VERSION
        || invalid_access_token
        || invalid_refresh_token
    {
        return Err(SessionStoreError::Invalid(
            "credential payload failed validation".to_string(),
        ));
    }
    Ok(AuthenticatedSession::from_stored_parts(
        SecretString::new(payload.access_token.clone()),
        payload.refresh_token.clone().map(SecretString::new),
        payload.expires_in,
        payload.scope.clone(),
        payload.acquired_at,
    ))
}

/// Reject token values that cannot be placed safely in an authorization header.
fn invalid_token_value(token: &str) -> bool {
    token.is_empty()
        || token
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

/// Restore or delete a credential after metadata persistence fails.
fn rollback_credential(
    credentials: &dyn SessionCredentialStore,
    credential_id: &str,
    prior: Option<&[u8]>,
) {
    match prior {
        Some(payload) => {
            let _ = credentials.put(credential_id, payload);
        }
        None => {
            let _ = credentials.delete(credential_id);
        }
    }
}

/// Ensure a session directory exists and is not a symlink.
fn ensure_private_directory(path: &Path) -> Result<(), SessionStoreError> {
    fs::create_dir_all(path).map_err(|error| SessionStoreError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| SessionStoreError::Io {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    if !metadata.file_type().is_dir() {
        return Err(SessionStoreError::Invalid(
            "session directory is not a real directory".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            SessionStoreError::Io {
                path: path.to_path_buf(),
                detail: error.to_string(),
            }
        })?;
    }
    Ok(())
}

/// Write one new owner-only temporary metadata file.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SessionStoreError> {
    let mut file = private_open_options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| SessionStoreError::Io {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| SessionStoreError::Io {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })
}

/// Build platform-appropriate private file options.
fn private_open_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
}

/// Reject metadata files readable or writable by group or other users.
fn validate_private_file_permissions(metadata: &fs::Metadata) -> Result<(), SessionStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SessionStoreError::Invalid(
                "session metadata permissions must exclude group and other users".to_string(),
            ));
        }
    }
    Ok(())
}

/// Return a collision-resistant temporary-file suffix.
fn random_suffix() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0_u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Return the current Unix timestamp.
fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
/// Deterministic session-store tests.
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// In-memory credential store.
    #[derive(Default)]
    struct FakeCredentials {
        /// Secret bytes keyed by credential ID.
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    /// Fake credential operations.
    impl SessionCredentialStore for FakeCredentials {
        /// Read one fake credential.
        fn get(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            Ok(self
                .values
                .lock()
                .expect("credential lock poisoned")
                .get(credential_id)
                .cloned()
                .map(Zeroizing::new))
        }

        /// Write one fake credential.
        fn put(&self, credential_id: &str, payload: &[u8]) -> Result<(), String> {
            self.values
                .lock()
                .expect("credential lock poisoned")
                .insert(credential_id.to_string(), payload.to_vec());
            Ok(())
        }

        /// Delete one fake credential.
        fn delete(&self, credential_id: &str) -> Result<bool, String> {
            Ok(self
                .values
                .lock()
                .expect("credential lock poisoned")
                .remove(credential_id)
                .is_some())
        }
    }

    /// Build non-secret metadata.
    fn metadata() -> SessionStoreMetadata {
        SessionStoreMetadata {
            authentication: SessionAuthentication::Oidc {
                issuer: Url::parse("https://issuer.example").expect("issuer URL"),
                client_id: "frameshift-cli".to_string(),
                redirect_uri: Box::new(
                    Url::parse("http://127.0.0.1:8765/callback").expect("redirect URL"),
                ),
                scopes: vec!["openid".to_string(), "profile".to_string()],
            },
            registry_url: Url::parse("https://registry.example").expect("registry URL"),
        }
    }

    /// Build one secret-bearing session.
    fn session() -> AuthenticatedSession {
        AuthenticatedSession::from_stored_parts(
            SecretString::new("secret-access".to_string()),
            Some(SecretString::new("secret-refresh".to_string())),
            Some(300),
            Some("openid profile".to_string()),
            42,
        )
    }

    /// Tokens remain absent from metadata and round-trip through native storage.
    #[test]
    fn saves_loads_and_removes_without_plaintext_metadata_tokens() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        store
            .save_with_store(metadata(), &session(), &credentials)
            .expect("save session");
        let metadata_bytes = fs::read(store.metadata_path()).expect("read metadata");
        let metadata_text = String::from_utf8(metadata_bytes).expect("metadata UTF-8");
        assert!(!metadata_text.contains("secret-access"));
        assert!(!metadata_text.contains("secret-refresh"));

        let loaded = store.load_with_store(&credentials).expect("load session");
        assert_eq!(
            loaded.session.access_token().expose_secret(),
            "secret-access"
        );
        assert!(!format!("{loaded:?}").contains("secret-access"));
        assert!(store
            .remove_with_store(&credentials)
            .expect("remove session"));
        assert!(!store.metadata_path().exists());
        assert!(!store
            .remove_with_store(&credentials)
            .expect("repeat removal"));
    }

    /// A tampered credential binding or symlinked metadata fails closed.
    #[test]
    fn rejects_tampered_or_symlinked_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        let mut stored = store
            .save_with_store(metadata(), &session(), &credentials)
            .expect("save session");
        stored.credential_id = "substituted".to_string();
        fs::write(
            store.metadata_path(),
            serde_json::to_vec(&stored).expect("serialize metadata"),
        )
        .expect("write tampered metadata");
        assert!(store.load_with_store(&credentials).is_err());

        #[cfg(unix)]
        {
            fs::remove_file(store.metadata_path()).expect("remove metadata");
            std::os::unix::fs::symlink("/dev/null", store.metadata_path())
                .expect("create metadata symlink");
            assert!(store.load_with_store(&credentials).is_err());
        }
    }

    /// Persisted metadata rejects unsafe URLs, malformed scopes, and duplicates.
    #[test]
    fn rejects_invalid_non_secret_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        let mut cases = Vec::new();

        let mut issuer_query = metadata();
        if let SessionAuthentication::Oidc { issuer, .. } = &mut issuer_query.authentication {
            *issuer = Url::parse("https://issuer.example?tenant=other").expect("issuer URL");
        }
        cases.push(issuer_query);

        let mut remote_http_redirect = metadata();
        if let SessionAuthentication::Oidc { redirect_uri, .. } =
            &mut remote_http_redirect.authentication
        {
            **redirect_uri = Url::parse("http://192.0.2.1:8765/callback").expect("redirect URL");
        }
        cases.push(remote_http_redirect);

        let mut duplicate_scopes = metadata();
        if let SessionAuthentication::Oidc { scopes, .. } = &mut duplicate_scopes.authentication {
            *scopes = vec!["openid".to_string(), "openid".to_string()];
        }
        cases.push(duplicate_scopes);

        let mut embedded_whitespace = metadata();
        if let SessionAuthentication::Oidc { scopes, .. } = &mut embedded_whitespace.authentication
        {
            *scopes = vec!["openid".to_string(), "bad scope".to_string()];
        }
        cases.push(embedded_whitespace);

        for invalid in cases {
            assert!(store
                .save_with_store(invalid, &session(), &credentials)
                .is_err());
        }
        assert!(!store.metadata_path().exists());
    }

    /// First-party sessions keep rotating refresh credentials only in secret storage.
    #[test]
    fn saves_and_loads_first_party_session() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        let metadata = SessionStoreMetadata {
            authentication: SessionAuthentication::FirstParty,
            registry_url: Url::parse("https://registry.example").expect("registry URL"),
        };
        let session = AuthenticatedSession::from_stored_parts(
            SecretString::new("local-access".to_string()),
            Some(SecretString::new("local-refresh".to_string())),
            Some(600),
            None,
            42,
        );

        store
            .save_with_store(metadata, &session, &credentials)
            .expect("save first-party session");
        let metadata_text =
            fs::read_to_string(store.metadata_path()).expect("read first-party metadata");
        assert!(metadata_text.contains("\"kind\": \"first_party\""));
        assert!(!metadata_text.contains("local-access"));
        assert!(!metadata_text.contains("local-refresh"));
        let loaded = store.load_with_store(&credentials).expect("load session");
        assert_eq!(
            loaded.metadata.authentication,
            SessionAuthentication::FirstParty
        );
        assert_eq!(
            loaded
                .session
                .refresh_token()
                .map(|token| token.expose_secret().as_str()),
            Some("local-refresh")
        );
        assert_eq!(
            loaded.session.access_token().expose_secret(),
            "local-access"
        );
    }

    /// Provider metadata cannot relabel an OIDC-scoped session as first-party.
    #[test]
    fn rejects_first_party_metadata_for_oidc_session_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        let metadata = SessionStoreMetadata {
            authentication: SessionAuthentication::FirstParty,
            registry_url: Url::parse("https://registry.example").expect("registry URL"),
        };

        assert!(store
            .save_with_store(metadata, &session(), &credentials)
            .is_err());
        assert!(!store.metadata_path().exists());
    }

    /// Schema-v1 OIDC metadata keeps its exact existing keyring credential binding.
    #[test]
    fn migrates_legacy_oidc_metadata_without_changing_credential_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SessionStore::new(temp.path());
        let credentials = FakeCredentials::default();
        let current = metadata();
        let expected_credential_id = credential_id(&current);
        let SessionAuthentication::Oidc {
            issuer,
            client_id,
            redirect_uri,
            scopes,
        } = &current.authentication
        else {
            panic!("test metadata must be OIDC");
        };
        let legacy = serde_json::json!({
            "schema_version": LEGACY_SESSION_METADATA_SCHEMA_VERSION,
            "issuer": issuer,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scopes": scopes,
            "registry_url": current.registry_url,
            "credential_id": expected_credential_id.clone(),
            "saved_at": 41
        });
        let path = store.metadata_path();
        ensure_private_directory(path.parent().expect("metadata parent"))
            .expect("create metadata parent");
        write_private_file(
            &path,
            &serde_json::to_vec(&legacy).expect("serialize legacy metadata"),
        )
        .expect("write legacy metadata");
        credentials
            .put(
                &expected_credential_id,
                &serialize_session(&session()).expect("secret payload"),
            )
            .expect("write legacy credential");

        let loaded = store
            .load_with_store(&credentials)
            .expect("load legacy session");
        assert_eq!(
            loaded.metadata.schema_version,
            SESSION_METADATA_SCHEMA_VERSION
        );
        assert_eq!(loaded.metadata.credential_id, expected_credential_id);
        assert!(matches!(
            loaded.metadata.authentication,
            SessionAuthentication::Oidc { .. }
        ));
    }
}

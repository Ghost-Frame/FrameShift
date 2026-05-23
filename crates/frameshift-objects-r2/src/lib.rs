//! Cloudflare R2 (S3-compatible) [`PackStore`] adapter.
//!
//! Implements the `frameshift-objects` `PackStore` trait against any
//! S3-compatible blob store. Targets Cloudflare R2 in production
//! (free egress to Cloudflare edge, no per-prefix throughput limits),
//! but works against AWS S3, MinIO, or any other vendor that speaks
//! the S3 wire protocol.
//!
//! # Key layout
//!
//! Objects are stored under a configurable key prefix with the hash
//! hex-encoded as the leaf:
//!
//! ```text
//! <prefix>/<64-char hex hash>
//! ```
//!
//! No sharding (R2 has no per-prefix hot-key throughput limits, unlike
//! older AWS S3). The trait's `list_prefix(bytes_prefix)` translates to
//! an S3 `ListObjectsV2` call with prefix `<prefix>/<hex(bytes_prefix)>`.
//!
//! # Atomicity
//!
//! S3 PUT is atomic at the object level: a partial PUT either fails or
//! produces a complete object. The adapter computes SHA-256 of the
//! caller-supplied bytes before issuing the PUT and rejects with
//! [`ObjectStoreError::HashMismatch`] if the computed digest does not
//! match the asserted `hash`, matching the trait contract.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use frameshift_objects::{ObjectHash, ObjectStoreError, ObjectStoreHealth, PackStore};
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as ObjectStorePath;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use sha2::{Digest, Sha256};

/// Build-time configuration for [`R2PackStore`].
///
/// Constructed by the caller from environment variables (or a config file)
/// and passed to [`R2PackStore::new`]. All fields are required except
/// `region` (R2 always uses `"auto"`).
#[derive(Debug, Clone)]
pub struct R2PackStoreConfig {
    /// S3 endpoint URL.
    ///
    /// For Cloudflare R2: `https://<account-id>.r2.cloudflarestorage.com`.
    /// For MinIO/local: `http://localhost:9000`.
    pub endpoint: String,

    /// Bucket name. Must exist before the store is used.
    pub bucket: String,

    /// Optional key prefix prepended to every object key.
    ///
    /// Empty means objects live at the bucket root. A typical value is
    /// `"objects"` so the bucket can also hold non-pack data without
    /// collision.
    pub prefix: String,

    /// S3 region. For R2 this is always `"auto"`.
    pub region: String,

    /// Access key ID (S3 access key).
    pub access_key_id: String,

    /// Secret access key (S3 secret).
    ///
    /// The caller is responsible for sourcing this from a secrets manager
    /// and never letting it appear in `Debug` output.
    pub secret_access_key: secrecy::SecretString,
}

/// R2/S3-compatible [`PackStore`] implementation.
///
/// Clone-safe and `Send + Sync`; multiple tasks can share an `Arc<R2PackStore>`.
#[derive(Clone)]
pub struct R2PackStore {
    /// The underlying `object_store::AmazonS3` client (already configured
    /// for the bucket and endpoint).
    inner: Arc<AmazonS3>,
    /// Prefix prepended to every object key (empty for bucket-root layout).
    prefix: String,
}

impl R2PackStore {
    /// Construct a new R2-backed PackStore.
    ///
    /// Validates the configuration and builds the underlying S3 client.
    /// Performs no network I/O at construction time; the first `put` /
    /// `get` will be the first time the bucket is contacted.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectStoreError::BackendError`] if the configuration is
    /// invalid (e.g. unparseable endpoint URL) or the underlying
    /// `AmazonS3Builder` fails to build a client.
    pub fn new(config: R2PackStoreConfig) -> Result<Self, ObjectStoreError> {
        use secrecy::ExposeSecret;
        let inner = AmazonS3Builder::new()
            .with_endpoint(&config.endpoint)
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_access_key_id(&config.access_key_id)
            .with_secret_access_key(config.secret_access_key.expose_secret())
            .with_virtual_hosted_style_request(false)
            .with_allow_http(config.endpoint.starts_with("http://"))
            .build()
            .map_err(|e| ObjectStoreError::BackendError(Box::new(e)))?;
        Ok(Self {
            inner: Arc::new(inner),
            prefix: config.prefix,
        })
    }

    /// Compose the full object key for `hash`.
    ///
    /// `<prefix>/<hex>` when `prefix` is non-empty, otherwise just `<hex>`.
    fn key_for(&self, hash: &ObjectHash) -> ObjectStorePath {
        let hex = hash.to_hex();
        let key = if self.prefix.is_empty() {
            hex
        } else {
            format!("{}/{hex}", self.prefix.trim_end_matches('/'))
        };
        ObjectStorePath::from(key)
    }

    /// Compose the list-prefix for the trait's raw-bytes prefix.
    ///
    /// Hex-encodes the input (which the trait declares as raw bytes that
    /// match the leading bytes of a hash) and joins with the configured
    /// prefix. An empty bytes-prefix yields just the configured prefix.
    fn list_prefix_for(&self, bytes_prefix: &[u8]) -> ObjectStorePath {
        let hex = hex::encode(bytes_prefix);
        let key = match (self.prefix.is_empty(), hex.is_empty()) {
            (true, true) => String::new(),
            (false, true) => self.prefix.trim_end_matches('/').to_string(),
            (true, false) => hex,
            (false, false) => format!("{}/{hex}", self.prefix.trim_end_matches('/')),
        };
        ObjectStorePath::from(key)
    }
}

#[async_trait]
impl PackStore for R2PackStore {
    /// Verify SHA-256(bytes) matches `hash`, then upload to S3 under the
    /// content-addressed key. Idempotent: re-uploading the same bytes to
    /// the same key is a no-op success per the trait contract (S3 PUT
    /// overwrites with identical content).
    async fn put(&self, hash: &ObjectHash, bytes: &[u8]) -> Result<(), ObjectStoreError> {
        let computed: [u8; 32] = Sha256::digest(bytes).into();
        let actual = ObjectHash::from_bytes(computed);
        if actual != *hash {
            return Err(ObjectStoreError::HashMismatch {
                expected: *hash,
                actual,
            });
        }
        let key = self.key_for(hash);
        let payload = PutPayload::from(Bytes::copy_from_slice(bytes));
        self.inner
            .put(&key, payload)
            .await
            .map_err(|e| ObjectStoreError::BackendError(Box::new(e)))
            .map(|_| ())
    }

    /// Download the object bytes via a single S3 GET.
    ///
    /// The trait returns `Vec<u8>`, so we buffer fully. A streaming variant
    /// would be a future optimization for very large pack archives.
    async fn get(&self, hash: &ObjectHash) -> Result<Vec<u8>, ObjectStoreError> {
        let key = self.key_for(hash);
        let result = self.inner.get(&key).await.map_err(|e| {
            if matches!(e, object_store::Error::NotFound { .. }) {
                ObjectStoreError::NotFound { hash: *hash }
            } else {
                ObjectStoreError::BackendError(Box::new(e))
            }
        })?;
        let bytes = result
            .bytes()
            .await
            .map_err(|e| ObjectStoreError::BackendError(Box::new(e)))?;
        Ok(bytes.to_vec())
    }

    /// HEAD the object; `Ok(true)` if it exists, `Ok(false)` if 404,
    /// `Err` for any other failure.
    async fn exists(&self, hash: &ObjectHash) -> Result<bool, ObjectStoreError> {
        let key = self.key_for(hash);
        match self.inner.head(&key).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(ObjectStoreError::BackendError(Box::new(e))),
        }
    }

    /// DELETE the object. Returns `NotFound` if it did not exist (probes
    /// with HEAD first because S3 DELETE returns 204 for both cases).
    async fn delete(&self, hash: &ObjectHash) -> Result<(), ObjectStoreError> {
        let key = self.key_for(hash);
        if !self.exists(hash).await? {
            return Err(ObjectStoreError::NotFound { hash: *hash });
        }
        self.inner
            .delete(&key)
            .await
            .map_err(|e| ObjectStoreError::BackendError(Box::new(e)))
    }

    /// List object hashes matching `prefix`. Stops at `limit`.
    ///
    /// A prefix longer than 32 bytes (the hash length) is rejected without
    /// a network call (no hash can ever match), per the trait contract.
    async fn list_prefix(
        &self,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<ObjectHash>, ObjectStoreError> {
        if prefix.len() > 32 {
            return Ok(Vec::new());
        }
        use futures::TryStreamExt;
        let list_prefix = self.list_prefix_for(prefix);
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut stream = self.inner.list(Some(&list_prefix));
        while let Some(meta) = stream
            .try_next()
            .await
            .map_err(|e| ObjectStoreError::BackendError(Box::new(e)))?
        {
            if out.len() >= limit {
                break;
            }
            // Leaf path component is the 64-char hex hash. Skip anything
            // that doesn't parse so corrupt keys don't crash the listing.
            let leaf = meta
                .location
                .parts()
                .next_back()
                .map(|p| p.as_ref().to_string())
                .unwrap_or_default();
            match ObjectHash::from_hex(&leaf) {
                Ok(hash) => out.push(hash),
                Err(_) => {
                    tracing::warn!(key = %meta.location, "skipping non-hash key in R2 listing");
                }
            }
        }
        Ok(out)
    }

    /// Probe the bucket with a bounded `list` to confirm credentials and
    /// endpoint are valid. Bucket capacity counters would require a full
    /// scan, so they are returned as `None`.
    async fn health(&self) -> Result<ObjectStoreHealth, ObjectStoreError> {
        use futures::TryStreamExt;
        let prefix = if self.prefix.is_empty() {
            None
        } else {
            Some(ObjectStorePath::from(self.prefix.clone()))
        };
        let mut stream = self.inner.list(prefix.as_ref());
        let probe = tokio::time::timeout(Duration::from_secs(5), stream.try_next()).await;
        match probe {
            Ok(Ok(_)) => Ok(ObjectStoreHealth {
                healthy: true,
                detail: format!("R2 reachable; prefix={}", self.prefix),
                total_objects: None,
                total_bytes: None,
            }),
            Ok(Err(e)) => Ok(ObjectStoreHealth {
                healthy: false,
                detail: format!("R2 list failed: {e}"),
                total_objects: None,
                total_bytes: None,
            }),
            Err(_) => Ok(ObjectStoreHealth {
                healthy: false,
                detail: "R2 list timed out after 5s".to_string(),
                total_objects: None,
                total_bytes: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_prefix(prefix: &str) -> R2PackStoreConfig {
        R2PackStoreConfig {
            endpoint: "https://example.r2.cloudflarestorage.com".into(),
            bucket: "b".into(),
            prefix: prefix.into(),
            region: "auto".into(),
            access_key_id: "x".into(),
            secret_access_key: secrecy::SecretString::new("y".into()),
        }
    }

    /// `key_for` joins the configured prefix with the hex hash.
    #[test]
    fn key_for_with_prefix_yields_prefix_slash_hex() {
        let store = R2PackStore::new(cfg_with_prefix("objects")).expect("config builds");
        let hash = ObjectHash::of(b"x");
        let key = store.key_for(&hash);
        assert!(key.as_ref().starts_with("objects/"));
        assert_eq!(
            key.as_ref().strip_prefix("objects/").unwrap().len(),
            64,
            "leaf must be 64-char hex"
        );
    }

    /// `key_for` without a prefix returns just the hex hash.
    #[test]
    fn key_for_without_prefix_yields_bare_hex() {
        let store = R2PackStore::new(cfg_with_prefix("")).expect("config builds");
        let hash = ObjectHash::of(b"x");
        let key = store.key_for(&hash);
        assert_eq!(key.as_ref().len(), 64);
    }

    /// `list_prefix_for` hex-encodes the byte prefix and joins with `prefix`.
    #[test]
    fn list_prefix_encodes_bytes_to_hex() {
        let store = R2PackStore::new(cfg_with_prefix("objects")).expect("config builds");
        let lp = store.list_prefix_for(&[0x01, 0xab]);
        assert_eq!(lp.as_ref(), "objects/01ab");
    }

    /// Empty byte-prefix with a configured prefix returns just the prefix.
    #[test]
    fn list_prefix_empty_bytes_returns_prefix() {
        let store = R2PackStore::new(cfg_with_prefix("objects")).expect("config builds");
        let lp = store.list_prefix_for(&[]);
        assert_eq!(lp.as_ref(), "objects");
    }

    /// `put` rejects bytes whose SHA-256 does not match the asserted hash.
    /// We can verify this without network I/O because the hash check
    /// happens before the S3 call.
    #[tokio::test]
    async fn put_rejects_hash_mismatch() {
        let store = R2PackStore::new(cfg_with_prefix("objects")).expect("config builds");
        let bytes = b"actual";
        let lying_hash = ObjectHash::of(b"different");
        let err = store.put(&lying_hash, bytes).await.unwrap_err();
        match err {
            ObjectStoreError::HashMismatch { expected, actual } => {
                assert_eq!(expected, lying_hash);
                assert_ne!(actual, lying_hash);
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }
}

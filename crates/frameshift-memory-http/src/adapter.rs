//! [`HttpAdapter`] -- HTTP-backed [`MemoryAdapter`] implementation.
//!
//! Builds a [`reqwest::Client`] once at construction time and reuses it for all
//! requests. Authentication headers (or mTLS) are baked into the client or
//! applied per-request. The retry policy lives in [`crate::retry`].

use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use frameshift_memory::{
    Filters, HealthStatus, Memory, MemoryAdapter, MemoryError, MemoryId, Metadata,
};
use reqwest::{Client, RequestBuilder, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::dto::{
    FiltersDto, HealthResponse, ListResponse, MemoryDto, SearchRequest, SearchResponse,
    StoreRequest, StoreResponse,
};
use crate::retry::{backoff_delay, is_retryable_status, parse_retry_after, MAX_ATTEMPTS};

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// Authentication scheme for the HTTP memory endpoint.
///
/// The variant is selected once at [`HttpAdapter::new()`] time; credentials are
/// never logged or printed because [`SecretString`] redacts its `Debug` output.
#[derive(Clone)]
pub enum HttpAuth {
    /// HTTP Bearer token (`Authorization: Bearer <token>`).
    Bearer(SecretString),

    /// Arbitrary header-based API key.
    ApiKey {
        /// The name of the header to set (e.g. `"X-Api-Key"`).
        header_name: String,
        /// The secret value sent in the header.
        value: SecretString,
    },

    /// OAuth 2.0 Bearer token (`Authorization: Bearer <token>`).
    ///
    /// Semantically distinct from plain `Bearer` so callers can distinguish
    /// the auth scheme in logs without exposing the token.
    OAuthBearer(SecretString),

    /// Mutual TLS: client certificate + private key loaded from disk.
    Mtls {
        /// Path to the PEM-encoded client certificate.
        client_cert: PathBuf,
        /// Path to the PEM-encoded client private key.
        client_key: PathBuf,
    },

    /// No authentication. Suitable for localhost-only endpoints that do not
    /// require credentials (e.g. a local memory gateway with that risk accepted).
    None,
}

impl std::fmt::Debug for HttpAuth {
    /// Redacts all credential values so they never appear in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.debug_tuple("Bearer").field(&"[REDACTED]").finish(),
            Self::ApiKey { header_name, .. } => f
                .debug_struct("ApiKey")
                .field("header_name", header_name)
                .field("value", &"[REDACTED]")
                .finish(),
            Self::OAuthBearer(_) => f.debug_tuple("OAuthBearer").field(&"[REDACTED]").finish(),
            Self::Mtls {
                client_cert,
                client_key,
            } => f
                .debug_struct("Mtls")
                .field("client_cert", client_cert)
                .field("client_key", client_key)
                .finish(),
            Self::None => write!(f, "None"),
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for constructing an [`HttpAdapter`].
///
/// Pass to [`HttpAdapter::new()`] to build the adapter. All fields are
/// validated at construction time so that runtime requests cannot fail due to
/// misconfiguration.
#[derive(Debug, Clone)]
pub struct HttpAdapterConfig {
    /// Base URL of the memory HTTP service (e.g. `http://localhost:8080/v1`).
    pub endpoint: Url,

    /// Authentication scheme to use for all requests.
    pub auth: HttpAuth,

    /// Request timeout. Applied per attempt, not across all retries.
    pub timeout: Duration,

    /// Value to send in the `User-Agent` header.
    pub user_agent: String,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// HTTP-backed implementation of [`MemoryAdapter`].
///
/// Constructed via [`HttpAdapter::new()`]. Holds a single [`reqwest::Client`]
/// that is reused across all requests (connection pooling, keep-alive).
///
/// `Debug` output intentionally omits all credential values.
pub struct HttpAdapter {
    /// The underlying HTTP client, pre-configured with TLS and timeout.
    client: Client,

    /// Base URL; all endpoint paths are appended to this.
    base: Url,

    /// Authentication configuration. Stored so header-based variants can be
    /// applied per-request.
    auth: HttpAuth,
}

impl std::fmt::Debug for HttpAdapter {
    /// Prints the base URL and auth variant name; credential values are redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAdapter")
            .field("base", &self.base.as_str())
            .field("auth", &self.auth)
            .finish()
    }
}

impl HttpAdapter {
    /// Construct an [`HttpAdapter`] from the given configuration.
    ///
    /// Validates that mTLS cert and key paths exist when `Mtls` auth is used.
    /// Builds the [`reqwest::Client`] once; returns an error if client
    /// construction or path validation fails.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::ConnectionFailed`] if the reqwest client cannot
    /// be built. Returns [`MemoryError::Unauthorized`] if mTLS paths are
    /// missing or the certificate cannot be read.
    pub fn new(config: HttpAdapterConfig) -> Result<Self, MemoryError> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent)
            .use_rustls_tls()
            .gzip(true);

        if let HttpAuth::Mtls {
            ref client_cert,
            ref client_key,
        } = config.auth
        {
            // Validate paths exist before attempting to read them.
            if !client_cert.exists() {
                return Err(MemoryError::Unauthorized(format!(
                    "mTLS client cert not found: {}",
                    client_cert.display()
                )));
            }
            if !client_key.exists() {
                return Err(MemoryError::Unauthorized(format!(
                    "mTLS client key not found: {}",
                    client_key.display()
                )));
            }

            let cert_pem = std::fs::read(client_cert).map_err(|e| {
                MemoryError::Unauthorized(format!(
                    "failed to read mTLS client cert {}: {e}",
                    client_cert.display()
                ))
            })?;
            let key_pem = std::fs::read(client_key).map_err(|e| {
                MemoryError::Unauthorized(format!(
                    "failed to read mTLS client key {}: {e}",
                    client_key.display()
                ))
            })?;

            // Combine cert + key into a single PEM bundle for reqwest.
            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(b"\n");
            identity_pem.extend_from_slice(&key_pem);

            let identity = reqwest::Identity::from_pem(&identity_pem)
                .map_err(|e| MemoryError::Unauthorized(format!("invalid mTLS identity: {e}")))?;

            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|e| MemoryError::ConnectionFailed(e.to_string()))?;

        // Normalize the base URL so [`Url::join`] treats it as a directory.
        // Without a trailing slash, `Url::join("store")` against
        // `http://host/v1` produces `http://host/store` (the last path segment
        // is replaced).  Always treating the endpoint as a directory removes
        // this footgun.
        let mut base = config.endpoint;
        if !base.path().ends_with('/') {
            let mut path = base.path().to_owned();
            path.push('/');
            base.set_path(&path);
        }

        Ok(Self {
            client,
            base,
            auth: config.auth,
        })
    }

    /// Apply authentication headers to a request builder.
    ///
    /// For `Mtls`, authentication is handled at the TLS layer by the client
    /// itself, so no headers are added.
    fn apply_auth(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            HttpAuth::Bearer(token) | HttpAuth::OAuthBearer(token) => {
                rb.bearer_auth(token.expose_secret())
            }
            HttpAuth::ApiKey { header_name, value } => {
                rb.header(header_name.as_str(), value.expose_secret())
            }
            HttpAuth::Mtls { .. } | HttpAuth::None => rb,
        }
    }

    /// Build an absolute URL by appending `path` to the base URL.
    ///
    /// Uses [`Url::join`] semantics: if `base` does not end with `/`, the last
    /// path segment is replaced. To avoid surprises, always ensure `base` ends
    /// with `/` or construct paths carefully.
    fn url(&self, path: &str) -> Result<Url, MemoryError> {
        self.base
            .join(path)
            .map_err(|e| MemoryError::Backend(format!("URL construction error: {e}")))
    }

    /// Execute a request with the retry policy.
    ///
    /// Retries on 5xx and 429 responses (up to [`MAX_ATTEMPTS`] total).
    /// Honors `Retry-After` on 429. Returns the raw [`reqwest::Response`] on
    /// success, or a [`MemoryError`] after exhausting retries or encountering a
    /// non-retryable error.
    async fn execute_with_retry(
        &self,
        build: impl Fn() -> RequestBuilder,
    ) -> Result<reqwest::Response, MemoryError> {
        let mut last_err: Option<MemoryError> = None;

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let delay = last_err.as_ref().and_then(|e| {
                    if let MemoryError::RateLimited { retry_after_secs } = e {
                        *retry_after_secs
                    } else {
                        None
                    }
                });
                tokio::time::sleep(backoff_delay(attempt - 1, delay)).await;
            }

            let rb = self.apply_auth(build());
            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    // Network-level error -- not retryable by our policy here,
                    // but we still record and return it.
                    return Err(MemoryError::ConnectionFailed(e.to_string()));
                }
            };

            let status = resp.status().as_u16();

            if !is_retryable_status(status) {
                return Ok(resp);
            }

            // Parse Retry-After for 429.
            let retry_after = if status == 429 {
                let header_val = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok());
                parse_retry_after(header_val)
            } else {
                None
            };

            last_err = Some(if status == 429 {
                MemoryError::RateLimited {
                    retry_after_secs: retry_after,
                }
            } else {
                MemoryError::ConnectionFailed(format!("server returned {status}"))
            });
        }

        Err(last_err.unwrap_or_else(|| {
            MemoryError::ConnectionFailed("retry exhausted with no recorded error".into())
        }))
    }

    /// Map a non-retryable HTTP status to a [`MemoryError`].
    ///
    /// Called after [`execute_with_retry`] returns a response so callers can
    /// translate 401, 404, and other codes into the appropriate variant.
    fn map_status_error(status: StatusCode, context: &str) -> MemoryError {
        match status.as_u16() {
            401 | 403 => MemoryError::Unauthorized(format!("{context}: {status}")),
            404 => {
                // NotFound requires a MemoryId; callers that know the ID
                // (recall, forget) handle 404 explicitly before reaching this
                // helper.  Reaching here means the server returned 404 for a
                // method that should not produce it (store, search, list,
                // health), which is a contract violation, not a transport
                // failure.
                MemoryError::Backend(format!("{context}: unexpected 404 from server"))
            }
            400 => MemoryError::InvalidQuery(format!("{context}: bad request ({status})")),
            _ => MemoryError::ConnectionFailed(format!("{context}: unexpected status {status}")),
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryAdapter impl
// ---------------------------------------------------------------------------

#[async_trait]
impl MemoryAdapter for HttpAdapter {
    /// Store `text` with the given `tags` and `metadata`.
    ///
    /// `POST {base}/store` -> 201 `{ id, created_at }`.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::ConnectionFailed`] on transport failure,
    /// [`MemoryError::Unauthorized`] on 401/403, or
    /// [`MemoryError::Backend`] on unexpected responses.
    async fn store(
        &self,
        text: &str,
        tags: &[String],
        metadata: Metadata,
    ) -> Result<MemoryId, MemoryError> {
        let url = self.url("store")?;
        let body = StoreRequest {
            text,
            tags,
            metadata: &metadata.inner,
        };
        let body_json =
            serde_json::to_string(&body).map_err(|e| MemoryError::Backend(e.to_string()))?;

        let resp = self
            .execute_with_retry(|| {
                self.client
                    .post(url.clone())
                    .header("Content-Type", "application/json")
                    .body(body_json.clone())
            })
            .await?;

        let status = resp.status();
        if status != StatusCode::CREATED {
            return Err(Self::map_status_error(status, "store"));
        }

        let store_resp: StoreResponse = resp
            .json()
            .await
            .map_err(|e| MemoryError::Backend(format!("store: failed to parse response: {e}")))?;

        Ok(MemoryId::from_uuid(store_resp.id))
    }

    /// Search for up to `k` memories matching `query`.
    ///
    /// Returns `Ok(vec![])` immediately when `k == 0` without making a request.
    ///
    /// `POST {base}/search` -> 200 `{ results: [Memory, ...] }`.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::InvalidQuery`] on 400,
    /// [`MemoryError::Unauthorized`] on 401/403,
    /// [`MemoryError::RateLimited`] when exhausted,
    /// or [`MemoryError::ConnectionFailed`] on transport failure.
    async fn search(
        &self,
        query: &str,
        k: usize,
        filters: &Filters,
    ) -> Result<Vec<Memory>, MemoryError> {
        if k == 0 {
            return Ok(Vec::new());
        }

        let url = self.url("search")?;

        // Build sorted tags slice for the wire DTO.
        let sorted_tags: Option<Vec<&str>> = filters.tags.as_ref().map(|tags| {
            let mut sorted: Vec<&str> = tags.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            sorted
        });

        let body = SearchRequest {
            query,
            k,
            filters: FiltersDto {
                tags: sorted_tags,
                after: filters.after,
                before: filters.before,
                metadata: filters.metadata.as_ref(),
            },
        };
        let body_json =
            serde_json::to_string(&body).map_err(|e| MemoryError::Backend(e.to_string()))?;

        let resp = self
            .execute_with_retry(|| {
                self.client
                    .post(url.clone())
                    .header("Content-Type", "application/json")
                    .body(body_json.clone())
            })
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Self::map_status_error(status, "search"));
        }

        let search_resp: SearchResponse = resp
            .json()
            .await
            .map_err(|e| MemoryError::Backend(format!("search: failed to parse response: {e}")))?;

        Ok(search_resp
            .results
            .into_iter()
            .map(memory_from_dto)
            .collect())
    }

    /// Retrieve a single memory by its identifier.
    ///
    /// `GET {base}/memories/{id}` -> 200 Memory | 404.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::NotFound`] on 404,
    /// [`MemoryError::Unauthorized`] on 401/403,
    /// or [`MemoryError::ConnectionFailed`] on transport failure.
    async fn recall(&self, id: &MemoryId) -> Result<Memory, MemoryError> {
        let url = self.url(&format!("memories/{id}"))?;

        let resp = self
            .execute_with_retry(|| self.client.get(url.clone()))
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Err(MemoryError::NotFound(id.clone()));
        }
        if !status.is_success() {
            return Err(Self::map_status_error(status, "recall"));
        }

        let dto: MemoryDto = resp
            .json()
            .await
            .map_err(|e| MemoryError::Backend(format!("recall: failed to parse response: {e}")))?;

        Ok(memory_from_dto(dto))
    }

    /// Return a paginated slice of all stored memories.
    ///
    /// `GET {base}/memories?limit={limit}&offset={offset}` -> 200 `{ items: [...] }`.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::ConnectionFailed`] on transport failure or
    /// [`MemoryError::Unauthorized`] on 401/403.
    async fn list(&self, limit: usize, offset: usize) -> Result<Vec<Memory>, MemoryError> {
        let url = self.url(&format!("memories?limit={limit}&offset={offset}"))?;

        let resp = self
            .execute_with_retry(|| self.client.get(url.clone()))
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Self::map_status_error(status, "list"));
        }

        let list_resp: ListResponse = resp
            .json()
            .await
            .map_err(|e| MemoryError::Backend(format!("list: failed to parse response: {e}")))?;

        Ok(list_resp.items.into_iter().map(memory_from_dto).collect())
    }

    /// Permanently delete the memory with the given identifier.
    ///
    /// `DELETE {base}/memories/{id}` -> 204 | 404.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::NotFound`] on 404,
    /// [`MemoryError::Unauthorized`] on 401/403,
    /// or [`MemoryError::ConnectionFailed`] on transport failure.
    async fn forget(&self, id: &MemoryId) -> Result<(), MemoryError> {
        let url = self.url(&format!("memories/{id}"))?;

        let resp = self
            .execute_with_retry(|| self.client.delete(url.clone()))
            .await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Err(MemoryError::NotFound(id.clone()));
        }
        if status == StatusCode::NO_CONTENT {
            return Ok(());
        }
        Err(Self::map_status_error(status, "forget"))
    }

    /// Report the operational health of the remote memory service.
    ///
    /// `GET {base}/health` -> 200 `{ healthy: bool, message: string }`.
    ///
    /// Measures round-trip latency. If the HTTP call itself fails (not just
    /// an unhealthy response), returns [`MemoryError::ConnectionFailed`].
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::ConnectionFailed`] only when the health probe
    /// cannot complete. A reachable-but-unhealthy service is reflected as
    /// `Ok(HealthStatus { healthy: false, .. })`.
    async fn health(&self) -> Result<HealthStatus, MemoryError> {
        let url = self.url("health")?;
        let start = Instant::now();

        let resp = self
            .execute_with_retry(|| self.client.get(url.clone()))
            .await?;

        let latency_ms = start.elapsed().as_millis() as u64;
        let status = resp.status();

        if !status.is_success() {
            return Err(MemoryError::ConnectionFailed(format!(
                "health endpoint returned {status}"
            )));
        }

        let health_resp: HealthResponse = resp.json().await.map_err(|e| {
            MemoryError::ConnectionFailed(format!("health: failed to parse response: {e}"))
        })?;

        Ok(HealthStatus {
            healthy: health_resp.healthy,
            message: health_resp.message,
            latency_ms: Some(latency_ms),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a wire [`MemoryDto`] into the shared [`Memory`] type.
fn memory_from_dto(dto: MemoryDto) -> Memory {
    Memory {
        id: MemoryId::from_uuid(dto.id),
        text: dto.text,
        tags: dto.tags,
        metadata: Metadata {
            inner: dto.metadata,
        },
        created_at: dto.created_at,
        updated_at: dto.updated_at,
    }
}

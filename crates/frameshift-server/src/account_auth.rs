//! OIDC bearer-token validation and account identity extraction.
//!
//! The verifier accepts only explicitly configured asymmetric algorithms,
//! validates issuer, audience, subject, expiry, and optional not-before claims,
//! and refreshes provider JWKS data without following redirects. Cached keys
//! may be used for a bounded stale window only when the provider is unavailable.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::config::OidcConfig;

/// Maximum accepted discovery or JWKS response size.
const MAX_OIDC_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Identity claims retained after successful bearer-token validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOidcIdentity {
    /// Exact validated issuer claim.
    pub issuer: String,
    /// Issuer-scoped stable subject claim.
    pub subject: String,
    /// Optional email profile metadata.
    pub email: Option<String>,
    /// Optional preferred display name.
    pub display_name: Option<String>,
    /// Authentication time used for step-up freshness checks.
    pub auth_time: Option<u64>,
}

/// Sanitized bearer validation failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OidcAuthError {
    /// The configured OIDC contract is incomplete or unsafe.
    #[error("OIDC configuration is invalid")]
    InvalidConfiguration,
    /// Provider discovery or JWKS refresh is unavailable without usable cache data.
    #[error("OIDC provider is temporarily unavailable")]
    ProviderUnavailable,
    /// The bearer token is absent, malformed, unverifiable, or violates claims policy.
    #[error("bearer token is invalid")]
    InvalidToken,
}

/// Async token verifier abstraction used by account middleware and test doubles.
#[async_trait]
pub trait BearerTokenVerifier: Send + Sync {
    /// Validate one encoded access token and return its stable identity claims.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError>;
}

/// Provider discovery fields required by the resource server.
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    /// Issuer asserted by the provider metadata.
    issuer: String,
    /// Provider JSON Web Key Set endpoint.
    jwks_uri: String,
}

/// Claims decoded only after signature and registered-claim validation.
#[derive(Debug, Deserialize)]
struct OidcClaims {
    /// Exact issuer claim.
    iss: String,
    /// Stable subject claim.
    sub: String,
    /// Optional email profile metadata.
    email: Option<String>,
    /// Optional preferred username.
    preferred_username: Option<String>,
    /// Optional human-readable name.
    name: Option<String>,
    /// Optional authentication timestamp.
    auth_time: Option<u64>,
}

/// Cached provider key set and its successful fetch time.
#[derive(Debug, Clone)]
struct CachedJwks {
    /// Parsed provider key set.
    keys: JwkSet,
    /// Monotonic time at which the key set was fetched.
    fetched_at: Instant,
}

/// Production OIDC verifier with discovery and bounded JWKS caching.
pub struct OidcVerifier {
    /// Validated immutable OIDC policy.
    config: OidcConfig,
    /// No-redirect HTTP client used for discovery and JWKS retrieval.
    client: reqwest::Client,
    /// Explicit or discovered JWKS endpoint.
    jwks_url: RwLock<Option<Url>>,
    /// Last successfully fetched key set.
    cache: RwLock<Option<CachedJwks>>,
    /// Parsed asymmetric algorithm allowlist.
    algorithms: Vec<Algorithm>,
}

/// Construction, retrieval, and validation behavior for [`OidcVerifier`].
impl OidcVerifier {
    /// Build a verifier when OIDC is enabled and fully valid.
    ///
    /// A disabled configuration returns `Ok(None)`. An enabled but incomplete
    /// configuration returns an error so the caller can omit authenticated routes.
    pub fn from_config(
        config: &OidcConfig,
    ) -> Result<Option<Arc<dyn BearerTokenVerifier>>, OidcAuthError> {
        if !config.enabled {
            return Ok(None);
        }
        validate_remote_url(&config.issuer)?;
        if config.audience.trim().is_empty()
            || config.allowed_algorithms.is_empty()
            || config.jwks_cache_ttl.is_zero()
        {
            return Err(OidcAuthError::InvalidConfiguration);
        }
        let algorithms = config
            .allowed_algorithms
            .iter()
            .map(|value| parse_algorithm(value))
            .collect::<Result<Vec<_>, _>>()?;
        let jwks_url = if config.jwks_url.trim().is_empty() {
            None
        } else {
            Some(validate_remote_url(&config.jwks_url)?)
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| OidcAuthError::InvalidConfiguration)?;
        let mut normalized = config.clone();
        normalized.issuer = config.issuer.trim().to_string();
        Ok(Some(Arc::new(Self {
            config: normalized,
            client,
            jwks_url: RwLock::new(jwks_url),
            cache: RwLock::new(None),
            algorithms,
        })))
    }

    /// Resolve and cache the provider JWKS endpoint through OIDC discovery.
    async fn resolve_jwks_url(&self) -> Result<Url, OidcAuthError> {
        if let Some(url) = self.jwks_url.read().await.clone() {
            return Ok(url);
        }
        let discovery_url = discovery_url(&self.config.issuer)?;
        let document: DiscoveryDocument = self.fetch_json(discovery_url).await?;
        if document.issuer != self.config.issuer {
            return Err(OidcAuthError::InvalidConfiguration);
        }
        let resolved = validate_remote_url(&document.jwks_uri)?;
        *self.jwks_url.write().await = Some(resolved.clone());
        Ok(resolved)
    }

    /// Fetch and size-limit one provider JSON document.
    async fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: Url,
    ) -> Result<T, OidcAuthError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| OidcAuthError::ProviderUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > MAX_OIDC_DOCUMENT_BYTES as u64)
        {
            return Err(OidcAuthError::ProviderUnavailable);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| OidcAuthError::ProviderUnavailable)?;
        if bytes.len() > MAX_OIDC_DOCUMENT_BYTES {
            return Err(OidcAuthError::ProviderUnavailable);
        }
        serde_json::from_slice(&bytes).map_err(|_| OidcAuthError::ProviderUnavailable)
    }

    /// Return fresh keys, refresh expired keys, or use bounded stale data on outage.
    async fn keys(&self, force_refresh: bool) -> Result<JwkSet, OidcAuthError> {
        if !force_refresh {
            if let Some(cached) = self.cache.read().await.as_ref() {
                if cached.fetched_at.elapsed() <= self.config.jwks_cache_ttl {
                    return Ok(cached.keys.clone());
                }
            }
        }
        let mut cache = self.cache.write().await;
        if !force_refresh {
            if let Some(cached) = cache.as_ref() {
                if cached.fetched_at.elapsed() <= self.config.jwks_cache_ttl {
                    return Ok(cached.keys.clone());
                }
            }
        }
        let fetched = match self.resolve_jwks_url().await {
            Ok(url) => self.fetch_json::<JwkSet>(url).await,
            Err(error) => Err(error),
        };
        match fetched {
            Ok(keys) if !keys.keys.is_empty() => {
                *cache = Some(CachedJwks {
                    keys: keys.clone(),
                    fetched_at: Instant::now(),
                });
                Ok(keys)
            }
            Ok(_) => Err(OidcAuthError::ProviderUnavailable),
            Err(error) => {
                let stale_limit = self.config.jwks_cache_ttl + self.config.jwks_stale_ttl;
                cache
                    .as_ref()
                    .filter(|cached| cached.fetched_at.elapsed() <= stale_limit)
                    .map(|cached| cached.keys.clone())
                    .ok_or(error)
            }
        }
    }

    /// Validate a token against a particular key set, refreshing once for rotation.
    async fn verify_with_rotation(
        &self,
        token: &str,
        key_id: &str,
        algorithm: Algorithm,
    ) -> Result<OidcClaims, OidcAuthError> {
        let mut keys = self.keys(false).await?;
        let mut key = keys.find(key_id);
        if key.is_none() {
            keys = self.keys(true).await?;
            key = keys.find(key_id);
        }
        let decoding_key = DecodingKey::from_jwk(key.ok_or(OidcAuthError::InvalidToken)?)
            .map_err(|_| OidcAuthError::InvalidToken)?;
        let mut validation = Validation::new(algorithm);
        validation.algorithms = self.algorithms.clone();
        validation.leeway = self.config.clock_skew.as_secs();
        validation.validate_nbf = true;
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        decode::<OidcClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|_| OidcAuthError::InvalidToken)
    }
}

/// Bearer-token validation implementation backed by provider JWKS data.
#[async_trait]
impl BearerTokenVerifier for OidcVerifier {
    /// Validate signature, algorithm, registered claims, and stable identity.
    async fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcAuthError> {
        if token.len() > 16 * 1024 {
            return Err(OidcAuthError::InvalidToken);
        }
        let header = decode_header(token).map_err(|_| OidcAuthError::InvalidToken)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(OidcAuthError::InvalidToken);
        }
        let key_id = header.kid.as_deref().ok_or(OidcAuthError::InvalidToken)?;
        let claims = self.verify_with_rotation(token, key_id, header.alg).await?;
        if claims.sub.trim().is_empty() || claims.iss != self.config.issuer {
            return Err(OidcAuthError::InvalidToken);
        }
        Ok(VerifiedOidcIdentity {
            issuer: claims.iss,
            subject: claims.sub,
            email: claims.email,
            display_name: claims.preferred_username.or(claims.name),
            auth_time: claims.auth_time,
        })
    }
}

/// Parse one configured algorithm and reject all shared-secret JWT modes.
fn parse_algorithm(value: &str) -> Result<Algorithm, OidcAuthError> {
    let algorithm =
        Algorithm::from_str(value.trim()).map_err(|_| OidcAuthError::InvalidConfiguration)?;
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Err(OidcAuthError::InvalidConfiguration)
        }
        _ => Ok(algorithm),
    }
}

/// Validate provider URLs while permitting HTTP only for loopback test issuers.
fn validate_remote_url(value: &str) -> Result<Url, OidcAuthError> {
    let url = Url::parse(value.trim()).map_err(|_| OidcAuthError::InvalidConfiguration)?;
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    if url.scheme() != "https" && !loopback_http {
        return Err(OidcAuthError::InvalidConfiguration);
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OidcAuthError::InvalidConfiguration);
    }
    Ok(url)
}

/// Build the standards-defined discovery path for an issuer with an optional path.
fn discovery_url(issuer: &str) -> Result<Url, OidcAuthError> {
    let mut url = validate_remote_url(issuer)?;
    let issuer_path = url.path().trim_matches('/');
    let path = if issuer_path.is_empty() {
        "/.well-known/openid-configuration".to_string()
    } else {
        format!("/.well-known/openid-configuration/{issuer_path}")
    };
    url.set_path(&path);
    Ok(url)
}

#[cfg(test)]
/// Unit tests for OIDC configuration rejection before network access.
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::{Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::{json, Value};

    use super::*;

    /// Mutable local JWKS provider state used by verifier integration tests.
    #[derive(Clone)]
    struct TestProviderState {
        /// Current JWKS response document.
        jwks: Arc<RwLock<Value>>,
        /// Whether the provider should return a temporary outage.
        unavailable: Arc<AtomicBool>,
    }

    /// Return the current JWKS document or a temporary provider failure.
    async fn serve_jwks(State(state): State<TestProviderState>) -> Response {
        if state.unavailable.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Json(state.jwks.read().await.clone()).into_response()
    }

    /// Start a loopback JWKS server and return its URL, state, and task handle.
    async fn start_provider(
        initial_jwks: Value,
    ) -> (String, TestProviderState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = TestProviderState {
            jwks: Arc::new(RwLock::new(initial_jwks)),
            unavailable: Arc::new(AtomicBool::new(false)),
        };
        let router = Router::new()
            .route("/jwks", get(serve_jwks))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), state, task)
    }

    /// Encode one Ed25519 JWT from deterministic test key material.
    fn token(seed: [u8; 32], key_id: &str, claims: Value) -> String {
        let mut private_der = hex::decode("302e020100300506032b657004220420").unwrap();
        private_der.extend_from_slice(&seed);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id.to_string());
        encode(&header, &claims, &EncodingKey::from_ed_der(&private_der)).unwrap()
    }

    /// Build one Ed25519 public JWK from deterministic test key material.
    fn jwk(seed: [u8; 32], key_id: &str) -> Value {
        let signing_key = SigningKey::from_bytes(&seed);
        json!({
            "kty": "OKP",
            "use": "sig",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            "kid": key_id,
            "alg": "EdDSA"
        })
    }

    /// Return the current Unix timestamp for registered-claim test fixtures.
    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Shared-secret JWT algorithms are rejected even when explicitly configured.
    #[test]
    fn hmac_algorithms_are_rejected() {
        assert_eq!(
            parse_algorithm("HS256"),
            Err(OidcAuthError::InvalidConfiguration)
        );
    }

    /// Public HTTP provider URLs are rejected while loopback test URLs are allowed.
    #[test]
    fn provider_url_requires_https_except_loopback() {
        assert!(validate_remote_url("http://issuer.example").is_err());
        assert!(validate_remote_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_remote_url("https://issuer.example").is_ok());
    }

    /// Discovery inserts the well-known segment before an issuer path.
    #[test]
    fn discovery_url_preserves_issuer_path_semantics() {
        assert_eq!(
            discovery_url("https://issuer.example/tenant")
                .unwrap()
                .as_str(),
            "https://issuer.example/.well-known/openid-configuration/tenant"
        );
    }

    /// The production verifier enforces claims, rotation, and bounded outage behavior.
    #[tokio::test]
    async fn verifier_enforces_security_contract_and_rotates_keys() {
        let seed_one = [11_u8; 32];
        let seed_two = [22_u8; 32];
        let (issuer, provider, task) =
            start_provider(json!({"keys": [jwk(seed_one, "key-one")]})).await;
        let config = OidcConfig {
            enabled: true,
            issuer: issuer.clone(),
            audience: "frameshift-api".to_string(),
            jwks_url: format!("{issuer}/jwks"),
            allowed_algorithms: vec!["EdDSA".to_string()],
            jwks_cache_ttl: Duration::from_millis(30),
            jwks_stale_ttl: Duration::from_millis(30),
            clock_skew: Duration::ZERO,
            fresh_auth_max_age: Duration::from_secs(300),
        };
        let verifier = OidcVerifier::from_config(&config).unwrap().unwrap();
        let now = unix_now();
        let valid_claims = json!({
            "iss": issuer,
            "sub": "account-1",
            "aud": "frameshift-api",
            "exp": now + 300,
            "nbf": now - 1,
            "auth_time": now
        });
        let valid = token(seed_one, "key-one", valid_claims.clone());
        assert_eq!(verifier.verify(&valid).await.unwrap().subject, "account-1");

        let wrong_issuer = token(
            seed_one,
            "key-one",
            json!({"iss":"https://wrong.example","sub":"x","aud":"frameshift-api","exp":now+300}),
        );
        assert_eq!(
            verifier.verify(&wrong_issuer).await,
            Err(OidcAuthError::InvalidToken)
        );
        let wrong_audience = token(
            seed_one,
            "key-one",
            json!({"iss":config.issuer,"sub":"x","aud":"wrong","exp":now+300}),
        );
        assert_eq!(
            verifier.verify(&wrong_audience).await,
            Err(OidcAuthError::InvalidToken)
        );
        let expired = token(
            seed_one,
            "key-one",
            json!({"iss":config.issuer,"sub":"x","aud":"frameshift-api","exp":now-1}),
        );
        assert_eq!(
            verifier.verify(&expired).await,
            Err(OidcAuthError::InvalidToken)
        );
        let not_yet_valid = token(
            seed_one,
            "key-one",
            json!({"iss":config.issuer,"sub":"x","aud":"frameshift-api","exp":now+300,"nbf":now+60}),
        );
        assert_eq!(
            verifier.verify(&not_yet_valid).await,
            Err(OidcAuthError::InvalidToken)
        );

        *provider.jwks.write().await = json!({"keys": [jwk(seed_two, "key-two")]});
        let rotated = token(
            seed_two,
            "key-two",
            json!({"iss":config.issuer,"sub":"rotated","aud":"frameshift-api","exp":now+300}),
        );
        assert_eq!(verifier.verify(&rotated).await.unwrap().subject, "rotated");

        provider.unavailable.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert_eq!(
            verifier.verify(&rotated).await,
            Err(OidcAuthError::ProviderUnavailable)
        );
        task.abort();
    }
}

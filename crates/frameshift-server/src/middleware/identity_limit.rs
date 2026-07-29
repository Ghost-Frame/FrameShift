//! Identity-aware rate limiting for authenticated and signed requests.
//!
//! Complements the per-IP governor boundary applied in the router: the per-IP
//! layers bound unauthenticated floods by source address, while these keyed
//! limiters bound each verified identity regardless of how many addresses it
//! rotates through. Every check runs strictly after authentication, so limiter
//! keys are bounded by real accounts, enrolled signing keys, and authorized
//! publishers -- an unauthenticated caller can neither insert limiter state
//! nor spend another identity's budget.
//!
//! Rejections return the fixed [`AppError::RateLimited`] 429 body so responses
//! never reveal which identity dimension tripped.

use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Extension, Request};
use axum::middleware::Next;
use axum::response::Response;
use frameshift_catalog::identity::Ed25519PublicKey;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use uuid::Uuid;

use crate::auth::VerifiedSigner;
use crate::config::ServerConfig;
use crate::error::AppError;
use crate::middleware::account::AuthenticatedAccount;

/// Keyed token-bucket limiter over one identity dimension.
///
/// [`DefaultKeyedStateStore`] resolves to governor's `DashMap`-backed store
/// (the crate's default features), which implements
/// [`governor::state::keyed::ShrinkableKeyedStateStore`] and therefore
/// supports the `retain_recent` eviction used below to bound the signer
/// limiter's growth.
type KeyedLimiter<K> = RateLimiter<K, DefaultKeyedStateStore<K>, DefaultClock>;

/// Number of signer-limiter checks between automatic `retain_recent` sweeps.
///
/// The signer limiter is keyed by any Ed25519 key whose request signature
/// verifies -- enrollment/authorization for that key is checked later, deep
/// inside the handler, not by this middleware. An unauthenticated caller can
/// therefore mint an unbounded number of distinct keypairs and force an
/// unbounded number of distinct entries into the limiter's map, unlike the
/// account and publisher dimensions (which only ever see already-authenticated
/// real identities). Periodically sweeping entries that are indistinguishable
/// from an unused key bounds the map's steady-state size regardless of how
/// many distinct unenrolled keys arrive, mirroring the bounded eviction the
/// replay-nonce cache already applies (see `auth::NonceCache`).
const SIGNER_RETAIN_SWEEP_INTERVAL: u64 = 256;

/// Identity-keyed rate limiters for accounts, signing keys, and publishers.
///
/// Each dimension is independently configured; a rate of `0` disables that
/// dimension entirely, matching the semantics of the per-IP knobs. Burst
/// capacity equals the per-minute rate, mirroring the per-IP governor layers.
pub struct IdentityRateLimits {
    /// Per-account limiter applied to all account-authenticated routes.
    ///
    /// Bounded by real accounts (only ever keyed after `require_account`
    /// authenticates a durable account), so no periodic sweep is needed.
    account: Option<KeyedLimiter<Uuid>>,
    /// Per-signing-key limiter applied after signed-request verification.
    ///
    /// NOT bounded by enrollment -- see [`SIGNER_RETAIN_SWEEP_INTERVAL`] for
    /// why this dimension alone needs periodic eviction.
    signer: Option<KeyedLimiter<Ed25519PublicKey>>,
    /// Per-publisher limiter applied after publisher authority is authorized.
    ///
    /// Bounded by authorized publishers, so no periodic sweep is needed.
    publisher: Option<KeyedLimiter<Uuid>>,
    /// Count of signer-limiter checks since the last `retain_recent` sweep.
    signer_checks: AtomicU64,
}

/// Construction and per-dimension budget checks.
impl IdentityRateLimits {
    /// Build all limiters from configuration; a zero rate disables a dimension.
    pub fn from_config(config: &ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            account: keyed_limiter(config.account_rate_per_min),
            signer: keyed_limiter(config.signer_rate_per_min),
            publisher: keyed_limiter(config.publisher_rate_per_min),
            signer_checks: AtomicU64::new(0),
        })
    }

    /// Spend one token for the authenticated account or reject with 429.
    pub fn check_account(&self, account_id: Uuid) -> Result<(), AppError> {
        check(self.account.as_ref(), &account_id)
    }

    /// Spend one token for the verified signing key or reject with 429.
    ///
    /// Every [`SIGNER_RETAIN_SWEEP_INTERVAL`] checks, this also triggers a
    /// `retain_recent` sweep over the signer limiter's key map so entries
    /// left behind by unenrolled, never-reused keys do not accumulate
    /// forever (F-09). The sweep runs after the budget check so the
    /// request's own outcome never depends on sweep timing.
    pub fn check_signer(&self, pubkey: Ed25519PublicKey) -> Result<(), AppError> {
        let result = check(self.signer.as_ref(), &pubkey);
        if let Some(limiter) = self.signer.as_ref() {
            let count = self.signer_checks.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_multiple_of(SIGNER_RETAIN_SWEEP_INTERVAL) {
                limiter.retain_recent();
            }
        }
        result
    }

    /// Spend one token for the authorized publisher or reject with 429.
    pub fn check_publisher(&self, publisher_id: Uuid) -> Result<(), AppError> {
        check(self.publisher.as_ref(), &publisher_id)
    }
}

/// Construct one keyed limiter, or `None` when the rate is zero (disabled).
fn keyed_limiter<K: Hash + Eq + Clone>(rate_per_min: u32) -> Option<KeyedLimiter<K>> {
    NonZeroU32::new(rate_per_min).map(|rate| RateLimiter::keyed(Quota::per_minute(rate)))
}

/// Spend one token for `key`, mapping exhaustion to the fixed 429 error.
fn check<K: Hash + Eq + Clone>(limiter: Option<&KeyedLimiter<K>>, key: &K) -> Result<(), AppError> {
    match limiter {
        None => Ok(()),
        Some(limiter) => limiter
            .check_key(key)
            .map_err(|_not_until| AppError::RateLimited),
    }
}

/// Enforce the per-account limit for a request authenticated by `require_account`.
///
/// Mounted strictly inside the account layer, so the [`AuthenticatedAccount`]
/// extension is always present; a missing extension is a wiring bug and fails
/// closed with an internal error instead of passing unlimited.
pub async fn enforce_account_rate_limit(
    Extension(limits): Extension<Arc<IdentityRateLimits>>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let account = request
        .extensions()
        .get::<AuthenticatedAccount>()
        .ok_or_else(|| {
            AppError::Internal("account rate limit ran without authentication".to_string())
        })?;
    limits.check_account(account.account.id)?;
    Ok(next.run(request).await)
}

/// Enforce the per-signing-key limit for a verified signed request.
///
/// Mounted strictly inside the signed-request layer, so only requests whose
/// Ed25519 signature already verified can spend a key's budget -- forged
/// requests naming a victim key are rejected 401 before reaching this point
/// and are bounded by the per-IP layer instead. A missing [`VerifiedSigner`]
/// extension is a wiring bug and fails closed with an internal error.
pub async fn enforce_signer_rate_limit(
    Extension(limits): Extension<Arc<IdentityRateLimits>>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let signer = request
        .extensions()
        .get::<VerifiedSigner>()
        .ok_or_else(|| {
            AppError::Internal("signer rate limit ran without signature verification".to_string())
        })?;
    limits.check_signer(signer.pubkey)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
/// Unit tests for limiter construction, isolation, and disabled dimensions.
mod tests {
    use std::time::Duration;

    use super::*;

    /// Build a config whose identity rates are the given triple.
    fn config_with_rates(account: u32, signer: u32, publisher: u32) -> ServerConfig {
        let mut config = crate::config::test_support::minimal_test_config();
        config.account_rate_per_min = account;
        config.signer_rate_per_min = signer;
        config.publisher_rate_per_min = publisher;
        config
    }

    /// A zero rate disables its dimension while others still enforce.
    #[test]
    fn zero_rate_disables_only_its_dimension() {
        let limits = IdentityRateLimits::from_config(&config_with_rates(0, 1, 1));
        let account = Uuid::new_v4();
        for _ in 0..10 {
            limits
                .check_account(account)
                .expect("disabled account limiter must never reject");
        }
        let publisher = Uuid::new_v4();
        limits
            .check_publisher(publisher)
            .expect("first publisher request must pass");
        assert!(
            limits.check_publisher(publisher).is_err(),
            "second publisher request within the window must be rejected"
        );
    }

    /// Exhausting one key leaves every other key's budget untouched.
    #[test]
    fn keys_are_isolated_per_identity() {
        let limits = IdentityRateLimits::from_config(&config_with_rates(1, 1, 1));
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        limits
            .check_account(first)
            .expect("first account request must pass");
        assert!(
            limits.check_account(first).is_err(),
            "first account must be exhausted"
        );
        limits
            .check_account(second)
            .expect("an unrelated account must be unaffected");

        let key_a = Ed25519PublicKey([1u8; 32]);
        let key_b = Ed25519PublicKey([2u8; 32]);
        limits
            .check_signer(key_a)
            .expect("first signer request must pass");
        assert!(
            limits.check_signer(key_a).is_err(),
            "signer key A must be exhausted"
        );
        limits
            .check_signer(key_b)
            .expect("an unrelated signer key must be unaffected");
    }

    /// Many distinct unenrolled signer keys do not grow the limiter map
    /// without bound: the periodic sweep triggered inside `check_signer`
    /// evicts entries that have fully recovered, keeping the map bounded
    /// even though every check below uses a brand-new key (F-09 regression).
    #[tokio::test]
    async fn signer_limiter_growth_is_bounded_by_periodic_retain_sweep() {
        // A quota whose full burst recovers in about a millisecond lets this
        // test observe real eviction without a long real-time sleep; the
        // sweep mechanism itself is otherwise identical to production.
        let quota = Quota::with_period(Duration::from_millis(1))
            .expect("positive period is valid")
            .allow_burst(NonZeroU32::new(1).expect("1 is nonzero"));
        let limits = IdentityRateLimits {
            account: None,
            signer: Some(RateLimiter::keyed(quota)),
            publisher: None,
            signer_checks: AtomicU64::new(0),
        };
        let total_keys = (SIGNER_RETAIN_SWEEP_INTERVAL * 3) as u32;
        for i in 0..total_keys {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            limits
                .check_signer(Ed25519PublicKey(bytes))
                .expect("a brand-new key must always pass its own first check");
            if i % 64 == 0 {
                // Let the fast-recovering quota clear earlier keys so the
                // periodic sweep inside `check_signer` has stale entries to
                // evict, mirroring how idle unenrolled keys age out in
                // production over the real per-minute quota window.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        let signer = limits.signer.as_ref().expect("signer limiter configured");
        assert!(
            signer.len() < total_keys as usize,
            "periodic retain_recent sweeps inside check_signer must bound map \
             growth: expected fewer than {total_keys} entries, found {}",
            signer.len()
        );
    }

    /// Burst capacity equals the configured per-minute rate.
    #[test]
    fn burst_capacity_matches_configured_rate() {
        let limits = IdentityRateLimits::from_config(&config_with_rates(3, 0, 0));
        let account = Uuid::new_v4();
        for attempt in 0..3 {
            limits
                .check_account(account)
                .unwrap_or_else(|_| panic!("burst request {attempt} must pass"));
        }
        assert!(
            limits.check_account(account).is_err(),
            "request beyond burst capacity must be rejected"
        );
    }
}

//! Retry logic for the HTTP memory adapter.
//!
//! Retries are applied for HTTP 5xx responses and 429 (Too Many Requests).
//! 4xx responses other than 429 are not retried. The policy is:
//!
//! - 3 total attempts (1 initial + 2 retries).
//! - Exponential backoff with a 200ms base and +/-25% jitter.
//! - If the server returns a `Retry-After` header with an integer number of
//!   seconds, that duration is used instead of the computed backoff (capped at
//!   a reasonable maximum to avoid blocking indefinitely).

use std::time::Duration;

/// Maximum wait imposed even if `Retry-After` says longer.
const MAX_RETRY_AFTER_SECS: u64 = 60;

/// Total number of attempts (initial + retries).
pub(crate) const MAX_ATTEMPTS: u32 = 3;

/// Base backoff duration before jitter.
const BASE_BACKOFF_MS: u64 = 200;

/// Returns `true` when the HTTP status code should trigger a retry.
///
/// Only 429 and 5xx codes are retried. 4xx (other than 429) are not retried
/// because they represent caller errors that a retry will not fix.
pub(crate) fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Compute the delay before the next attempt.
///
/// `attempt` is 0-indexed: `0` means "about to make the 2nd attempt" (first
/// retry). Uses exponential backoff (`base * 2^attempt`) plus +/-25% jitter.
///
/// If `retry_after_secs` is provided (parsed from the `Retry-After` header),
/// it overrides the computed backoff but is capped at [`MAX_RETRY_AFTER_SECS`].
pub(crate) fn backoff_delay(attempt: u32, retry_after_secs: Option<u64>) -> Duration {
    if let Some(secs) = retry_after_secs {
        return Duration::from_secs(secs.min(MAX_RETRY_AFTER_SECS));
    }

    let base_ms = BASE_BACKOFF_MS * (1u64 << attempt);
    // Jitter: +/-25% using a simple LCG-derived value.
    // We avoid pulling in `rand` just for this; instead we derive pseudo-random
    // jitter from the current nanosecond timestamp, which is sufficient for
    // spread across concurrent retries in a single process.
    let jitter_range = base_ms / 4; // 25% of base
    let jitter_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    // Map jitter_ns to [-jitter_range, +jitter_range].
    let jitter = (jitter_ns % (jitter_range * 2 + 1)) as i64 - jitter_range as i64;
    let delay_ms = (base_ms as i64 + jitter).max(0) as u64;

    Duration::from_millis(delay_ms)
}

/// Parse an integer `Retry-After` header value (seconds form).
///
/// Returns `None` if the value is absent, non-numeric (e.g. HTTP-date form),
/// or cannot be parsed as a `u64`.
pub(crate) fn parse_retry_after(header_value: Option<&str>) -> Option<u64> {
    header_value?.trim().parse::<u64>().ok()
}

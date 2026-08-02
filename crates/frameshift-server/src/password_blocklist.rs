//! Deterministic compromised and deployment-specific password rejection.

use sha2::{Digest as _, Sha256};

/// Embedded lowercase SHA-256 digests, one per non-comment line.
const BLOCKLIST_DIGESTS: &str = include_str!("password_blocklist.txt");

/// Reviewable service-specific values that attackers are expected to try.
const EXPECTED_PASSWORDS: &[&str] = &[
    "frameshiftpassword",
    "frameshift-password",
    "frameshift123456",
    "ghostframepassword",
    "syntheospassword",
];

/// Return whether a candidate matches a known or expected password.
///
/// Outer whitespace and ASCII case are ignored only for comparison. Callers
/// keep the original password bytes unchanged for hashing when the candidate
/// is accepted.
pub(crate) fn is_blocklisted(password: &str) -> bool {
    let normalized = password.trim().to_ascii_lowercase();
    if EXPECTED_PASSWORDS.contains(&normalized.as_str()) {
        return true;
    }
    let candidate_digest = hex::encode(Sha256::digest(normalized.as_bytes()));

    BLOCKLIST_DIGESTS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|digest| digest == candidate_digest)
}

#[cfg(test)]
/// Unit tests for deterministic blocklist matching.
mod tests {
    use super::is_blocklisted;

    /// The pinned compromised-password baseline is active.
    #[test]
    fn common_password_is_blocklisted() {
        assert!(is_blocklisted("password"));
    }

    /// Expected FrameShift variants ignore outer whitespace and ASCII case.
    #[test]
    fn service_specific_password_is_normalized_for_comparison() {
        assert!(is_blocklisted("  FrameShiftPassword  "));
    }

    /// An unrelated passphrase does not produce a false positive.
    #[test]
    fn unrelated_passphrase_is_not_blocklisted() {
        assert!(!is_blocklisted("correct horse battery staple"));
    }
}

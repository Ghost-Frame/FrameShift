//! First-party password hashing and verification.
//!
//! This module only provides the cryptographic primitive. Public registration,
//! login, recovery, and session routes remain disabled until their separate
//! abuse-control and recovery requirements are complete.

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;
use secrecy::{ExposeSecret as _, SecretString};

/// Argon2id memory cost in KiB from RFC 9106's memory-constrained profile.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;

/// Argon2id iteration count from RFC 9106's memory-constrained profile.
const ARGON2_ITERATIONS: u32 = 3;

/// Argon2id parallelism from RFC 9106's memory-constrained profile.
const ARGON2_PARALLELISM: u32 = 4;

/// Password-hash output length in bytes.
const ARGON2_OUTPUT_BYTES: usize = 32;

/// Errors produced by first-party password hashing and verification.
#[derive(Debug, thiserror::Error)]
pub enum PasswordAuthError {
    /// The fixed Argon2id parameters or supplied pepper are invalid.
    #[error("password hashing configuration is invalid")]
    InvalidConfiguration,

    /// Password hashing failed without producing a value safe to persist.
    #[error("password hashing failed")]
    HashFailed,

    /// The stored password hash is malformed or uses an unsupported algorithm.
    #[error("stored password hash is invalid")]
    InvalidStoredHash,

    /// Verification failed for a reason other than a password mismatch.
    #[error("password verification failed")]
    VerificationFailed,
}

/// Argon2id password service backed by a deployment secret kept outside the database.
pub struct PasswordService {
    /// Versioned deployment pepper obtained from the credential broker.
    pepper: SecretString,
}

/// Provide the first-party password cryptography operations.
impl PasswordService {
    /// Construct a password service after validating the fixed parameters and pepper.
    ///
    /// The pepper must come from the credential broker in production and must
    /// never be stored beside password hashes.
    pub fn new(pepper: SecretString) -> Result<Self, PasswordAuthError> {
        if pepper.expose_secret().is_empty() {
            return Err(PasswordAuthError::InvalidConfiguration);
        }

        let service = Self { pepper };
        service.argon2()?;
        Ok(service)
    }

    /// Hash a password with Argon2id v19 and a fresh operating-system random salt.
    ///
    /// The returned PHC string contains the algorithm, version, cost parameters,
    /// salt, and derived output needed for later verification.
    pub fn hash_password(&self, password: &SecretString) -> Result<String, PasswordAuthError> {
        let salt = SaltString::generate(&mut OsRng);

        self.argon2()?
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| PasswordAuthError::HashFailed)
    }

    /// Verify a password against a stored PHC string.
    ///
    /// A normal password mismatch returns `Ok(false)`. Malformed hashes,
    /// unsupported algorithms, and internal verification failures fail closed.
    pub fn verify_password(
        &self,
        password: &SecretString,
        encoded_hash: &str,
    ) -> Result<bool, PasswordAuthError> {
        let parsed =
            PasswordHash::new(encoded_hash).map_err(|_| PasswordAuthError::InvalidStoredHash)?;
        let parsed_params =
            Params::try_from(&parsed).map_err(|_| PasswordAuthError::InvalidStoredHash)?;
        let configured = self.argon2()?;

        if parsed.algorithm.as_str() != "argon2id"
            || parsed.version != Some(19)
            || &parsed_params != configured.params()
        {
            return Err(PasswordAuthError::InvalidStoredHash);
        }

        match configured.verify_password(password.expose_secret().as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(argon2::password_hash::Error::Algorithm) => {
                Err(PasswordAuthError::InvalidStoredHash)
            }
            Err(_) => Err(PasswordAuthError::VerificationFailed),
        }
    }

    /// Build an Argon2id v19 instance borrowing the protected deployment pepper.
    fn argon2(&self) -> Result<Argon2<'_>, PasswordAuthError> {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_BYTES),
        )
        .map_err(|_| PasswordAuthError::InvalidConfiguration)?;

        Argon2::new_with_secret(
            self.pepper.expose_secret().as_bytes(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
        .map_err(|_| PasswordAuthError::InvalidConfiguration)
    }
}

#[cfg(test)]
/// Unit tests for password hashing, verification, and fail-closed parsing.
mod tests {
    use super::{PasswordAuthError, PasswordService};
    use secrecy::SecretString;

    /// Build a deterministic-pepper service for unit tests.
    fn service() -> PasswordService {
        PasswordService::new(SecretString::from(
            "unit-test-pepper-not-for-production".to_owned(),
        ))
        .expect("test pepper should be valid")
    }

    /// Convert a test password into protected memory.
    fn password(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    /// Verify that a freshly hashed password authenticates successfully.
    #[test]
    fn correct_password_verifies() {
        let service = service();
        let password = password("a long and memorable test password");
        let hash = service
            .hash_password(&password)
            .expect("hashing should succeed");

        assert!(service
            .verify_password(&password, &hash)
            .expect("verification should succeed"));
    }

    /// Verify that a normal password mismatch is not treated as an internal error.
    #[test]
    fn wrong_password_returns_false() {
        let service = service();
        let hash = service
            .hash_password(&password("the correct long test password"))
            .expect("hashing should succeed");

        assert!(!service
            .verify_password(&password("the wrong long test password"), &hash)
            .expect("mismatch should be a normal result"));
    }

    /// Verify that each hash receives a distinct operating-system random salt.
    #[test]
    fn repeated_hashing_uses_unique_salts() {
        let service = service();
        let password = password("a repeated long test password");
        let first = service
            .hash_password(&password)
            .expect("first hash should succeed");
        let second = service
            .hash_password(&password)
            .expect("second hash should succeed");

        assert_ne!(first, second);
    }

    /// Verify that hashes encode the selected algorithm, version, and cost parameters.
    #[test]
    fn hash_encodes_argon2id_v19_parameters() {
        let hash = service()
            .hash_password(&password("a parameter inspection password"))
            .expect("hashing should succeed");

        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));
    }

    /// Verify that malformed stored hashes fail closed without panicking.
    #[test]
    fn malformed_hash_fails_closed() {
        let result = service().verify_password(&password("any password"), "not-a-phc-string");

        assert!(matches!(result, Err(PasswordAuthError::InvalidStoredHash)));
    }

    /// Verify that a well-formed hash for another algorithm is never accepted.
    #[test]
    fn unsupported_algorithm_fails_closed() {
        let service = service();
        let hash = service
            .hash_password(&password("any password"))
            .expect("hashing should succeed")
            .replacen("$argon2id$", "$argon2i$", 1);
        let result = service.verify_password(&password("any password"), &hash);

        assert!(matches!(result, Err(PasswordAuthError::InvalidStoredHash)));
    }

    /// Verify that attacker-controlled cost parameters cannot force excessive work.
    #[test]
    fn unconfigured_cost_parameters_fail_closed() {
        let service = service();
        let hash = service
            .hash_password(&password("any password"))
            .expect("hashing should succeed")
            .replacen("m=65536", "m=4294967295", 1);
        let result = service.verify_password(&password("any password"), &hash);

        assert!(matches!(result, Err(PasswordAuthError::InvalidStoredHash)));
    }

    /// Verify that an empty deployment pepper is rejected.
    #[test]
    fn empty_pepper_is_rejected() {
        let result = PasswordService::new(SecretString::from(String::new()));

        assert!(matches!(
            result,
            Err(PasswordAuthError::InvalidConfiguration)
        ));
    }
}

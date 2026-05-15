//! Configuration for [`crate::PostgresCatalog`].
//!
//! [`PostgresCatalogConfig`] carries all parameters needed to open a pool and
//! run embedded migrations. The connection URL is held in a [`secrecy::SecretString`]
//! so it is never accidentally printed to logs.

use std::fmt;
use std::time::Duration;

use secrecy::SecretString;

/// Configuration required to construct a [`crate::PostgresCatalog`].
///
/// Build this struct with field initialisation syntax or a builder pattern in
/// the calling crate. The `url` field uses [`SecretString`] so that the
/// connection URL (which may contain a password) is never emitted to logs or
/// debug output.
///
/// # Example
///
/// ```rust,no_run
/// use frameshift_catalog_postgres::PostgresCatalogConfig;
/// use secrecy::SecretString;
/// use std::time::Duration;
///
/// let config = PostgresCatalogConfig {
///     url: SecretString::from("postgres://user:pass@localhost/catalog".to_string()),
///     pool_size: 10,
///     connect_timeout: Duration::from_secs(5),
///     statement_timeout: Duration::from_secs(30),
/// };
/// ```
pub struct PostgresCatalogConfig {
    /// PostgreSQL connection URL.
    ///
    /// Format: `postgres://user:password@host:port/dbname`.
    /// Held as [`SecretString`] to prevent the password from appearing in
    /// debug output or log aggregators.
    pub url: SecretString,

    /// Maximum number of connections in the pool.
    ///
    /// This is passed directly to [`bb8::Pool::max_size`]. The pool will
    /// maintain up to `pool_size` simultaneous database connections.
    pub pool_size: u32,

    /// Maximum time to wait for a connection to be established.
    ///
    /// Passed to [`bb8::Pool::connection_timeout`]. If a connection cannot be
    /// established within this duration, pool checkout returns an error.
    pub connect_timeout: Duration,

    /// PostgreSQL `statement_timeout` session parameter.
    ///
    /// After opening each connection the pool runs:
    /// `SET statement_timeout = <ms>`.
    /// Any query that runs longer than this duration is cancelled by Postgres,
    /// which results in a `CatalogError::BackendError` returned to the caller.
    pub statement_timeout: Duration,
}

/// Manual `Debug` impl that redacts the connection URL.
///
/// Only the non-secret fields are printed. The `url` field is shown as
/// `<redacted>` to prevent password leakage through log aggregators.
impl fmt::Debug for PostgresCatalogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresCatalogConfig")
            .field("url", &"<redacted>")
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .finish()
    }
}

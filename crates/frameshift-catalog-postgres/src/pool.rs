//! Connection pool initialisation for [`crate::PostgresCatalog`].
//!
//! [`build_pool`] constructs a [`bb8::Pool`] backed by
//! `diesel_async::pooled_connection::AsyncDieselConnectionManager<AsyncPgConnection>`
//! and applies the configured `statement_timeout` to every freshly-opened
//! connection via a `SET statement_timeout = <ms>` command issued through
//! [`diesel_async::SimpleAsyncConnection::batch_execute`].

use diesel_async::pooled_connection::{AsyncDieselConnectionManager, ManagerConfig};
use diesel_async::AsyncPgConnection;
use futures_util::FutureExt as _;
use secrecy::ExposeSecret as _;

use crate::config::PostgresCatalogConfig;

/// The concrete pool type used by [`crate::PostgresCatalog`].
///
/// Alias kept here so that `backend.rs` can import it cleanly.
pub type PgPool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

/// The error type for pool checkout failures.
///
/// `bb8::RunError` wraps the pool manager's own error type, which for
/// `diesel-async` is [`diesel_async::pooled_connection::PoolError`].
pub type PgPoolRunError = bb8::RunError<diesel_async::pooled_connection::PoolError>;

/// Build a `bb8` connection pool from the provided configuration.
///
/// Each freshly-opened connection has `SET statement_timeout = <ms>` applied
/// immediately after being created via the [`ManagerConfig::custom_setup`]
/// callback. This ensures that any query exceeding the configured duration is
/// cancelled by Postgres rather than blocking indefinitely.
///
/// The pool is not validated on return -- the first checkout will surface any
/// connectivity problems.
///
/// # Errors
///
/// Returns a boxed error if the pool builder itself fails (e.g. bad URL format).
pub async fn build_pool(
    config: &PostgresCatalogConfig,
) -> Result<PgPool, Box<dyn std::error::Error + Send + Sync>> {
    let url = config.url.expose_secret().to_string();
    let statement_timeout_ms = config.statement_timeout.as_millis() as u64;

    // Build the manager with a custom connection setup callback.
    // The callback runs for every new physical connection, before the
    // connection enters the pool's idle queue.
    //
    // diesel-async 0.6+ made `ManagerConfig` generic over the connection type,
    // so the connection type is named explicitly here rather than left to
    // inference.
    let mut manager_config = ManagerConfig::<AsyncPgConnection>::default();
    manager_config.custom_setup = Box::new(move |url: &str| {
        let url = url.to_string();
        let timeout_ms = statement_timeout_ms;
        async move {
            use diesel_async::AsyncConnection as _;
            use diesel_async::SimpleAsyncConnection as _;

            let mut conn = AsyncPgConnection::establish(&url).await?;
            let timeout_sql = format!("SET statement_timeout = {timeout_ms}");
            conn.batch_execute(&timeout_sql)
                .await
                .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
            Ok(conn)
        }
        .boxed()
    });

    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(url, manager_config);

    let pool = bb8::Pool::builder()
        .max_size(config.pool_size)
        .connection_timeout(config.connect_timeout)
        .build(manager)
        .await?;

    Ok(pool)
}

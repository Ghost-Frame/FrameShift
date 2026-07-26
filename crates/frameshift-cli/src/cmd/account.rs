//! Interactive account login, status, and logout commands.
//!
//! Login uses the system browser and a loopback Authorization Code callback
//! with S256 PKCE. Tokens never enter command-line arguments or terminal input.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use frameshift_client::account::{get_account, get_auth_config, AccountView};
use frameshift_client::session::{OidcSession, SessionClient, SessionClientConfig};
use frameshift_client::session_store::{
    SessionStore, SessionStoreError, SessionStoreMetadata, StoredSession,
};
use frameshift_client::{registry_base_url, Client, ClientError};
use secrecy::SecretString;
use url::{Position, Url};

use crate::util::{validate_server_url, CliError};

/// Default public OAuth client identifier for the shipped CLI.
const DEFAULT_CLIENT_ID: &str = "frameshift-cli";
/// Default exact loopback callback registered for the shipped CLI.
const DEFAULT_REDIRECT_URI: &str = "http://127.0.0.1:8765/callback";
/// Default time allowed for a user to complete browser authorization.
const DEFAULT_LOGIN_TIMEOUT_SECS: u64 = 180;
/// Maximum accepted loopback HTTP request bytes.
const MAX_CALLBACK_REQUEST_BYTES: usize = 16 * 1024;
/// Access-token lifetime margin that triggers proactive refresh.
const REFRESH_MARGIN_SECS: u64 = 30;

/// Arguments for the `account` command group.
#[derive(Debug, Args)]
pub struct AccountArgs {
    /// Account session operation.
    #[command(subcommand)]
    pub command: AccountCommand,
}

/// Account session operations.
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Authenticate in the system browser and save the session securely.
    Login(AccountLoginArgs),
    /// Fetch and print the current authenticated account.
    Status,
    /// Revoke the provider session when supported and erase local credentials.
    Logout,
}

/// Browser login options.
#[derive(Debug, Args)]
pub struct AccountLoginArgs {
    /// Registry API base URL; defaults to `FRAMESHIFT_REGISTRY_URL` or production.
    #[arg(long)]
    pub server: Option<String>,
    /// OIDC issuer override; defaults to `FRAMESHIFT_OIDC_ISSUER` or registry discovery.
    #[arg(long)]
    pub issuer: Option<String>,
    /// Public OAuth client ID; defaults to `FRAMESHIFT_OIDC_CLIENT_ID` or `frameshift-cli`.
    #[arg(long)]
    pub client_id: Option<String>,
    /// Exact registered loopback callback URI.
    #[arg(long, default_value = DEFAULT_REDIRECT_URI)]
    pub redirect_uri: String,
    /// Comma-separated OIDC scopes.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "openid,profile,email,offline_access"
    )]
    pub scopes: Vec<String>,
    /// Seconds allowed to complete browser authorization.
    #[arg(long, default_value_t = DEFAULT_LOGIN_TIMEOUT_SECS)]
    pub timeout_secs: u64,
}

/// Accepted callback URL paired with its response stream.
struct PendingCallback {
    /// Exact callback URL reconstructed from the registered redirect.
    url: Url,
    /// Loopback browser connection awaiting a terminal response.
    stream: TcpStream,
}

/// Execute one account session operation.
pub fn run_account(args: AccountArgs) -> Result<(), CliError> {
    match args.command {
        AccountCommand::Login(args) => run_login(args),
        AccountCommand::Status => run_status(),
        AccountCommand::Logout => run_logout(),
    }
}

/// Authenticate through the browser and persist the resulting session.
fn run_login(args: AccountLoginArgs) -> Result<(), CliError> {
    let server = args.server.unwrap_or_else(registry_base_url);
    validate_server_url(&server)?;
    let registry_url = Url::parse(&server).map_err(|error| CliError::Account(error.to_string()))?;
    let issuer = resolve_issuer(&server, args.issuer)?;
    let client_id = resolve_client_id(args.client_id)?;
    let redirect_uri = Url::parse(&args.redirect_uri)
        .map_err(|error| CliError::Account(format!("invalid redirect URI: {error}")))?;
    let listener = bind_callback_listener(&redirect_uri)?;
    let timeout = Duration::from_secs(args.timeout_secs);
    let config = SessionClientConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        scopes: args.scopes.clone(),
    };
    let session_client =
        SessionClient::discover(config).map_err(|error| CliError::Account(error.to_string()))?;
    let flow = session_client
        .begin_authorization()
        .map_err(|error| CliError::Account(error.to_string()))?;
    open_browser(&flow.authorization_url);
    let mut callback = wait_for_callback(&listener, &redirect_uri, timeout)?;
    let session = match session_client.complete_authorization(&flow, &callback.url) {
        Ok(session) => session,
        Err(error) => {
            respond_to_browser(&mut callback.stream, false);
            return Err(CliError::Account(error.to_string()));
        }
    };
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    if let Err(error) = store.save(
        SessionStoreMetadata {
            issuer,
            client_id,
            redirect_uri,
            scopes: args.scopes,
            registry_url,
        },
        &session,
    ) {
        respond_to_browser(&mut callback.stream, false);
        return Err(account_store_error(error));
    }
    respond_to_browser(&mut callback.stream, true);
    println!("logged in to {server}");
    Ok(())
}

/// Load, refresh when needed, and print the current registry account.
fn run_status() -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    let mut stored = store.load().map_err(account_store_error)?;
    let session_client = session_client_for(&stored)?;
    if session_expires_soon(&stored.session) && stored.session.refresh_token().is_some() {
        stored.session = session_client
            .refresh(&stored.session)
            .map_err(|error| CliError::Account(error.to_string()))?;
        persist_loaded_session(&store, &stored)?;
    }
    let view = match get_account(
        stored.metadata.registry_url.as_str(),
        stored.session.access_token(),
    ) {
        Ok(view) => view,
        Err(ClientError::RegistryRejected { status: 401, .. })
            if stored.session.refresh_token().is_some() =>
        {
            stored.session = session_client
                .refresh(&stored.session)
                .map_err(|error| CliError::Account(error.to_string()))?;
            persist_loaded_session(&store, &stored)?;
            get_account(
                stored.metadata.registry_url.as_str(),
                stored.session.access_token(),
            )
            .map_err(|error| CliError::Account(error.to_string()))?
        }
        Err(error) => return Err(CliError::Account(error.to_string())),
    };
    print_account(&view);
    Ok(())
}

/// Return a refreshed stored access token only for its exact registry base URL.
pub(crate) fn access_token_for_registry(server: &str) -> Result<Option<SecretString>, CliError> {
    let requested_registry = normalized_registry_url(server)?;
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    let Some(mut stored) = optional_stored_session(store.load())? else {
        return Ok(None);
    };
    if normalized_registry_url(stored.metadata.registry_url.as_str())? != requested_registry {
        return Ok(None);
    }
    if session_expires_soon(&stored.session) && stored.session.refresh_token().is_some() {
        let session_client = session_client_for(&stored)?;
        stored.session = session_client
            .refresh(&stored.session)
            .map_err(|error| CliError::Account(error.to_string()))?;
        persist_loaded_session(&store, &stored)?;
    }
    Ok(Some(stored.session.access_token().clone()))
}

/// Convert a session load into optional state while preserving real failures.
fn optional_stored_session<T>(result: Result<T, SessionStoreError>) -> Result<Option<T>, CliError> {
    match result {
        Ok(stored) => Ok(Some(stored)),
        Err(SessionStoreError::NotFound) => Ok(None),
        Err(error) => Err(account_store_error(error)),
    }
}

/// Normalize a registry base URL while treating one trailing slash as cosmetic.
fn normalized_registry_url(server: &str) -> Result<Url, CliError> {
    validate_server_url(server)?;
    let mut registry = Url::parse(server).map_err(|error| CliError::Account(error.to_string()))?;
    let normalized_path = registry.path().trim_end_matches('/').to_string();
    registry.set_path(&normalized_path);
    Ok(registry)
}

/// Best-effort revoke the provider session, then erase exact local state.
fn run_logout() -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    let stored = match store.load() {
        Ok(stored) => Some(stored),
        Err(SessionStoreError::NotFound) => None,
        Err(error) => return Err(account_store_error(error)),
    };
    if let Some(stored) = &stored {
        match session_client_for(stored).and_then(|client| {
            client
                .revoke(&stored.session)
                .map_err(|error| CliError::Account(error.to_string()))
        }) {
            Ok(()) => {}
            Err(CliError::Account(message))
                if message.contains("does not advertise a revocation endpoint") => {}
            Err(error) => eprintln!("warning: provider revocation failed: {error}"),
        }
    }
    let removed = store.remove().map_err(account_store_error)?;
    if removed {
        println!("logged out and removed the local session");
    } else {
        println!("no local account session was stored");
    }
    Ok(())
}

/// Resolve the issuer from an override, environment, or registry bootstrap.
fn resolve_issuer(server: &str, override_value: Option<String>) -> Result<Url, CliError> {
    let value = override_value
        .or_else(|| nonempty_env("FRAMESHIFT_OIDC_ISSUER"))
        .map(Ok)
        .unwrap_or_else(|| {
            let config =
                get_auth_config(server).map_err(|error| CliError::Account(error.to_string()))?;
            if !config.enabled {
                return Err(CliError::Account(
                    "registry account authentication is disabled".to_string(),
                ));
            }
            config.issuer.ok_or_else(|| {
                CliError::Account("registry omitted its enabled OIDC issuer".to_string())
            })
        })?;
    Url::parse(&value).map_err(|error| CliError::Account(format!("invalid OIDC issuer: {error}")))
}

/// Resolve and validate the public OAuth client identifier.
fn resolve_client_id(override_value: Option<String>) -> Result<String, CliError> {
    let value = override_value
        .or_else(|| nonempty_env("FRAMESHIFT_OIDC_CLIENT_ID"))
        .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::Account(
            "OIDC client ID must be non-empty and contain no control characters".to_string(),
        ));
    }
    Ok(value)
}

/// Return one non-empty environment value.
fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Bind only the exact IP loopback callback address and explicit port.
fn bind_callback_listener(redirect_uri: &Url) -> Result<TcpListener, CliError> {
    if redirect_uri.scheme() != "http"
        || redirect_uri.query().is_some()
        || redirect_uri.fragment().is_some()
        || !redirect_uri.username().is_empty()
        || redirect_uri.password().is_some()
    {
        return Err(CliError::Account(
            "CLI redirect URI must be credential-free loopback HTTP without query or fragment"
                .to_string(),
        ));
    }
    let ip = redirect_uri
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .filter(IpAddr::is_loopback)
        .ok_or_else(|| {
            CliError::Account("CLI redirect URI host must be an IP loopback address".to_string())
        })?;
    let port = redirect_uri
        .port()
        .filter(|port| *port != 0)
        .ok_or_else(|| CliError::Account("CLI redirect URI needs an explicit port".to_string()))?;
    let listener = TcpListener::bind(SocketAddr::new(ip, port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Open the authorization URL or print a copyable fallback.
fn open_browser(url: &Url) {
    if let Err(error) = webbrowser::open(url.as_str()) {
        eprintln!("could not open the system browser ({error}); open this URL:\n{url}");
    }
}

/// Accept one bounded loopback callback before the deadline.
fn wait_for_callback(
    listener: &TcpListener,
    redirect_uri: &Url,
    timeout: Duration,
) -> Result<PendingCallback, CliError> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let url = read_callback_url(&mut stream, redirect_uri)?;
                return Ok(PendingCallback { url, stream });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(CliError::Account(
                        "timed out waiting for browser authorization".to_string(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(CliError::Io(error)),
        }
    }
}

/// Parse one origin-form GET request into the registered callback origin.
fn read_callback_url(stream: &mut TcpStream, redirect_uri: &Url) -> Result<Url, CliError> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > MAX_CALLBACK_REQUEST_BYTES {
            return Err(CliError::Account(
                "browser callback request exceeded the size limit".to_string(),
            ));
        }
    }
    parse_callback_request(&request, redirect_uri)
}

/// Parse bounded HTTP request bytes into the registered callback origin.
fn parse_callback_request(request: &[u8], redirect_uri: &Url) -> Result<Url, CliError> {
    let first_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim_end)
        .ok_or_else(|| CliError::Account("browser callback was not valid HTTP".to_string()))?;
    let mut parts = first_line.split_ascii_whitespace();
    let method = parts.next();
    let target = parts.next();
    let version = parts.next();
    if method != Some("GET")
        || version.is_none_or(|value| !value.starts_with("HTTP/1."))
        || parts.next().is_some()
    {
        return Err(CliError::Account(
            "browser callback must be one HTTP GET request".to_string(),
        ));
    }
    let target = target.filter(|value| value.starts_with('/') && !value.starts_with("//"));
    let target = target
        .ok_or_else(|| CliError::Account("browser callback target is invalid".to_string()))?;
    Url::parse(&format!(
        "{}{}",
        &redirect_uri[..Position::BeforePath],
        target
    ))
    .map_err(|error| CliError::Account(format!("browser callback URL is invalid: {error}")))
}

/// Send a secret-free terminal browser response.
fn respond_to_browser(stream: &mut TcpStream, success: bool) {
    let (status, message) = if success {
        (
            "200 OK",
            "FrameShift login complete. You may close this window.",
        )
    } else {
        (
            "400 Bad Request",
            "FrameShift rejected this login callback. Return to the terminal.",
        )
    };
    let body =
        format!("<!doctype html><meta charset=utf-8><title>FrameShift</title><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Recreate the provider client for persisted metadata.
fn session_client_for(stored: &StoredSession) -> Result<SessionClient, CliError> {
    SessionClient::discover(SessionClientConfig {
        issuer: stored.metadata.issuer.clone(),
        client_id: stored.metadata.client_id.clone(),
        redirect_uri: stored.metadata.redirect_uri.clone(),
        scopes: stored.metadata.scopes.clone(),
    })
    .map_err(|error| CliError::Account(error.to_string()))
}

/// Return whether an access token is expired or within the refresh margin.
fn session_expires_soon(session: &OidcSession) -> bool {
    session
        .summary()
        .expires_at
        .is_some_and(|expiry| expiry <= unix_now().saturating_add(REFRESH_MARGIN_SECS))
}

/// Rewrite one refreshed session using its existing public metadata.
fn persist_loaded_session(store: &SessionStore, stored: &StoredSession) -> Result<(), CliError> {
    store
        .save(
            SessionStoreMetadata {
                issuer: stored.metadata.issuer.clone(),
                client_id: stored.metadata.client_id.clone(),
                redirect_uri: stored.metadata.redirect_uri.clone(),
                scopes: stored.metadata.scopes.clone(),
                registry_url: stored.metadata.registry_url.clone(),
            },
            &stored.session,
        )
        .map(|_| ())
        .map_err(account_store_error)
}

/// Print non-secret account and membership state.
fn print_account(view: &AccountView) {
    println!("account: {}", view.account.id);
    println!("status: {:?}", view.account.status);
    if let Some(display_name) = &view.account.display_name {
        println!("display name: {display_name}");
    }
    if let Some(email) = &view.account.email {
        println!("email: {email}");
    }
    println!("publisher memberships: {}", view.memberships.len());
    for membership in &view.memberships {
        println!(
            "  {}  {:?}  {:?}",
            membership.publisher_id, membership.role, membership.state
        );
    }
}

/// Convert a session-store failure into the account command error surface.
fn account_store_error(error: SessionStoreError) -> CliError {
    CliError::Account(error.to_string())
}

/// Return the current Unix timestamp.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
/// Deterministic account command tests.
mod tests {
    use super::*;

    /// Registry matching ignores a cosmetic trailing slash only.
    #[test]
    fn normalizes_registry_trailing_slash_without_weakening_base_binding() {
        let base = normalized_registry_url("https://registry.example/api").expect("base URL");
        let trailing =
            normalized_registry_url("https://registry.example/api/").expect("trailing URL");
        let other_scheme =
            normalized_registry_url("http://registry.example/api").expect("scheme URL");
        let other_path =
            normalized_registry_url("https://registry.example/other").expect("path URL");

        assert_eq!(base, trailing);
        assert_ne!(base, other_scheme);
        assert_ne!(base, other_path);
    }

    /// Missing stored sessions become optional while storage failures remain visible.
    #[test]
    fn distinguishes_missing_sessions_from_store_failures() {
        assert_eq!(
            optional_stored_session::<()>(Err(SessionStoreError::NotFound))
                .expect("missing session"),
            None
        );
        let error = optional_stored_session::<()>(Err(SessionStoreError::Invalid(
            "bad metadata".to_string(),
        )))
        .expect_err("invalid session");
        assert!(error
            .to_string()
            .contains("stored FrameShift session is invalid"));
    }

    /// A valid origin-form callback is reconstructed on the registered origin.
    #[test]
    fn parses_valid_loopback_callback() {
        let redirect = Url::parse(DEFAULT_REDIRECT_URI).expect("redirect URL");
        let callback = parse_callback_request(
            b"GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: ignored\r\n\r\n",
            &redirect,
        )
        .expect("callback");
        assert_eq!(
            callback.as_str(),
            "http://127.0.0.1:8765/callback?code=abc&state=xyz"
        );
    }

    /// Absolute-form, non-GET, and ambiguous request lines fail closed.
    #[test]
    fn rejects_unsafe_callback_request_targets() {
        let redirect = Url::parse(DEFAULT_REDIRECT_URI).expect("redirect URL");
        for request in [
            b"GET http://attacker.example/callback HTTP/1.1\r\n\r\n".as_slice(),
            b"POST /callback HTTP/1.1\r\n\r\n".as_slice(),
            b"GET //attacker.example/callback HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /callback HTTP/1.1 extra\r\n\r\n".as_slice(),
        ] {
            assert!(parse_callback_request(request, &redirect).is_err());
        }
    }

    /// The CLI listener refuses non-loopback, implicit-port, and HTTPS callbacks.
    #[test]
    fn rejects_non_loopback_callback_bindings() {
        for value in [
            "http://192.0.2.1:8765/callback",
            "http://127.0.0.1/callback",
            "https://127.0.0.1:8765/callback",
            "http://localhost:8765/callback",
        ] {
            let redirect = Url::parse(value).expect("redirect URL");
            assert!(bind_callback_listener(&redirect).is_err());
        }
    }
}

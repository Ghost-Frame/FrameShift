//! Interactive account registration, login, status, and logout commands.
//!
//! OIDC login uses the system browser and a loopback Authorization Code callback
//! with S256 PKCE. First-party credentials use hidden terminal prompts. No
//! password, invitation, or token is accepted through arguments or environment.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use frameshift_client::account::{
    get_account, get_auth_config, login_local_account, logout_local_account,
    register_local_account, AccountView, LocalAccountSession, NativeAuthClient,
};
use frameshift_client::session::{AuthenticatedSession, SessionClient, SessionClientConfig};
use frameshift_client::session_store::{
    SessionAuthentication, SessionStore, SessionStoreError, SessionStoreMetadata, StoredSession,
};
use frameshift_client::{registry_base_url, Client, ClientError};
use secrecy::{ExposeSecret as _, SecretString};
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
    /// Authenticate through an advertised provider and save the session securely.
    Login(AccountLoginArgs),
    /// Redeem a first-party invitation and save the new session securely.
    Register(AccountRegisterArgs),
    /// Fetch and print the current authenticated account.
    Status,
    /// Revoke the provider session when supported and erase local credentials.
    Logout,
}

/// Account login options.
#[derive(Debug, Args)]
pub struct AccountLoginArgs {
    /// Registry API base URL; defaults to `FRAMESHIFT_REGISTRY_URL` or production.
    #[arg(long)]
    pub server: Option<String>,
    /// Use first-party password login when the registry also advertises OIDC.
    #[arg(long)]
    pub first_party: bool,
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

/// First-party invitation registration options.
#[derive(Debug, Args)]
pub struct AccountRegisterArgs {
    /// Registry API base URL; defaults to `FRAMESHIFT_REGISTRY_URL` or production.
    #[arg(long)]
    pub server: Option<String>,
}

/// Authentication mode selected from explicit intent and registry capabilities.
enum AccountLoginMode {
    /// OIDC system-browser flow through the exact issuer.
    Oidc(Url),
    /// First-party password flow through hidden terminal prompts.
    FirstParty,
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
        AccountCommand::Register(args) => run_register(args),
        AccountCommand::Status => run_status(),
        AccountCommand::Logout => run_logout(),
    }
}

/// Authenticate through the selected provider and persist the resulting session.
fn run_login(args: AccountLoginArgs) -> Result<(), CliError> {
    let server = args.server.clone().unwrap_or_else(registry_base_url);
    validate_server_url(&server)?;
    let registry_url = Url::parse(&server).map_err(|error| CliError::Account(error.to_string()))?;
    match resolve_login_mode(&server, args.first_party, args.issuer.clone())? {
        AccountLoginMode::Oidc(issuer) => run_oidc_login(args, server, registry_url, issuer),
        AccountLoginMode::FirstParty => run_first_party_login(&server, registry_url),
    }
}

/// Complete OIDC system-browser login and persist its refreshable session.
fn run_oidc_login(
    args: AccountLoginArgs,
    server: String,
    registry_url: Url,
    issuer: Url,
) -> Result<(), CliError> {
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
            authentication: SessionAuthentication::Oidc {
                issuer,
                client_id,
                redirect_uri,
                scopes: args.scopes,
            },
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

/// Prompt for first-party credentials and persist one opaque bearer session.
fn run_first_party_login(server: &str, registry_url: Url) -> Result<(), CliError> {
    require_interactive_terminal()?;
    let email = prompt_line("Email: ")?;
    let password = prompt_secret("Password: ", "password")?;
    let authenticated = login_local_account(server, &email, &password, NativeAuthClient::Cli)
        .map_err(|error| CliError::Account(error.to_string()))?;
    persist_first_party_session(registry_url, &authenticated)?;
    let view = get_account(server, authenticated.session.access_token())
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("logged in to {server}");
    print_account(&view);
    Ok(())
}

/// Redeem one invitation through hidden prompts and persist the initial session.
fn run_register(args: AccountRegisterArgs) -> Result<(), CliError> {
    let server = args.server.unwrap_or_else(registry_base_url);
    validate_server_url(&server)?;
    let config = get_auth_config(&server).map_err(|error| CliError::Account(error.to_string()))?;
    if !config.first_party_enabled {
        return Err(CliError::Account(
            "registry does not advertise first-party account registration".to_string(),
        ));
    }
    if config.registration.as_deref() != Some("invite_only") {
        return Err(CliError::Account(
            "registry does not advertise invite-only account registration".to_string(),
        ));
    }
    require_interactive_terminal()?;
    let invite = prompt_secret("Invitation token: ", "invitation token")?;
    let email = prompt_line("Email: ")?;
    let display_name = prompt_line_allow_empty("Display name (optional): ")?;
    let password = prompt_confirmed_password()?;
    let authenticated = register_local_account(
        &server,
        &invite,
        &email,
        (!display_name.is_empty()).then_some(display_name.as_str()),
        &password,
        NativeAuthClient::Cli,
    )
    .map_err(|error| CliError::Account(error.to_string()))?;
    let registry_url = Url::parse(&server).map_err(|error| CliError::Account(error.to_string()))?;
    persist_first_party_session(registry_url, &authenticated)?;
    println!("registered and logged in to {server}");
    Ok(())
}

/// Persist one first-party session and revoke it if local storage fails.
fn persist_first_party_session(
    registry_url: Url,
    authenticated: &LocalAccountSession,
) -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    if let Err(error) = store.save(
        SessionStoreMetadata {
            authentication: SessionAuthentication::FirstParty,
            registry_url: registry_url.clone(),
        },
        &authenticated.session,
    ) {
        let _ = logout_local_account(registry_url.as_str(), authenticated.session.access_token());
        return Err(account_store_error(error));
    }
    Ok(())
}

/// Load, refresh when needed, and print the current registry account.
fn run_status() -> Result<(), CliError> {
    let client = Client::with_default_data_root()?;
    let store = SessionStore::new(client.data_root());
    let mut stored = store.load().map_err(account_store_error)?;
    refresh_loaded_session_if_needed(&store, &mut stored)?;
    let view = match get_account(
        stored.metadata.registry_url.as_str(),
        stored.session.access_token(),
    ) {
        Ok(view) => view,
        Err(ClientError::RegistryRejected { status: 401, .. })
            if stored.session.refresh_token().is_some()
                && matches!(
                    &stored.metadata.authentication,
                    SessionAuthentication::Oidc { .. }
                ) =>
        {
            let session_client = session_client_for(&stored)?;
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
    refresh_loaded_session_if_needed(&store, &mut stored)?;
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
        let revocation = match &stored.metadata.authentication {
            SessionAuthentication::Oidc { .. } => session_client_for(stored).and_then(|client| {
                client
                    .revoke(&stored.session)
                    .map_err(|error| CliError::Account(error.to_string()))
            }),
            SessionAuthentication::FirstParty => logout_local_account(
                stored.metadata.registry_url.as_str(),
                stored.session.access_token(),
            )
            .map_err(|error| CliError::Account(error.to_string())),
        };
        match revocation {
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

/// Resolve first-party or OIDC login from explicit intent and registry capability.
fn resolve_login_mode(
    server: &str,
    first_party: bool,
    issuer_override: Option<String>,
) -> Result<AccountLoginMode, CliError> {
    if first_party && issuer_override.is_some() {
        return Err(CliError::Account(
            "--first-party cannot be combined with --issuer".to_string(),
        ));
    }
    if !first_party {
        if let Some(value) = issuer_override.or_else(|| nonempty_env("FRAMESHIFT_OIDC_ISSUER")) {
            let issuer = Url::parse(&value)
                .map_err(|error| CliError::Account(format!("invalid OIDC issuer: {error}")))?;
            return Ok(AccountLoginMode::Oidc(issuer));
        }
    }
    let config = get_auth_config(server).map_err(|error| CliError::Account(error.to_string()))?;
    if !config.enabled {
        return Err(CliError::Account(
            "registry account authentication is disabled".to_string(),
        ));
    }
    if first_party {
        return config
            .first_party_enabled
            .then_some(AccountLoginMode::FirstParty)
            .ok_or_else(|| {
                CliError::Account("registry does not advertise first-party login".to_string())
            });
    }
    if let Some(value) = config.issuer {
        let issuer = Url::parse(&value)
            .map_err(|error| CliError::Account(format!("invalid OIDC issuer: {error}")))?;
        return Ok(AccountLoginMode::Oidc(issuer));
    }
    if config.first_party_enabled {
        return Ok(AccountLoginMode::FirstParty);
    }
    Err(CliError::Account(
        "registry omitted every enabled authentication provider".to_string(),
    ))
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

/// Require an interactive terminal before reading first-party credentials.
fn require_interactive_terminal() -> Result<(), CliError> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        Ok(())
    } else {
        Err(CliError::Account(
            "first-party credentials require an interactive terminal".to_string(),
        ))
    }
}

/// Read one required visible line without accepting control characters.
fn prompt_line(prompt: &str) -> Result<String, CliError> {
    let value = prompt_line_allow_empty(prompt)?;
    if value.is_empty() {
        return Err(CliError::Account("a required value was empty".to_string()));
    }
    Ok(value)
}

/// Read one optional visible line from the interactive terminal.
fn prompt_line_allow_empty(prompt: &str) -> Result<String, CliError> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.chars().any(char::is_control) {
        return Err(CliError::Account(
            "interactive account values must not contain control characters".to_string(),
        ));
    }
    Ok(value)
}

/// Read one non-empty secret through a hidden terminal prompt.
fn prompt_secret(prompt: &str, label: &str) -> Result<SecretString, CliError> {
    let value = rpassword::prompt_password(prompt)?;
    if value.is_empty() {
        return Err(CliError::Account(format!("{label} cannot be empty")));
    }
    Ok(SecretString::new(value))
}

/// Read and exactly confirm one new password through hidden prompts.
fn prompt_confirmed_password() -> Result<SecretString, CliError> {
    let password = prompt_secret("Password: ", "password")?;
    let confirmation = prompt_secret("Confirm password: ", "password confirmation")?;
    if password.expose_secret() != confirmation.expose_secret() {
        return Err(CliError::Account("passwords did not match".to_string()));
    }
    Ok(password)
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
    let SessionAuthentication::Oidc {
        issuer,
        client_id,
        redirect_uri,
        scopes,
    } = &stored.metadata.authentication
    else {
        return Err(CliError::Account(
            "first-party sessions do not use OIDC discovery".to_string(),
        ));
    };
    SessionClient::discover(SessionClientConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        scopes: scopes.clone(),
    })
    .map_err(|error| CliError::Account(error.to_string()))
}

/// Return whether an access token is expired or within the refresh margin.
fn session_expires_soon(session: &AuthenticatedSession) -> bool {
    session
        .summary()
        .expires_at
        .is_some_and(|expiry| expiry <= unix_now().saturating_add(REFRESH_MARGIN_SECS))
}

/// Refresh one expiring OIDC session while leaving first-party sessions untouched.
fn refresh_loaded_session_if_needed(
    store: &SessionStore,
    stored: &mut StoredSession,
) -> Result<(), CliError> {
    if matches!(
        &stored.metadata.authentication,
        SessionAuthentication::Oidc { .. }
    ) && session_expires_soon(&stored.session)
        && stored.session.refresh_token().is_some()
    {
        let session_client = session_client_for(stored)?;
        stored.session = session_client
            .refresh(&stored.session)
            .map_err(|error| CliError::Account(error.to_string()))?;
        persist_loaded_session(store, stored)?;
    }
    Ok(())
}

/// Rewrite one refreshed session using its existing public metadata.
fn persist_loaded_session(store: &SessionStore, stored: &StoredSession) -> Result<(), CliError> {
    store
        .save(
            SessionStoreMetadata {
                authentication: stored.metadata.authentication.clone(),
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
    use clap::Parser as _;

    /// Minimal parser that exercises the public account command hierarchy.
    #[derive(Debug, clap::Parser)]
    #[command(name = "frameshift")]
    struct TestCli {
        /// Parsed top-level command.
        #[command(subcommand)]
        command: TestCommand,
    }

    /// Top-level command subset needed for account parser tests.
    #[derive(Debug, clap::Subcommand)]
    enum TestCommand {
        /// Account-session command group.
        Account(AccountArgs),
    }

    /// Registration accepts only public connection options, never credential material.
    #[test]
    fn parses_registration_without_secret_arguments() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "register",
            "--server",
            "https://registry.example",
        ])
        .expect("registration arguments");
        let TestCommand::Account(AccountArgs {
            command: AccountCommand::Register(arguments),
        }) = parsed.command
        else {
            panic!("expected account registration");
        };
        assert_eq!(
            arguments.server.as_deref(),
            Some("https://registry.example")
        );

        for secret_flag in ["--password", "--invite-token"] {
            assert!(TestCli::try_parse_from([
                "frameshift",
                "account",
                "register",
                secret_flag,
                "secret",
            ])
            .is_err());
        }
    }

    /// Login exposes an explicit first-party selector without accepting a password argument.
    #[test]
    fn parses_first_party_login_without_password_argument() {
        let parsed = TestCli::try_parse_from(["frameshift", "account", "login", "--first-party"])
            .expect("first-party login arguments");
        let TestCommand::Account(AccountArgs {
            command: AccountCommand::Login(arguments),
        }) = parsed.command
        else {
            panic!("expected account login");
        };
        assert!(arguments.first_party);
        assert!(TestCli::try_parse_from([
            "frameshift",
            "account",
            "login",
            "--password",
            "secret",
        ])
        .is_err());
    }

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

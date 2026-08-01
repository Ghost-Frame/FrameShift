//! Account session and administrator account-control commands.
//!
//! OIDC login uses the system browser and a loopback Authorization Code callback
//! with S256 PKCE. First-party credentials use hidden terminal prompts. Session
//! commands accept no password, invitation, or bearer-token argument.

use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use frameshift_catalog::{AccountInviteStatus, AccountStatus, PlatformRole};
use frameshift_client::account::{
    assign_account_platform_role, create_publisher_profile, get_account, get_auth_config,
    issue_account_invite, list_account_invite_requests, login_local_account, logout_local_account,
    register_local_account, review_account_invite_request, revoke_account_platform_role,
    set_account_status, update_account_profile, update_publisher_profile,
    AccountInviteReviewStatus, AccountView, IssuedAccountInvite, LocalAccountSession,
    NativeAuthClient,
};
use frameshift_client::session::{AuthenticatedSession, SessionClient, SessionClientConfig};
use frameshift_client::session_store::{
    SessionAuthentication, SessionStore, SessionStoreError, SessionStoreMetadata, StoredSession,
};
use frameshift_client::{registry_base_url, Client, ClientError};
use secrecy::{ExposeSecret as _, SecretString};
use url::{Position, Url};
use uuid::Uuid;

use crate::cmd::keys::resolve_access_token;
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
    /// Account session or administrator operation.
    #[command(subcommand)]
    pub command: AccountCommand,
}

/// Account session and administrator operations.
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
    /// Update mutable metadata for the authenticated account.
    #[command(group(ArgGroup::new("account_profile").required(true).args(["email", "display_name"])))]
    UpdateProfile {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Replacement account email metadata.
        #[arg(long)]
        email: Option<String>,
        /// Replacement account display name.
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Create a pending publisher profile owned by the authenticated account.
    CreatePublisher {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Unique lowercase public publisher handle.
        #[arg(long)]
        handle: String,
        /// Public publisher display name.
        #[arg(long)]
        display_name: String,
        /// Optional public publisher biography.
        #[arg(long)]
        biography: Option<String>,
    },
    /// Update a publisher profile under active-owner authority.
    UpdatePublisher {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Existing public publisher handle.
        #[arg(long)]
        handle: String,
        /// Replacement public display name.
        #[arg(long)]
        display_name: String,
        /// Replacement public biography.
        #[arg(long, conflicts_with = "clear_biography")]
        biography: Option<String>,
        /// Remove the existing public biography.
        #[arg(long)]
        clear_biography: bool,
    },
    /// Grant one global platform role under administrator authority.
    GrantRole {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Stable target account UUID.
        #[arg(long)]
        account_id: Uuid,
        /// Global platform role to grant.
        #[arg(long, value_enum)]
        role: PlatformRoleArg,
    },
    /// Revoke one global platform role under administrator authority.
    RevokeRole {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Stable target account UUID.
        #[arg(long)]
        account_id: Uuid,
        /// Global platform role to revoke.
        #[arg(long, value_enum)]
        role: PlatformRoleArg,
    },
    /// Set one account lifecycle state under administrator authority.
    SetStatus {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Stable target account UUID.
        #[arg(long)]
        account_id: Uuid,
        /// Account lifecycle state to apply.
        #[arg(long, value_enum)]
        status: AccountStatusArg,
    },
    /// List administrator-visible account invitation requests.
    InviteRequests {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Optional invitation review state filter.
        #[arg(long, value_enum)]
        status: Option<InviteQueueStatusArg>,
        /// Number of newest requests to return.
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=200))]
        limit: u32,
    },
    /// Transition one invitation request to a non-issued review state.
    ReviewInviteRequest {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Stable invitation-request UUID.
        #[arg(long)]
        request_id: Uuid,
        /// Pending, reviewing, or declined state to apply.
        #[arg(long, value_enum)]
        status: InviteReviewStatusArg,
    },
    /// Issue one invitation and print its raw one-time token once.
    IssueInvite {
        /// Registry API base URL.
        #[arg(long)]
        server: String,
        /// Stable invitation-request UUID.
        #[arg(long)]
        request_id: Uuid,
    },
}

/// CLI spelling for global platform roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PlatformRoleArg {
    /// Authority to review publication submissions.
    Moderator,
    /// Authority to administer platform and publication controls.
    Administrator,
}

/// Convert a CLI platform role into the shared wire enum.
impl From<PlatformRoleArg> for PlatformRole {
    /// Preserve the selected authority exactly.
    fn from(value: PlatformRoleArg) -> Self {
        match value {
            PlatformRoleArg::Moderator => Self::Moderator,
            PlatformRoleArg::Administrator => Self::Administrator,
        }
    }
}

/// CLI spelling for account lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AccountStatusArg {
    /// Allow the account to authenticate and use assigned authority.
    Active,
    /// Temporarily deny account access while retaining history.
    Suspended,
    /// Permanently disable the account while retaining history.
    Disabled,
}

/// Convert a CLI account state into the shared wire enum.
impl From<AccountStatusArg> for AccountStatus {
    /// Preserve the selected lifecycle state exactly.
    fn from(value: AccountStatusArg) -> Self {
        match value {
            AccountStatusArg::Active => Self::Active,
            AccountStatusArg::Suspended => Self::Suspended,
            AccountStatusArg::Disabled => Self::Disabled,
        }
    }
}

/// CLI spelling for administrator invitation queue filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InviteQueueStatusArg {
    /// Applications waiting for initial review.
    Pending,
    /// Applications actively under review.
    Reviewing,
    /// Applications whose one-time invitation was issued.
    Invited,
    /// Applications declined with their audit record retained.
    Declined,
}

/// Convert a CLI queue filter into the shared invitation status.
impl From<InviteQueueStatusArg> for AccountInviteStatus {
    /// Preserve the selected queue state exactly.
    fn from(value: InviteQueueStatusArg) -> Self {
        match value {
            InviteQueueStatusArg::Pending => Self::Pending,
            InviteQueueStatusArg::Reviewing => Self::Reviewing,
            InviteQueueStatusArg::Invited => Self::Invited,
            InviteQueueStatusArg::Declined => Self::Declined,
        }
    }
}

/// CLI spelling for non-issued invitation review transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InviteReviewStatusArg {
    /// Return an application to the initial review queue.
    Pending,
    /// Mark an application as actively under review.
    Reviewing,
    /// Decline an application while retaining its audit record.
    Declined,
}

/// Convert a CLI review transition into the restricted client input.
impl From<InviteReviewStatusArg> for AccountInviteReviewStatus {
    /// Preserve the selected non-issued review state exactly.
    fn from(value: InviteReviewStatusArg) -> Self {
        match value {
            InviteReviewStatusArg::Pending => Self::Pending,
            InviteReviewStatusArg::Reviewing => Self::Reviewing,
            InviteReviewStatusArg::Declined => Self::Declined,
        }
    }
}

/// Borrowed structured output for one newly issued invitation.
#[derive(serde::Serialize)]
struct IssuedAccountInviteOutput<'a> {
    /// Durable non-secret invitation metadata.
    invite: &'a frameshift_catalog::AccountInviteRecord,
    /// Raw invitation token deliberately displayed exactly once.
    token: &'a str,
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

/// Execute one account session or administrator operation.
pub fn run_account(args: AccountArgs) -> Result<(), CliError> {
    match args.command {
        AccountCommand::Login(args) => run_login(args),
        AccountCommand::Register(args) => run_register(args),
        AccountCommand::Status => run_status(),
        AccountCommand::Logout => run_logout(),
        AccountCommand::UpdateProfile {
            server,
            email,
            display_name,
        } => update_profile(&server, email.as_deref(), display_name.as_deref()),
        AccountCommand::CreatePublisher {
            server,
            handle,
            display_name,
            biography,
        } => create_publisher(&server, &handle, &display_name, biography.as_deref()),
        AccountCommand::UpdatePublisher {
            server,
            handle,
            display_name,
            biography,
            clear_biography,
        } => update_publisher(
            &server,
            &handle,
            &display_name,
            biography.as_deref(),
            clear_biography,
        ),
        AccountCommand::GrantRole {
            server,
            account_id,
            role,
        } => grant_role(&server, account_id, role),
        AccountCommand::RevokeRole {
            server,
            account_id,
            role,
        } => revoke_role(&server, account_id, role),
        AccountCommand::SetStatus {
            server,
            account_id,
            status,
        } => set_status(&server, account_id, status),
        AccountCommand::InviteRequests {
            server,
            status,
            limit,
        } => invite_requests(&server, status, limit),
        AccountCommand::ReviewInviteRequest {
            server,
            request_id,
            status,
        } => review_invite_request(&server, request_id, status),
        AccountCommand::IssueInvite { server, request_id } => issue_invite(&server, request_id),
    }
}

/// Update the current account profile through its exact authenticated session.
fn update_profile(
    server: &str,
    email: Option<&str>,
    display_name: Option<&str>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let account = update_account_profile(server, &token, email, display_name)
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&account)?);
    Ok(())
}

/// Create one publisher profile through the current authenticated session.
fn create_publisher(
    server: &str,
    handle: &str,
    display_name: &str,
    biography: Option<&str>,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let publisher = create_publisher_profile(server, &token, handle, display_name, biography)
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&publisher)?);
    Ok(())
}

/// Update one owned publisher profile through the current authenticated session.
fn update_publisher(
    server: &str,
    handle: &str,
    display_name: &str,
    biography: Option<&str>,
    clear_biography: bool,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let publisher = update_publisher_profile(
        server,
        &token,
        handle,
        display_name,
        biography,
        clear_biography,
    )
    .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&publisher)?);
    Ok(())
}

/// Grant one role through the exact authenticated registry session.
fn grant_role(server: &str, account_id: Uuid, role: PlatformRoleArg) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let record = assign_account_platform_role(server, &token, account_id, role.into())
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Revoke one role through the exact authenticated registry session.
fn revoke_role(server: &str, account_id: Uuid, role: PlatformRoleArg) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let record = revoke_account_platform_role(server, &token, account_id, role.into())
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}

/// Transition one account through the exact authenticated registry session.
fn set_status(server: &str, account_id: Uuid, status: AccountStatusArg) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let account = set_account_status(server, &token, account_id, status.into())
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&account)?);
    Ok(())
}

/// Print one bounded administrator invitation queue.
fn invite_requests(
    server: &str,
    status: Option<InviteQueueStatusArg>,
    limit: u32,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let requests = list_account_invite_requests(server, &token, status.map(Into::into), limit)
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&requests)?);
    Ok(())
}

/// Transition one invitation request through administrator review.
fn review_invite_request(
    server: &str,
    request_id: Uuid,
    status: InviteReviewStatusArg,
) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let request = review_account_invite_request(server, &token, request_id, status.into())
        .map_err(|error| CliError::Account(error.to_string()))?;
    println!("{}", serde_json::to_string_pretty(&request)?);
    Ok(())
}

/// Issue one invitation and deliberately write its one-time token to standard output.
fn issue_invite(server: &str, request_id: Uuid) -> Result<(), CliError> {
    validate_server_url(server)?;
    let token = resolve_access_token(server)?;
    let issued = issue_account_invite(server, &token, request_id)
        .map_err(|error| CliError::Account(error.to_string()))?;
    print_issued_invite(&issued)
}

/// Serialize one secret-bearing invitation without creating a debug representation.
fn print_issued_invite(issued: &IssuedAccountInvite) -> Result<(), CliError> {
    let output = IssuedAccountInviteOutput {
        invite: &issued.invite,
        token: issued.token().expose_secret(),
    };
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &output)?;
    writeln!(writer)?;
    Ok(())
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
                redirect_uri: Box::new(redirect_uri),
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
        redirect_uri: redirect_uri.as_ref().clone(),
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

    /// Account profile parsing requires at least one replacement field.
    #[test]
    fn parses_account_profile_update() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "update-profile",
            "--server",
            "https://registry.example",
            "--display-name",
            "Alice Example",
        ])
        .expect("account profile arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::UpdateProfile {
                    server,
                    email,
                    display_name,
                },
        }) = parsed.command
        else {
            panic!("expected account profile update");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(email, None);
        assert_eq!(display_name.as_deref(), Some("Alice Example"));
        assert!(TestCli::try_parse_from([
            "frameshift",
            "account",
            "update-profile",
            "--server",
            "https://registry.example",
        ])
        .is_err());
    }

    /// Publisher creation parsing preserves its public profile fields.
    #[test]
    fn parses_publisher_profile_creation() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "create-publisher",
            "--server",
            "https://registry.example",
            "--handle",
            "gatekeeper",
            "--display-name",
            "Gatekeeper",
            "--biography",
            "Verifies releases.",
        ])
        .expect("publisher creation arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::CreatePublisher {
                    server,
                    handle,
                    display_name,
                    biography,
                },
        }) = parsed.command
        else {
            panic!("expected publisher profile creation");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(handle, "gatekeeper");
        assert_eq!(display_name, "Gatekeeper");
        assert_eq!(biography.as_deref(), Some("Verifies releases."));
    }

    /// Publisher updates expose explicit biography replacement or removal.
    #[test]
    fn parses_publisher_profile_update() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "update-publisher",
            "--server",
            "https://registry.example",
            "--handle",
            "gatekeeper",
            "--display-name",
            "Release Gatekeeper",
            "--clear-biography",
        ])
        .expect("publisher update arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::UpdatePublisher {
                    server,
                    handle,
                    display_name,
                    biography,
                    clear_biography,
                },
        }) = parsed.command
        else {
            panic!("expected publisher profile update");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(handle, "gatekeeper");
        assert_eq!(display_name, "Release Gatekeeper");
        assert_eq!(biography, None);
        assert!(clear_biography);
        assert!(TestCli::try_parse_from([
            "frameshift",
            "account",
            "update-publisher",
            "--server",
            "https://registry.example",
            "--handle",
            "gatekeeper",
            "--display-name",
            "Gatekeeper",
            "--biography",
            "Replacement",
            "--clear-biography",
        ])
        .is_err());
    }

    /// Administrator role grant parsing preserves the exact target and closed role value.
    #[test]
    fn parses_administrator_role_grant() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "grant-role",
            "--server",
            "https://registry.example",
            "--account-id",
            "00000000-0000-0000-0000-000000000001",
            "--role",
            "administrator",
        ])
        .expect("role grant arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::GrantRole {
                    server,
                    account_id,
                    role,
                },
        }) = parsed.command
        else {
            panic!("expected administrator role grant");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(account_id, Uuid::from_u128(1));
        assert_eq!(role, PlatformRoleArg::Administrator);
    }

    /// Administrator role revocation parsing preserves the exact target and role value.
    #[test]
    fn parses_administrator_role_revocation() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "revoke-role",
            "--server",
            "https://registry.example",
            "--account-id",
            "00000000-0000-0000-0000-000000000001",
            "--role",
            "moderator",
        ])
        .expect("role revocation arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::RevokeRole {
                    server,
                    account_id,
                    role,
                },
        }) = parsed.command
        else {
            panic!("expected administrator role revocation");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(account_id, Uuid::from_u128(1));
        assert_eq!(role, PlatformRoleArg::Moderator);
    }

    /// Administrator status parsing accepts the closed suspended state.
    #[test]
    fn parses_administrator_account_status_transition() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "set-status",
            "--server",
            "https://registry.example",
            "--account-id",
            "00000000-0000-0000-0000-000000000001",
            "--status",
            "suspended",
        ])
        .expect("account status arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::SetStatus {
                    server,
                    account_id,
                    status,
                },
        }) = parsed.command
        else {
            panic!("expected administrator account status transition");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(account_id, Uuid::from_u128(1));
        assert_eq!(status, AccountStatusArg::Suspended);
    }

    /// Administrator role commands reject publisher roles outside the closed platform set.
    #[test]
    fn administrator_role_commands_reject_publisher_roles() {
        let result = TestCli::try_parse_from([
            "frameshift",
            "account",
            "revoke-role",
            "--server",
            "https://registry.example",
            "--account-id",
            "00000000-0000-0000-0000-000000000001",
            "--role",
            "owner",
        ]);
        assert!(result.is_err());
    }

    /// Every CLI platform-role value maps to its exact shared wire value.
    #[test]
    fn maps_all_administrator_platform_roles() {
        assert_eq!(
            PlatformRole::from(PlatformRoleArg::Moderator),
            PlatformRole::Moderator
        );
        assert_eq!(
            PlatformRole::from(PlatformRoleArg::Administrator),
            PlatformRole::Administrator
        );
    }

    /// Every CLI account-status value maps to its exact shared wire value.
    #[test]
    fn maps_all_administrator_account_statuses() {
        assert_eq!(
            AccountStatus::from(AccountStatusArg::Active),
            AccountStatus::Active
        );
        assert_eq!(
            AccountStatus::from(AccountStatusArg::Suspended),
            AccountStatus::Suspended
        );
        assert_eq!(
            AccountStatus::from(AccountStatusArg::Disabled),
            AccountStatus::Disabled
        );
    }

    /// Administrator invite queue parsing preserves the exact filter and bounded limit.
    #[test]
    fn parses_administrator_invite_queue() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "invite-requests",
            "--server",
            "https://registry.example",
            "--status",
            "invited",
            "--limit",
            "200",
        ])
        .expect("invite queue arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::InviteRequests {
                    server,
                    status,
                    limit,
                },
        }) = parsed.command
        else {
            panic!("expected administrator invite queue");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(status, Some(InviteQueueStatusArg::Invited));
        assert_eq!(limit, 200);
        assert!(TestCli::try_parse_from([
            "frameshift",
            "account",
            "invite-requests",
            "--server",
            "https://registry.example",
            "--limit",
            "201",
        ])
        .is_err());
    }

    /// Administrator invite review parsing excludes the issuance-only invited state.
    #[test]
    fn parses_administrator_invite_review() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "review-invite-request",
            "--server",
            "https://registry.example",
            "--request-id",
            "00000000-0000-0000-0000-000000000003",
            "--status",
            "declined",
        ])
        .expect("invite review arguments");
        let TestCommand::Account(AccountArgs {
            command:
                AccountCommand::ReviewInviteRequest {
                    server,
                    request_id,
                    status,
                },
        }) = parsed.command
        else {
            panic!("expected administrator invite review");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(request_id, Uuid::from_u128(3));
        assert_eq!(status, InviteReviewStatusArg::Declined);
        assert!(TestCli::try_parse_from([
            "frameshift",
            "account",
            "review-invite-request",
            "--server",
            "https://registry.example",
            "--request-id",
            "00000000-0000-0000-0000-000000000003",
            "--status",
            "invited",
        ])
        .is_err());
    }

    /// Administrator invitation issuance parsing preserves the exact application target.
    #[test]
    fn parses_administrator_invite_issuance() {
        let parsed = TestCli::try_parse_from([
            "frameshift",
            "account",
            "issue-invite",
            "--server",
            "https://registry.example",
            "--request-id",
            "00000000-0000-0000-0000-000000000003",
        ])
        .expect("invite issuance arguments");
        let TestCommand::Account(AccountArgs {
            command: AccountCommand::IssueInvite { server, request_id },
        }) = parsed.command
        else {
            panic!("expected administrator invite issuance");
        };
        assert_eq!(server, "https://registry.example");
        assert_eq!(request_id, Uuid::from_u128(3));
    }

    /// Every CLI invitation queue filter maps to its exact shared wire value.
    #[test]
    fn maps_all_administrator_invite_queue_statuses() {
        assert_eq!(
            AccountInviteStatus::from(InviteQueueStatusArg::Pending),
            AccountInviteStatus::Pending
        );
        assert_eq!(
            AccountInviteStatus::from(InviteQueueStatusArg::Reviewing),
            AccountInviteStatus::Reviewing
        );
        assert_eq!(
            AccountInviteStatus::from(InviteQueueStatusArg::Invited),
            AccountInviteStatus::Invited
        );
        assert_eq!(
            AccountInviteStatus::from(InviteQueueStatusArg::Declined),
            AccountInviteStatus::Declined
        );
    }

    /// Every CLI invitation review state maps to its restricted client input.
    #[test]
    fn maps_all_administrator_invite_review_statuses() {
        assert_eq!(
            AccountInviteReviewStatus::from(InviteReviewStatusArg::Pending),
            AccountInviteReviewStatus::Pending
        );
        assert_eq!(
            AccountInviteReviewStatus::from(InviteReviewStatusArg::Reviewing),
            AccountInviteReviewStatus::Reviewing
        );
        assert_eq!(
            AccountInviteReviewStatus::from(InviteReviewStatusArg::Declined),
            AccountInviteReviewStatus::Declined
        );
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

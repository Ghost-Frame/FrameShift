//! PostgreSQL persistence for account-scoped remote persona state.
//!
//! Every public operation is scoped by the authenticated account identifier
//! carried by the catalog contract. Mutations serialize on one account state
//! row, keep idempotency evidence append-only, and never log private growth
//! text or receipt payloads.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use diesel::sql_types::{
    BigInt, Binary, Bool, Integer, Jsonb, Nullable, SmallInt, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel::{OptionalExtension as _, QueryableByName};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use frameshift_catalog::{
    exact_reference_set_hash, validate_growth_policy_candidate, AccountPersonaStateBackend,
    AccountPersonaStateSnapshot, ActivePersonaRecord, AppendGrowthRequest, ExactPersonaVersion,
    GrowthCursor, InstallPersonaRequest, InstallationCursor, MutatePreferenceRequest,
    MutationContext, MutationOutcome, MutationReceipt, ObjectHash, OperationCursor, PageLimit,
    PersonaGrowthListItem, PersonaGrowthRecord, PersonaInstallationListItem,
    PersonaInstallationRecord, PersonaName, PersonaOperationRecord, PersonaPreferenceRecord,
    PersonaStateError, PreferenceCursor, PreferenceMutation, RenderPersonaStateSnapshot,
    SetActivePersonaRequest, StatePage, FRAMESHIFT_GROW_APPEND_TOOL_NAME,
    FRAMESHIFT_INSTALL_TOOL_NAME, FRAMESHIFT_PREFS_TOOL_NAME, FRAMESHIFT_USE_TOOL_NAME,
    MAX_GROWTH_ENTRIES_PER_ACCOUNT_PACK, MAX_INSTALLATIONS_PER_ACCOUNT, MAX_OPERATIONS_PER_ACCOUNT,
    MAX_PREFERENCES_PER_ACCOUNT, MAX_PREFERENCE_BIAS_MILLIS, MAX_RENDER_GROWTH_BYTES,
    MAX_RENDER_GROWTH_ENTRIES, MIN_PREFERENCE_BIAS_MILLIS, PERSONA_STATE_REQUEST_SCHEMA_VERSION,
    PREFERENCE_BUMP_MILLIS, PREFERENCE_DECAY_MILLIS,
};
use uuid::Uuid;

use crate::PostgresCatalog;

/// One account status loaded under a database row lock.
#[derive(Debug, QueryableByName)]
struct AccountStatusRow {
    /// Exact lifecycle state stored by the account substrate.
    #[diesel(sql_type = Text)]
    status: String,
}

/// One account revision loaded from the serialization row.
#[derive(Debug, QueryableByName)]
struct RevisionRow {
    /// Latest fresh mutation sequence.
    #[diesel(sql_type = BigInt)]
    revision: i64,
}

/// One aggregate count returned by a bounded quota query.
#[derive(Debug, QueryableByName)]
struct CountRow {
    /// Number of matching account-scoped rows.
    #[diesel(sql_type = BigInt)]
    count: i64,
}

/// One exact account installation loaded from PostgreSQL.
#[derive(Debug, QueryableByName)]
struct InstallationRow {
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact immutable public version.
    #[diesel(sql_type = Text)]
    version: String,
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// First installation timestamp.
    #[diesel(sql_type = Timestamptz)]
    installed_at: DateTime<Utc>,
}

/// Installation row plus list-only availability projections.
#[derive(Debug, QueryableByName)]
struct InstallationListRow {
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact immutable public version.
    #[diesel(sql_type = Text)]
    version: String,
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// First installation timestamp.
    #[diesel(sql_type = Timestamptz)]
    installed_at: DateTime<Utc>,
    /// Whether the exact catalog version remains active.
    #[diesel(sql_type = Bool)]
    available: bool,
    /// Whether this exact installation is currently selected.
    #[diesel(sql_type = Bool)]
    active: bool,
    /// Number of account growth rows retained for the pack name.
    #[diesel(sql_type = BigInt)]
    growth_count: i64,
}

/// One account-level active selection loaded from PostgreSQL.
#[derive(Debug, QueryableByName)]
struct ActivePersonaRow {
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact immutable public version.
    #[diesel(sql_type = Text)]
    version: String,
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// Latest selection timestamp.
    #[diesel(sql_type = Timestamptz)]
    selected_at: DateTime<Utc>,
}

/// One account preference loaded from PostgreSQL.
#[derive(Debug, QueryableByName)]
struct PreferenceRow {
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact integer bias in milli-units.
    #[diesel(sql_type = SmallInt)]
    bias_millis: i16,
    /// Number of mutations incorporated into this row.
    #[diesel(sql_type = BigInt)]
    mutation_count: i64,
    /// Latest mutation timestamp.
    #[diesel(sql_type = Timestamptz)]
    updated_at: DateTime<Utc>,
}

/// One private growth row loaded from PostgreSQL.
#[derive(QueryableByName)]
struct GrowthRow {
    /// Account-scoped growth identifier.
    #[diesel(sql_type = SqlUuid)]
    entry_id: Uuid,
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact immutable public version.
    #[diesel(sql_type = Text)]
    version: String,
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// Positive account mutation sequence.
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    /// Exact private growth text.
    #[diesel(sql_type = Text)]
    text: String,
    /// SHA-256 hash of the exact growth text.
    #[diesel(sql_type = Binary)]
    text_hash: Vec<u8>,
    /// Commit timestamp.
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    /// Creating idempotency operation.
    #[diesel(sql_type = SqlUuid)]
    operation_id: Uuid,
}

/// Metadata-only growth row used by list operations.
#[derive(Debug, QueryableByName)]
struct GrowthListRow {
    /// Account-scoped growth identifier.
    #[diesel(sql_type = SqlUuid)]
    entry_id: Uuid,
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Canonical public pack name.
    #[diesel(sql_type = Text)]
    pack_name: String,
    /// Exact immutable public version.
    #[diesel(sql_type = Text)]
    version: String,
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// Positive account mutation sequence.
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    /// SHA-256 hash of the private growth text.
    #[diesel(sql_type = Binary)]
    text_hash: Vec<u8>,
    /// Commit timestamp.
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
    /// Creating idempotency operation.
    #[diesel(sql_type = SqlUuid)]
    operation_id: Uuid,
}

/// One immutable idempotency operation loaded from PostgreSQL.
#[derive(Debug, QueryableByName)]
struct OperationRow {
    /// Owning account identifier.
    #[diesel(sql_type = SqlUuid)]
    account_id: Uuid,
    /// Account-scoped operation identifier.
    #[diesel(sql_type = SqlUuid)]
    operation_id: Uuid,
    /// Positive sequence equal to the committed revision.
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    /// Exact remote mutation tool name.
    #[diesel(sql_type = Text)]
    tool_name: String,
    /// Canonical request-hashing schema version.
    #[diesel(sql_type = Integer)]
    request_schema_version: i32,
    /// SHA-256 canonical request hash bytes.
    #[diesel(sql_type = Binary)]
    request_hash: Vec<u8>,
    /// Bounded typed receipt JSON.
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
    /// Commit timestamp.
    #[diesel(sql_type = Timestamptz)]
    created_at: DateTime<Utc>,
}

/// Exact active catalog row locked before attaching or using a version.
#[derive(Debug, QueryableByName)]
struct CatalogVersionRow {
    /// Exact SHA-256 archive hash bytes.
    #[diesel(sql_type = Binary)]
    content_hash: Vec<u8>,
    /// Publication lifecycle kind extracted from JSON status.
    #[diesel(sql_type = Nullable<Text>)]
    status_kind: Option<String>,
}

/// Existing preference values locked before an exact mutation.
#[derive(Debug, QueryableByName)]
struct PreferenceValueRow {
    /// Current integer bias in milli-units.
    #[diesel(sql_type = SmallInt)]
    bias_millis: i16,
    /// Current bounded mutation count.
    #[diesel(sql_type = BigInt)]
    mutation_count: i64,
}

/// Transaction error that preserves static domain failures across rollback.
#[derive(Debug)]
enum PersonaTransactionError {
    /// Stable public state-contract failure.
    Domain(PersonaStateError),
    /// Raw database failure collapsed without retaining sensitive details.
    Diesel,
}

/// Diesel conversion required by the asynchronous transaction API.
impl From<diesel::result::Error> for PersonaTransactionError {
    /// Discard one raw Diesel error while preserving transaction rollback.
    fn from(_error: diesel::result::Error) -> Self {
        Self::Diesel
    }
}

/// Mutation preflight result after locking one account serialization row.
enum MutationStart {
    /// Exact prior operation replay with no fresh revision allocation.
    Replay(Box<MutationOutcome>),
    /// Fresh mutation allocation bound to the prior and next revisions.
    Fresh {
        /// Revision locked before the domain mutation.
        previous_revision: u64,
        /// Positive sequence allocated to this fresh operation.
        sequence: u64,
    },
}

/// Database row-lock strength used for one account lifecycle check.
#[derive(Debug, Clone, Copy)]
enum AccountLock {
    /// Read the account lifecycle without retaining a row lock.
    None,
    /// Retain a shared account row lock through the current transaction.
    Share,
    /// Retain an exclusive account row lock through the current transaction.
    Update,
}

/// Convert any pool failure into the static backend error class.
fn pool_error() -> PersonaStateError {
    PersonaStateError::Backend
}

/// Convert a transaction result into the stable catalog error surface.
fn map_transaction_result<T>(
    result: Result<T, PersonaTransactionError>,
) -> Result<T, PersonaStateError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(public_transaction_error(error)),
    }
}

/// Collapse one transaction failure into the static public error surface.
fn public_transaction_error(error: PersonaTransactionError) -> PersonaStateError {
    match error {
        PersonaTransactionError::Domain(error) => error,
        PersonaTransactionError::Diesel => PersonaStateError::Backend,
    }
}

/// Construct a transaction-scoped stable domain failure.
fn domain_error(error: PersonaStateError) -> PersonaTransactionError {
    PersonaTransactionError::Domain(error)
}

/// Convert exact 32-byte database storage into an object hash.
fn object_hash(bytes: Vec<u8>) -> Result<ObjectHash, PersonaStateError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| PersonaStateError::Backend)?;
    Ok(ObjectHash::from_bytes(bytes))
}

/// Convert a non-negative database integer into the domain revision type.
fn unsigned(value: i64) -> Result<u64, PersonaStateError> {
    u64::try_from(value).map_err(|_| PersonaStateError::Backend)
}

/// Convert a bounded database count into the domain counter type.
fn count_u32(value: i64) -> Result<u32, PersonaStateError> {
    u32::try_from(value).map_err(|_| PersonaStateError::Backend)
}

/// Construct one validated exact persona identity from database columns.
fn exact_persona(
    pack_name: String,
    version: String,
    content_hash: Vec<u8>,
) -> Result<ExactPersonaVersion, PersonaStateError> {
    ExactPersonaVersion::new(pack_name, version, object_hash(content_hash)?)
        .map_err(|_| PersonaStateError::Backend)
}

/// Convert one installation row into the public record.
fn installation_record(
    row: InstallationRow,
) -> Result<PersonaInstallationRecord, PersonaStateError> {
    Ok(PersonaInstallationRecord {
        account_id: row.account_id,
        persona: exact_persona(row.pack_name, row.version, row.content_hash)?,
        installed_at: row.installed_at,
    })
}

/// Convert one installation list row into its public projection.
fn installation_list_item(
    row: InstallationListRow,
) -> Result<PersonaInstallationListItem, PersonaStateError> {
    Ok(PersonaInstallationListItem {
        installation: PersonaInstallationRecord {
            account_id: row.account_id,
            persona: exact_persona(row.pack_name, row.version, row.content_hash)?,
            installed_at: row.installed_at,
        },
        available: row.available,
        active: row.active,
        growth_count: count_u32(row.growth_count)?,
    })
}

/// Convert one active selection row into the public record.
fn active_record(row: ActivePersonaRow) -> Result<ActivePersonaRecord, PersonaStateError> {
    Ok(ActivePersonaRecord {
        account_id: row.account_id,
        persona: exact_persona(row.pack_name, row.version, row.content_hash)?,
        selected_at: row.selected_at,
    })
}

/// Convert one preference row into the public record.
fn preference_record(row: PreferenceRow) -> Result<PersonaPreferenceRecord, PersonaStateError> {
    PersonaName::new(row.pack_name.clone()).map_err(|_| PersonaStateError::Backend)?;
    let mutation_count = count_u32(row.mutation_count)?;
    if !(MIN_PREFERENCE_BIAS_MILLIS..=MAX_PREFERENCE_BIAS_MILLIS).contains(&row.bias_millis)
        || mutation_count == 0
    {
        return Err(PersonaStateError::Backend);
    }
    Ok(PersonaPreferenceRecord {
        account_id: row.account_id,
        pack_name: row.pack_name,
        bias_millis: row.bias_millis,
        mutation_count,
        updated_at: row.updated_at,
    })
}

/// Convert one private growth row into the render-only record.
fn growth_record(row: GrowthRow) -> Result<PersonaGrowthRecord, PersonaStateError> {
    let sequence = unsigned(row.sequence)?;
    if row.entry_id.is_nil() || row.operation_id.is_nil() || sequence == 0 {
        return Err(PersonaStateError::Backend);
    }
    frameshift_catalog::validate_growth_text(&row.text).map_err(|_| PersonaStateError::Backend)?;
    let text_hash = object_hash(row.text_hash)?;
    if ObjectHash::of(row.text.as_bytes()) != text_hash {
        return Err(PersonaStateError::Backend);
    }
    Ok(PersonaGrowthRecord {
        entry_id: row.entry_id,
        account_id: row.account_id,
        persona: exact_persona(row.pack_name, row.version, row.content_hash)?,
        sequence,
        text: row.text,
        text_hash,
        created_at: row.created_at,
        operation_id: row.operation_id,
    })
}

/// Convert one metadata-only growth row into the safe list projection.
fn growth_list_item(row: GrowthListRow) -> Result<PersonaGrowthListItem, PersonaStateError> {
    let sequence = unsigned(row.sequence)?;
    if row.entry_id.is_nil() || row.operation_id.is_nil() || sequence == 0 {
        return Err(PersonaStateError::Backend);
    }
    Ok(PersonaGrowthListItem {
        entry_id: row.entry_id,
        account_id: row.account_id,
        persona: exact_persona(row.pack_name, row.version, row.content_hash)?,
        sequence,
        text_hash: object_hash(row.text_hash)?,
        created_at: row.created_at,
        operation_id: row.operation_id,
    })
}

/// Return the exact tool name corresponding to one closed receipt variant.
fn receipt_tool(receipt: &MutationReceipt) -> &'static str {
    match receipt {
        MutationReceipt::Install { .. } => FRAMESHIFT_INSTALL_TOOL_NAME,
        MutationReceipt::SetActive { .. } => FRAMESHIFT_USE_TOOL_NAME,
        MutationReceipt::AppendGrowth { .. } => FRAMESHIFT_GROW_APPEND_TOOL_NAME,
        MutationReceipt::MutatePreference { .. } => FRAMESHIFT_PREFS_TOOL_NAME,
    }
}

/// Convert one operation row into validated immutable evidence.
fn operation_record(row: OperationRow) -> Result<PersonaOperationRecord, PersonaStateError> {
    let sequence = unsigned(row.sequence)?;
    let request_schema_version =
        u16::try_from(row.request_schema_version).map_err(|_| PersonaStateError::Backend)?;
    let receipt: MutationReceipt =
        serde_json::from_value(row.receipt).map_err(|_| PersonaStateError::Backend)?;
    if row.account_id.is_nil()
        || row.operation_id.is_nil()
        || sequence == 0
        || request_schema_version != PERSONA_STATE_REQUEST_SCHEMA_VERSION
        || row.tool_name != receipt_tool(&receipt)
    {
        return Err(PersonaStateError::Backend);
    }
    Ok(PersonaOperationRecord {
        account_id: row.account_id,
        operation_id: row.operation_id,
        sequence,
        tool_name: row.tool_name,
        request_schema_version,
        request_hash: object_hash(row.request_hash)?,
        receipt,
        created_at: row.created_at,
    })
}

/// Require one account to exist and remain active, optionally locking it.
async fn require_active_account(
    connection: &mut AsyncPgConnection,
    account_id: Uuid,
    lock: AccountLock,
) -> Result<(), PersonaTransactionError> {
    let query = match lock {
        AccountLock::None => diesel::sql_query("SELECT status FROM accounts WHERE id = $1"),
        AccountLock::Share => {
            diesel::sql_query("SELECT status FROM accounts WHERE id = $1 FOR SHARE")
        }
        AccountLock::Update => {
            diesel::sql_query("SELECT status FROM accounts WHERE id = $1 FOR UPDATE")
        }
    };
    let row = query
        .bind::<SqlUuid, _>(account_id)
        .get_result::<AccountStatusRow>(connection)
        .await
        .optional()?;
    match row {
        Some(row) if row.status == "active" => Ok(()),
        _ => Err(domain_error(PersonaStateError::Unavailable)),
    }
}

/// Load one operation by its tenant-composite primary key.
async fn load_operation(
    connection: &mut AsyncPgConnection,
    account_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<PersonaOperationRecord>, PersonaTransactionError> {
    let row = diesel::sql_query(
        "SELECT account_id, operation_id, sequence, tool_name, \
         request_schema_version, request_hash, receipt, created_at \
         FROM account_persona_operations \
         WHERE account_id = $1 AND operation_id = $2",
    )
    .bind::<SqlUuid, _>(account_id)
    .bind::<SqlUuid, _>(operation_id)
    .get_result::<OperationRow>(connection)
    .await
    .optional()?;
    row.map(operation_record).transpose().map_err(domain_error)
}

/// Lock one account and resolve exact replay or allocate a fresh sequence.
async fn begin_mutation(
    connection: &mut AsyncPgConnection,
    context: &MutationContext,
) -> Result<MutationStart, PersonaTransactionError> {
    require_active_account(connection, context.account_id(), AccountLock::Update).await?;
    diesel::sql_query(
        "INSERT INTO account_persona_state (account_id) VALUES ($1) \
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind::<SqlUuid, _>(context.account_id())
    .execute(connection)
    .await?;
    let revision_row = diesel::sql_query(
        "SELECT revision FROM account_persona_state \
         WHERE account_id = $1 FOR UPDATE",
    )
    .bind::<SqlUuid, _>(context.account_id())
    .get_result::<RevisionRow>(connection)
    .await?;
    let revision = unsigned(revision_row.revision).map_err(domain_error)?;

    if let Some(operation) =
        load_operation(connection, context.account_id(), context.operation_id()).await?
    {
        if operation.tool_name == context.tool_name()
            && operation.request_schema_version == context.request_schema_version()
            && operation.request_hash == context.request_hash()
        {
            return Ok(MutationStart::Replay(Box::new(MutationOutcome {
                operation,
                replayed: true,
            })));
        }
        return Err(domain_error(PersonaStateError::OperationConflict));
    }

    if context
        .expected_revision()
        .is_some_and(|expected| expected != revision)
    {
        return Err(domain_error(PersonaStateError::RevisionConflict));
    }
    let operation_count = diesel::sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM account_persona_operations \
         WHERE account_id = $1",
    )
    .bind::<SqlUuid, _>(context.account_id())
    .get_result::<CountRow>(connection)
    .await?;
    if count_u32(operation_count.count).map_err(domain_error)? >= MAX_OPERATIONS_PER_ACCOUNT {
        return Err(domain_error(PersonaStateError::Quota));
    }
    let sequence = revision
        .checked_add(1)
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or_else(|| domain_error(PersonaStateError::Quota))?;
    Ok(MutationStart::Fresh {
        previous_revision: revision,
        sequence,
    })
}

/// Commit one fresh revision and its bounded immutable operation receipt.
async fn finish_mutation(
    connection: &mut AsyncPgConnection,
    context: &MutationContext,
    previous_revision: u64,
    sequence: u64,
    receipt: MutationReceipt,
) -> Result<MutationOutcome, PersonaTransactionError> {
    receipt.validate().map_err(domain_error)?;
    if receipt_tool(&receipt) != context.tool_name() {
        return Err(domain_error(PersonaStateError::Invalid));
    }
    let receipt_value =
        serde_json::to_value(&receipt).map_err(|_| domain_error(PersonaStateError::Backend))?;
    let previous_revision =
        i64::try_from(previous_revision).map_err(|_| domain_error(PersonaStateError::Backend))?;
    let sequence_i64 =
        i64::try_from(sequence).map_err(|_| domain_error(PersonaStateError::Backend))?;
    let updated = diesel::sql_query(
        "UPDATE account_persona_state SET revision = $1, updated_at = NOW() \
         WHERE account_id = $2 AND revision = $3",
    )
    .bind::<BigInt, _>(sequence_i64)
    .bind::<SqlUuid, _>(context.account_id())
    .bind::<BigInt, _>(previous_revision)
    .execute(connection)
    .await?;
    if updated != 1 {
        return Err(domain_error(PersonaStateError::Backend));
    }
    let row = diesel::sql_query(
        "INSERT INTO account_persona_operations (\
             account_id, operation_id, sequence, tool_name, \
             request_schema_version, request_hash, receipt\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING account_id, operation_id, sequence, tool_name, \
                   request_schema_version, request_hash, receipt, created_at",
    )
    .bind::<SqlUuid, _>(context.account_id())
    .bind::<SqlUuid, _>(context.operation_id())
    .bind::<BigInt, _>(sequence_i64)
    .bind::<Text, _>(context.tool_name())
    .bind::<Integer, _>(i32::from(context.request_schema_version()))
    .bind::<Binary, _>(context.request_hash().as_bytes().to_vec())
    .bind::<Jsonb, _>(receipt_value)
    .get_result::<OperationRow>(connection)
    .await?;
    let operation = operation_record(row).map_err(domain_error)?;
    Ok(MutationOutcome {
        operation,
        replayed: false,
    })
}

/// Require one exact catalog version to remain active under a row lock.
async fn require_active_catalog_version(
    connection: &mut AsyncPgConnection,
    persona: &ExactPersonaVersion,
) -> Result<(), PersonaTransactionError> {
    let row = diesel::sql_query(
        "SELECT content_hash, status ->> 'kind' AS status_kind \
         FROM pack_versions WHERE pack_name = $1 AND version = $2 \
         FOR SHARE",
    )
    .bind::<Text, _>(persona.pack_name())
    .bind::<Text, _>(persona.version())
    .get_result::<CatalogVersionRow>(connection)
    .await
    .optional()?;
    let Some(row) = row else {
        return Err(domain_error(PersonaStateError::Unavailable));
    };
    let hash = object_hash(row.content_hash).map_err(domain_error)?;
    if row.status_kind.as_deref() != Some("active") || hash != persona.content_hash() {
        return Err(domain_error(PersonaStateError::Unavailable));
    }
    Ok(())
}

/// Require one exact installation and catalog version to remain available.
async fn require_available_installation(
    connection: &mut AsyncPgConnection,
    account_id: Uuid,
    persona: &ExactPersonaVersion,
) -> Result<(), PersonaTransactionError> {
    let row = diesel::sql_query(
        "SELECT i.account_id, i.pack_name, i.version, i.content_hash, i.installed_at \
         FROM account_persona_installations i \
         JOIN pack_versions pv \
           ON pv.pack_name = i.pack_name \
          AND pv.version = i.version \
          AND pv.content_hash = i.content_hash \
         WHERE i.account_id = $1 AND i.pack_name = $2 AND i.version = $3 \
           AND i.content_hash = $4 AND pv.status ->> 'kind' = 'active' \
         FOR SHARE OF i, pv",
    )
    .bind::<SqlUuid, _>(account_id)
    .bind::<Text, _>(persona.pack_name())
    .bind::<Text, _>(persona.version())
    .bind::<Binary, _>(persona.content_hash().as_bytes().to_vec())
    .get_result::<InstallationRow>(connection)
    .await
    .optional()?;
    if row.is_none() {
        return Err(domain_error(PersonaStateError::Unavailable));
    }
    Ok(())
}

/// Return whether two exact persona identities are byte-for-byte equal.
fn same_persona(left: &ExactPersonaVersion, right: &ExactPersonaVersion) -> bool {
    left.pack_name() == right.pack_name()
        && left.version() == right.version()
        && left.content_hash() == right.content_hash()
}

/// Compare exact persona identities in one stable bytewise lock order.
fn exact_persona_order(
    left: &ExactPersonaVersion,
    right: &ExactPersonaVersion,
) -> std::cmp::Ordering {
    left.pack_name()
        .cmp(right.pack_name())
        .then_with(|| left.version().cmp(right.version()))
        .then_with(|| {
            left.content_hash()
                .as_bytes()
                .cmp(right.content_hash().as_bytes())
        })
}

/// Ensure an installation replay receipt remains bound to the requested identity.
fn validate_install_replay(
    outcome: MutationOutcome,
    persona: &ExactPersonaVersion,
) -> Result<MutationOutcome, PersonaTransactionError> {
    match &outcome.operation.receipt {
        MutationReceipt::Install {
            persona: installed, ..
        } if same_persona(installed, persona) => Ok(outcome),
        _ => Err(domain_error(PersonaStateError::OperationConflict)),
    }
}

/// Ensure an active-selection replay remains bound to the requested root.
fn validate_set_active_replay(
    outcome: MutationOutcome,
    root: &ExactPersonaVersion,
    reference_set_hash: ObjectHash,
) -> Result<MutationOutcome, PersonaTransactionError> {
    match &outcome.operation.receipt {
        MutationReceipt::SetActive {
            persona,
            reference_set_hash: stored_hash,
            ..
        } if same_persona(persona, root) && *stored_hash == reference_set_hash => Ok(outcome),
        _ => Err(domain_error(PersonaStateError::OperationConflict)),
    }
}

/// Ensure a growth replay remains bound to its exact identity and private-text hash.
fn validate_growth_replay(
    outcome: MutationOutcome,
    persona: &ExactPersonaVersion,
    entry_id: Uuid,
    text_hash: ObjectHash,
) -> Result<MutationOutcome, PersonaTransactionError> {
    match &outcome.operation.receipt {
        MutationReceipt::AppendGrowth {
            entry_id: stored_entry,
            persona: stored_persona,
            text_hash: stored_hash,
            ..
        } if *stored_entry == entry_id
            && same_persona(stored_persona, persona)
            && *stored_hash == text_hash =>
        {
            Ok(outcome)
        }
        _ => Err(domain_error(PersonaStateError::OperationConflict)),
    }
}

/// Ensure a preference replay remains bound to its exact mutation and target.
fn validate_preference_replay(
    outcome: MutationOutcome,
    mutation: PreferenceMutation,
    pack_name: Option<&str>,
) -> Result<MutationOutcome, PersonaTransactionError> {
    match &outcome.operation.receipt {
        MutationReceipt::MutatePreference {
            mutation: stored_mutation,
            pack_name: stored_name,
            ..
        } if *stored_mutation == mutation && stored_name.as_deref() == pack_name => Ok(outcome),
        _ => Err(domain_error(PersonaStateError::OperationConflict)),
    }
}

/// Construct the next cursor after trimming one lookahead row.
fn trim_page<T, C>(
    mut items: Vec<T>,
    limit: PageLimit,
    cursor: impl FnOnce(&T) -> Result<C, PersonaStateError>,
) -> Result<StatePage<T, C>, PersonaStateError> {
    let has_more = items.len() > limit.get() as usize;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        items.last().map(cursor).transpose()?
    } else {
        None
    };
    Ok(StatePage { items, next_cursor })
}

/// PostgreSQL implementation of the account-scoped persona-state contract.
#[async_trait]
impl AccountPersonaStateBackend for PostgresCatalog {
    /// Read one active account revision without creating a state row.
    async fn get_snapshot(
        &self,
        account_id: Uuid,
    ) -> Result<AccountPersonaStateSnapshot, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let row = diesel::sql_query(
            "SELECT COALESCE(s.revision, 0)::BIGINT AS revision \
             FROM accounts a \
             LEFT JOIN account_persona_state s ON s.account_id = a.id \
             WHERE a.id = $1 AND a.status = 'active'",
        )
        .bind::<SqlUuid, _>(account_id)
        .get_result::<RevisionRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| PersonaStateError::Backend)?
        .ok_or(PersonaStateError::Unavailable)?;
        Ok(AccountPersonaStateSnapshot {
            account_id,
            revision: unsigned(row.revision)?,
        })
    }

    /// List tenant-scoped installations in stable keyset order.
    async fn list_installations(
        &self,
        account_id: Uuid,
        cursor: Option<InstallationCursor>,
        limit: PageLimit,
    ) -> Result<StatePage<PersonaInstallationListItem, InstallationCursor>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let cursor_at = cursor.as_ref().map(|value| value.installed_at().to_owned());
        let cursor_name = cursor.as_ref().map(|value| value.pack_name().to_string());
        let cursor_version = cursor.as_ref().map(|value| value.version().to_string());
        let rows = diesel::sql_query(
            "SELECT i.account_id, i.pack_name, i.version, i.content_hash, i.installed_at, \
                    EXISTS (\
                        SELECT 1 FROM pack_versions pv \
                        WHERE pv.pack_name = i.pack_name \
                          AND pv.version = i.version \
                          AND pv.content_hash = i.content_hash \
                          AND pv.status ->> 'kind' = 'active'\
                    ) AS available, \
                    EXISTS (\
                        SELECT 1 FROM account_active_personas ap \
                        WHERE ap.account_id = i.account_id \
                          AND ap.pack_name = i.pack_name \
                          AND ap.version = i.version \
                          AND ap.content_hash = i.content_hash\
                    ) AS active, \
                    (SELECT COUNT(*)::BIGINT \
                     FROM account_persona_growth_entries g \
                     WHERE g.account_id = i.account_id \
                       AND g.pack_name = i.pack_name) AS growth_count \
             FROM account_persona_installations i \
             WHERE i.account_id = $1 \
               AND ($2::TIMESTAMPTZ IS NULL OR \
                    (i.installed_at, i.pack_name, i.version) > ($2, $3, $4)) \
             ORDER BY i.installed_at, i.pack_name, i.version \
             LIMIT $5",
        )
        .bind::<SqlUuid, _>(account_id)
        .bind::<Nullable<Timestamptz>, _>(cursor_at)
        .bind::<Nullable<Text>, _>(cursor_name)
        .bind::<Nullable<Text>, _>(cursor_version)
        .bind::<BigInt, _>(i64::from(limit.get()) + 1)
        .load::<InstallationListRow>(&mut connection)
        .await
        .map_err(|_| PersonaStateError::Backend)?;
        let items = rows
            .into_iter()
            .map(installation_list_item)
            .collect::<Result<Vec<_>, _>>()?;
        trim_page(items, limit, |item| {
            InstallationCursor::new(
                item.installation.installed_at,
                item.installation.persona.pack_name(),
                item.installation.persona.version(),
            )
        })
    }

    /// Read one exact installation without any unscoped lookup path.
    async fn get_installation(
        &self,
        account_id: Uuid,
        persona: &ExactPersonaVersion,
    ) -> Result<Option<PersonaInstallationRecord>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let row = diesel::sql_query(
            "SELECT account_id, pack_name, version, content_hash, installed_at \
             FROM account_persona_installations \
             WHERE account_id = $1 AND pack_name = $2 AND version = $3 \
               AND content_hash = $4",
        )
        .bind::<SqlUuid, _>(account_id)
        .bind::<Text, _>(persona.pack_name())
        .bind::<Text, _>(persona.version())
        .bind::<Binary, _>(persona.content_hash().as_bytes().to_vec())
        .get_result::<InstallationRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| PersonaStateError::Backend)?;
        row.map(installation_record).transpose()
    }

    /// Read the tenant's historical active selection, if one exists.
    async fn get_active(
        &self,
        account_id: Uuid,
    ) -> Result<Option<ActivePersonaRecord>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let row = diesel::sql_query(
            "SELECT account_id, pack_name, version, content_hash, selected_at \
             FROM account_active_personas WHERE account_id = $1",
        )
        .bind::<SqlUuid, _>(account_id)
        .get_result::<ActivePersonaRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| PersonaStateError::Backend)?;
        row.map(active_record).transpose()
    }

    /// List tenant-scoped preferences in stable pack-name order.
    async fn list_preferences(
        &self,
        account_id: Uuid,
        cursor: Option<PreferenceCursor>,
        limit: PageLimit,
    ) -> Result<StatePage<PersonaPreferenceRecord, PreferenceCursor>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let cursor_name = cursor.as_ref().map(|value| value.pack_name().to_string());
        let rows = diesel::sql_query(
            "SELECT account_id, pack_name, bias_millis, mutation_count, updated_at \
             FROM account_persona_preferences \
             WHERE account_id = $1 \
               AND ($2::TEXT IS NULL OR pack_name > $2) \
             ORDER BY pack_name LIMIT $3",
        )
        .bind::<SqlUuid, _>(account_id)
        .bind::<Nullable<Text>, _>(cursor_name)
        .bind::<BigInt, _>(i64::from(limit.get()) + 1)
        .load::<PreferenceRow>(&mut connection)
        .await
        .map_err(|_| PersonaStateError::Backend)?;
        let items = rows
            .into_iter()
            .map(preference_record)
            .collect::<Result<Vec<_>, _>>()?;
        trim_page(items, limit, |item| {
            PreferenceCursor::new(item.pack_name.clone())
        })
    }

    /// List metadata-only growth rows without loading private text.
    async fn list_growth(
        &self,
        account_id: Uuid,
        pack_name: &PersonaName,
        cursor: Option<GrowthCursor>,
        limit: PageLimit,
    ) -> Result<StatePage<PersonaGrowthListItem, GrowthCursor>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let cursor_sequence = cursor.map(GrowthCursor::sequence);
        let cursor_entry = cursor.map(GrowthCursor::entry_id);
        let cursor_sequence = cursor_sequence
            .map(i64::try_from)
            .transpose()
            .map_err(|_| PersonaStateError::Invalid)?;
        let rows = diesel::sql_query(
            "SELECT entry_id, account_id, pack_name, version, content_hash, \
                    sequence, text_hash, created_at, operation_id \
             FROM account_persona_growth_entries \
             WHERE account_id = $1 AND pack_name = $2 \
               AND ($3::BIGINT IS NULL OR (sequence, entry_id) > ($3, $4)) \
             ORDER BY sequence, entry_id LIMIT $5",
        )
        .bind::<SqlUuid, _>(account_id)
        .bind::<Text, _>(pack_name.as_str())
        .bind::<Nullable<BigInt>, _>(cursor_sequence)
        .bind::<Nullable<SqlUuid>, _>(cursor_entry)
        .bind::<BigInt, _>(i64::from(limit.get()) + 1)
        .load::<GrowthListRow>(&mut connection)
        .await
        .map_err(|_| PersonaStateError::Backend)?;
        let items = rows
            .into_iter()
            .map(growth_list_item)
            .collect::<Result<Vec<_>, _>>()?;
        trim_page(items, limit, |item| {
            GrowthCursor::new(item.sequence, item.entry_id)
        })
    }

    /// Load one exact active render snapshot under shared row locks.
    async fn load_render_snapshot(
        &self,
        account_id: Uuid,
        root: &ExactPersonaVersion,
    ) -> Result<RenderPersonaStateSnapshot, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let root = root.clone();
        let result = connection
            .transaction::<RenderPersonaStateSnapshot, PersonaTransactionError, _>(
                async move |connection| {
                    require_active_account(connection, account_id, AccountLock::Share).await?;
                    let revision_row = diesel::sql_query(
                        "SELECT revision FROM account_persona_state \
                         WHERE account_id = $1 FOR SHARE",
                    )
                    .bind::<SqlUuid, _>(account_id)
                    .get_result::<RevisionRow>(connection)
                    .await
                    .optional()?
                    .ok_or_else(|| domain_error(PersonaStateError::NotFound))?;
                    let installation_row = diesel::sql_query(
                        "SELECT i.account_id, i.pack_name, i.version, i.content_hash, \
                                i.installed_at \
                         FROM account_persona_installations i \
                         JOIN pack_versions pv \
                           ON pv.pack_name = i.pack_name \
                          AND pv.version = i.version \
                          AND pv.content_hash = i.content_hash \
                         WHERE i.account_id = $1 AND i.pack_name = $2 \
                           AND i.version = $3 AND i.content_hash = $4 \
                           AND pv.status ->> 'kind' = 'active' \
                         FOR SHARE OF i, pv",
                    )
                    .bind::<SqlUuid, _>(account_id)
                    .bind::<Text, _>(root.pack_name())
                    .bind::<Text, _>(root.version())
                    .bind::<Binary, _>(root.content_hash().as_bytes().to_vec())
                    .get_result::<InstallationRow>(connection)
                    .await
                    .optional()?
                    .ok_or_else(|| domain_error(PersonaStateError::Unavailable))?;
                    let growth_rows = diesel::sql_query(
                        "SELECT entry_id, account_id, pack_name, version, content_hash, \
                                sequence, text, text_hash, created_at, operation_id \
                         FROM account_persona_growth_entries \
                         WHERE account_id = $1 AND pack_name = $2 AND version = $3 \
                           AND content_hash = $4 \
                         ORDER BY sequence DESC, entry_id DESC LIMIT $5",
                    )
                    .bind::<SqlUuid, _>(account_id)
                    .bind::<Text, _>(root.pack_name())
                    .bind::<Text, _>(root.version())
                    .bind::<Binary, _>(root.content_hash().as_bytes().to_vec())
                    .bind::<BigInt, _>(i64::from(MAX_RENDER_GROWTH_ENTRIES))
                    .load::<GrowthRow>(connection)
                    .await?;
                    let mut growth = Vec::with_capacity(growth_rows.len());
                    let mut growth_bytes = 0_usize;
                    for row in growth_rows {
                        let record = growth_record(row).map_err(domain_error)?;
                        let Some(next_bytes) = growth_bytes.checked_add(record.text.len()) else {
                            return Err(domain_error(PersonaStateError::Backend));
                        };
                        if next_bytes > MAX_RENDER_GROWTH_BYTES {
                            break;
                        }
                        growth_bytes = next_bytes;
                        growth.push(record);
                    }
                    growth.reverse();
                    Ok(RenderPersonaStateSnapshot {
                        state: AccountPersonaStateSnapshot {
                            account_id,
                            revision: unsigned(revision_row.revision).map_err(domain_error)?,
                        },
                        installation: installation_record(installation_row)
                            .map_err(domain_error)?,
                        growth,
                    })
                },
            )
            .await;
        map_transaction_result(result)
    }

    /// List immutable operations in stable account revision order.
    async fn list_operations(
        &self,
        account_id: Uuid,
        cursor: Option<OperationCursor>,
        limit: PageLimit,
    ) -> Result<StatePage<PersonaOperationRecord, OperationCursor>, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        require_active_account(&mut connection, account_id, AccountLock::None)
            .await
            .map_err(public_transaction_error)?;
        let cursor_sequence = cursor.map(OperationCursor::sequence);
        let cursor_operation = cursor.map(OperationCursor::operation_id);
        let cursor_sequence = cursor_sequence
            .map(i64::try_from)
            .transpose()
            .map_err(|_| PersonaStateError::Invalid)?;
        let rows = diesel::sql_query(
            "SELECT account_id, operation_id, sequence, tool_name, \
                    request_schema_version, request_hash, receipt, created_at \
             FROM account_persona_operations \
             WHERE account_id = $1 \
               AND ($2::BIGINT IS NULL OR (sequence, operation_id) > ($2, $3)) \
             ORDER BY sequence, operation_id LIMIT $4",
        )
        .bind::<SqlUuid, _>(account_id)
        .bind::<Nullable<BigInt>, _>(cursor_sequence)
        .bind::<Nullable<SqlUuid>, _>(cursor_operation)
        .bind::<BigInt, _>(i64::from(limit.get()) + 1)
        .load::<OperationRow>(&mut connection)
        .await
        .map_err(|_| PersonaStateError::Backend)?;
        let items = rows
            .into_iter()
            .map(operation_record)
            .collect::<Result<Vec<_>, _>>()?;
        trim_page(items, limit, |item| {
            OperationCursor::new(item.sequence, item.operation_id)
        })
    }

    /// Atomically attach one exact active catalog version to an account.
    async fn install(
        &self,
        request: InstallPersonaRequest,
    ) -> Result<MutationOutcome, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let context = request.context().clone();
        let persona = request.persona().clone();
        let result = connection
            .transaction::<MutationOutcome, PersonaTransactionError, _>(async move |connection| {
                let start = begin_mutation(connection, &context).await?;
                let (previous_revision, sequence) = match start {
                    MutationStart::Replay(outcome) => {
                        return validate_install_replay(*outcome, &persona);
                    }
                    MutationStart::Fresh {
                        previous_revision,
                        sequence,
                    } => (previous_revision, sequence),
                };
                require_active_catalog_version(connection, &persona).await?;

                let existing = diesel::sql_query(
                    "SELECT account_id, pack_name, version, content_hash, installed_at \
                         FROM account_persona_installations \
                         WHERE account_id = $1 AND pack_name = $2 AND version = $3 \
                         FOR UPDATE",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .bind::<Text, _>(persona.pack_name())
                .bind::<Text, _>(persona.version())
                .get_result::<InstallationRow>(connection)
                .await
                .optional()?;
                let created = match existing {
                    Some(row) => {
                        let existing = installation_record(row).map_err(domain_error)?;
                        if !same_persona(&existing.persona, &persona) {
                            return Err(domain_error(PersonaStateError::Unavailable));
                        }
                        false
                    }
                    None => {
                        let count = diesel::sql_query(
                            "SELECT COUNT(*)::BIGINT AS count \
                                 FROM account_persona_installations WHERE account_id = $1",
                        )
                        .bind::<SqlUuid, _>(context.account_id())
                        .get_result::<CountRow>(connection)
                        .await?;
                        if count_u32(count.count).map_err(domain_error)?
                            >= MAX_INSTALLATIONS_PER_ACCOUNT
                        {
                            return Err(domain_error(PersonaStateError::Quota));
                        }
                        diesel::sql_query(
                            "INSERT INTO account_persona_installations (\
                                     account_id, pack_name, version, content_hash\
                                 ) VALUES ($1, $2, $3, $4)",
                        )
                        .bind::<SqlUuid, _>(context.account_id())
                        .bind::<Text, _>(persona.pack_name())
                        .bind::<Text, _>(persona.version())
                        .bind::<Binary, _>(persona.content_hash().as_bytes().to_vec())
                        .execute(connection)
                        .await?;
                        true
                    }
                };
                let count = diesel::sql_query(
                    "SELECT COUNT(*)::BIGINT AS count \
                         FROM account_persona_installations WHERE account_id = $1",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .get_result::<CountRow>(connection)
                .await?;
                let installation_count = count_u32(count.count).map_err(domain_error)?;
                finish_mutation(
                    connection,
                    &context,
                    previous_revision,
                    sequence,
                    MutationReceipt::Install {
                        persona,
                        created,
                        installation_count,
                    },
                )
                .await
            })
            .await;
        map_transaction_result(result)
    }

    /// Atomically select one exact root after locking every rendered reference.
    async fn set_active(
        &self,
        request: SetActivePersonaRequest,
    ) -> Result<MutationOutcome, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let context = request.context().clone();
        let root = request.root().clone();
        let references = request.references().to_vec();
        let reference_set_hash = exact_reference_set_hash(&references);
        let mut required = Vec::with_capacity(references.len() + 1);
        required.push(root.clone());
        required.extend_from_slice(&references);
        required.sort_by(exact_persona_order);
        let result = connection
            .transaction::<MutationOutcome, PersonaTransactionError, _>(async move |connection| {
                let start = begin_mutation(connection, &context).await?;
                let (previous_revision, sequence) = match start {
                    MutationStart::Replay(outcome) => {
                        let outcome =
                            validate_set_active_replay(*outcome, &root, reference_set_hash)?;
                        for persona in &required {
                            require_available_installation(
                                connection,
                                context.account_id(),
                                persona,
                            )
                            .await?;
                        }
                        return Ok(outcome);
                    }
                    MutationStart::Fresh {
                        previous_revision,
                        sequence,
                    } => (previous_revision, sequence),
                };
                for persona in &required {
                    require_available_installation(connection, context.account_id(), persona)
                        .await?;
                }

                let previous_row = diesel::sql_query(
                    "SELECT account_id, pack_name, version, content_hash, selected_at \
                         FROM account_active_personas WHERE account_id = $1 FOR UPDATE",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .get_result::<ActivePersonaRow>(connection)
                .await
                .optional()?;
                let previous = previous_row
                    .map(active_record)
                    .transpose()
                    .map_err(domain_error)?
                    .map(|record| record.persona);
                if previous
                    .as_ref()
                    .is_none_or(|current| !same_persona(current, &root))
                {
                    diesel::sql_query(
                        "INSERT INTO account_active_personas (\
                                 account_id, pack_name, version, content_hash\
                             ) VALUES ($1, $2, $3, $4) \
                             ON CONFLICT (account_id) DO UPDATE SET \
                                 pack_name = EXCLUDED.pack_name, \
                                 version = EXCLUDED.version, \
                                 content_hash = EXCLUDED.content_hash, \
                                 selected_at = NOW()",
                    )
                    .bind::<SqlUuid, _>(context.account_id())
                    .bind::<Text, _>(root.pack_name())
                    .bind::<Text, _>(root.version())
                    .bind::<Binary, _>(root.content_hash().as_bytes().to_vec())
                    .execute(connection)
                    .await?;
                }
                finish_mutation(
                    connection,
                    &context,
                    previous_revision,
                    sequence,
                    MutationReceipt::SetActive {
                        persona: root,
                        reference_set_hash,
                        previous,
                    },
                )
                .await
            })
            .await;
        map_transaction_result(result)
    }

    /// Atomically append private growth while storing only its hash in receipts.
    async fn append_growth(
        &self,
        request: AppendGrowthRequest,
    ) -> Result<MutationOutcome, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let context = request.context().clone();
        let persona = request.persona().clone();
        let entry_id = request.entry_id();
        let text = request.text().to_string();
        let text_hash = ObjectHash::of(text.as_bytes());
        let result = connection
            .transaction::<MutationOutcome, PersonaTransactionError, _>(async move |connection| {
                let start = begin_mutation(connection, &context).await?;
                let (previous_revision, sequence) = match start {
                    MutationStart::Replay(outcome) => {
                        return validate_growth_replay(*outcome, &persona, entry_id, text_hash);
                    }
                    MutationStart::Fresh {
                        previous_revision,
                        sequence,
                    } => (previous_revision, sequence),
                };
                if !validate_growth_policy_candidate(&text).valid {
                    return Err(domain_error(PersonaStateError::Invalid));
                }
                require_available_installation(connection, context.account_id(), &persona).await?;

                let existing_entry = diesel::sql_query(
                    "SELECT COUNT(*)::BIGINT AS count \
                         FROM account_persona_growth_entries \
                         WHERE account_id = $1 AND entry_id = $2",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .bind::<SqlUuid, _>(entry_id)
                .get_result::<CountRow>(connection)
                .await?;
                if existing_entry.count != 0 {
                    return Err(domain_error(PersonaStateError::OperationConflict));
                }
                let count = diesel::sql_query(
                    "SELECT COUNT(*)::BIGINT AS count \
                         FROM account_persona_growth_entries \
                         WHERE account_id = $1 AND pack_name = $2",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .bind::<Text, _>(persona.pack_name())
                .get_result::<CountRow>(connection)
                .await?;
                let growth_count = count_u32(count.count).map_err(domain_error)?;
                if growth_count >= MAX_GROWTH_ENTRIES_PER_ACCOUNT_PACK {
                    return Err(domain_error(PersonaStateError::Quota));
                }
                let growth_count = growth_count
                    .checked_add(1)
                    .ok_or_else(|| domain_error(PersonaStateError::Quota))?;
                let sequence_i64 = i64::try_from(sequence)
                    .map_err(|_| domain_error(PersonaStateError::Backend))?;
                diesel::sql_query(
                    "INSERT INTO account_persona_growth_entries (\
                             account_id, entry_id, pack_name, version, content_hash, \
                             sequence, text, text_hash, operation_id\
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind::<SqlUuid, _>(context.account_id())
                .bind::<SqlUuid, _>(entry_id)
                .bind::<Text, _>(persona.pack_name())
                .bind::<Text, _>(persona.version())
                .bind::<Binary, _>(persona.content_hash().as_bytes().to_vec())
                .bind::<BigInt, _>(sequence_i64)
                .bind::<Text, _>(&text)
                .bind::<Binary, _>(text_hash.as_bytes().to_vec())
                .bind::<SqlUuid, _>(context.operation_id())
                .execute(connection)
                .await?;
                finish_mutation(
                    connection,
                    &context,
                    previous_revision,
                    sequence,
                    MutationReceipt::AppendGrowth {
                        entry_id,
                        persona,
                        sequence,
                        text_hash,
                        growth_count,
                    },
                )
                .await
            })
            .await;
        map_transaction_result(result)
    }

    /// Atomically bump, decay, or reset bounded account preferences.
    async fn mutate_preference(
        &self,
        request: MutatePreferenceRequest,
    ) -> Result<MutationOutcome, PersonaStateError> {
        let mut connection = self.pool().get().await.map_err(|_| pool_error())?;
        let context = request.context().clone();
        let pack_name = request.pack_name().map(str::to_string);
        let mutation = request.mutation();
        let result = connection
            .transaction::<MutationOutcome, PersonaTransactionError, _>(async move |connection| {
                let start = begin_mutation(connection, &context).await?;
                let (previous_revision, sequence) = match start {
                    MutationStart::Replay(outcome) => {
                        return validate_preference_replay(
                            *outcome,
                            mutation,
                            pack_name.as_deref(),
                        );
                    }
                    MutationStart::Fresh {
                        previous_revision,
                        sequence,
                    } => (previous_revision, sequence),
                };
                if mutation != PreferenceMutation::Reset {
                    let target = pack_name
                        .as_deref()
                        .ok_or_else(|| domain_error(PersonaStateError::Invalid))?;
                    let active = diesel::sql_query(
                        "SELECT ap.account_id, ap.pack_name, ap.version, \
                                    ap.content_hash, ap.selected_at \
                             FROM account_active_personas ap \
                             JOIN account_persona_installations i \
                               ON i.account_id = ap.account_id \
                              AND i.pack_name = ap.pack_name \
                              AND i.version = ap.version \
                              AND i.content_hash = ap.content_hash \
                             JOIN pack_versions pv \
                               ON pv.pack_name = i.pack_name \
                              AND pv.version = i.version \
                              AND pv.content_hash = i.content_hash \
                             WHERE ap.account_id = $1 AND ap.pack_name = $2 \
                               AND pv.status ->> 'kind' = 'active' \
                             FOR SHARE OF ap, i, pv",
                    )
                    .bind::<SqlUuid, _>(context.account_id())
                    .bind::<Text, _>(target)
                    .get_result::<ActivePersonaRow>(connection)
                    .await
                    .optional()?;
                    if active.is_none() {
                        return Err(domain_error(PersonaStateError::Unavailable));
                    }
                }
                let (receipt_pack_name, bias_millis, affected_count) = match mutation {
                    PreferenceMutation::Reset => {
                        let affected = diesel::sql_query(
                            "DELETE FROM account_persona_preferences \
                                 WHERE account_id = $1",
                        )
                        .bind::<SqlUuid, _>(context.account_id())
                        .execute(connection)
                        .await?;
                        let affected = u32::try_from(affected)
                            .map_err(|_| domain_error(PersonaStateError::Backend))?;
                        if affected > MAX_PREFERENCES_PER_ACCOUNT {
                            return Err(domain_error(PersonaStateError::Backend));
                        }
                        (None, None, affected)
                    }
                    PreferenceMutation::Bump | PreferenceMutation::Decay => {
                        let target = pack_name
                            .as_deref()
                            .ok_or_else(|| domain_error(PersonaStateError::Invalid))?;
                        let existing = diesel::sql_query(
                            "SELECT bias_millis, mutation_count \
                                 FROM account_persona_preferences \
                                 WHERE account_id = $1 AND pack_name = $2 FOR UPDATE",
                        )
                        .bind::<SqlUuid, _>(context.account_id())
                        .bind::<Text, _>(target)
                        .get_result::<PreferenceValueRow>(connection)
                        .await
                        .optional()?;
                        if existing.is_none() {
                            let count = diesel::sql_query(
                                "SELECT COUNT(*)::BIGINT AS count \
                                     FROM account_persona_preferences WHERE account_id = $1",
                            )
                            .bind::<SqlUuid, _>(context.account_id())
                            .get_result::<CountRow>(connection)
                            .await?;
                            if count_u32(count.count).map_err(domain_error)?
                                >= MAX_PREFERENCES_PER_ACCOUNT
                            {
                                return Err(domain_error(PersonaStateError::Quota));
                            }
                        }
                        let (current_bias, current_count) = match existing.as_ref() {
                            Some(row) => {
                                let count = count_u32(row.mutation_count).map_err(domain_error)?;
                                if count == 0
                                    || !(MIN_PREFERENCE_BIAS_MILLIS..=MAX_PREFERENCE_BIAS_MILLIS)
                                        .contains(&row.bias_millis)
                                {
                                    return Err(domain_error(PersonaStateError::Backend));
                                }
                                (row.bias_millis, count)
                            }
                            None => (0_i16, 0_u32),
                        };
                        if current_count == u32::MAX {
                            return Err(domain_error(PersonaStateError::Quota));
                        }
                        let delta = match mutation {
                            PreferenceMutation::Bump => PREFERENCE_BUMP_MILLIS,
                            PreferenceMutation::Decay => PREFERENCE_DECAY_MILLIS,
                            PreferenceMutation::Reset => {
                                return Err(domain_error(PersonaStateError::Backend));
                            }
                        };
                        let bias = (i32::from(current_bias) + i32::from(delta)).clamp(
                            i32::from(MIN_PREFERENCE_BIAS_MILLIS),
                            i32::from(MAX_PREFERENCE_BIAS_MILLIS),
                        ) as i16;
                        let mutation_count = current_count + 1;
                        diesel::sql_query(
                            "INSERT INTO account_persona_preferences (\
                                     account_id, pack_name, bias_millis, mutation_count\
                                 ) VALUES ($1, $2, $3, $4) \
                                 ON CONFLICT (account_id, pack_name) DO UPDATE SET \
                                     bias_millis = EXCLUDED.bias_millis, \
                                     mutation_count = EXCLUDED.mutation_count, \
                                     updated_at = NOW()",
                        )
                        .bind::<SqlUuid, _>(context.account_id())
                        .bind::<Text, _>(target)
                        .bind::<SmallInt, _>(bias)
                        .bind::<BigInt, _>(i64::from(mutation_count))
                        .execute(connection)
                        .await?;
                        (Some(target.to_string()), Some(bias), 1)
                    }
                };
                finish_mutation(
                    connection,
                    &context,
                    previous_revision,
                    sequence,
                    MutationReceipt::MutatePreference {
                        mutation,
                        pack_name: receipt_pack_name,
                        bias_millis,
                        affected_count,
                    },
                )
                .await
            })
            .await;
        map_transaction_result(result)
    }
}

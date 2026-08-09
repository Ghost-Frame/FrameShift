-- Add account-scoped cloud persona state for authenticated remote connectors.
--
-- Mutable account state is removed with its owning state row, while immutable
-- operation evidence and exact installation references use RESTRICT. As a
-- result, an account with connector history cannot be physically deleted;
-- account lifecycle changes must use accounts.status so replay evidence and
-- catalog provenance remain intact.

-- Exact content identity is required as a PostgreSQL foreign-key target.
-- The existing (pack_name, version) primary key still defines public version
-- identity; this key additionally lets account rows bind the immutable hash.
ALTER TABLE pack_versions
    ADD CONSTRAINT pack_versions_exact_content_unique
    UNIQUE (pack_name, version, content_hash);

-- One row per account is the serialization lock and compare-and-swap fence for
-- every connector mutation. Count quotas are enforced transactionally while
-- this row is locked by the persistence adapter.
CREATE TABLE account_persona_state (
    -- Stable account identity derived by the authenticated server boundary.
    account_id UUID PRIMARY KEY
        REFERENCES accounts(id) ON DELETE CASCADE,
    -- Latest committed mutation sequence; zero means no mutation has committed.
    revision BIGINT NOT NULL DEFAULT 0,
    -- Commit timestamp of the latest fresh mutation.
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Revisions are represented by non-negative signed PostgreSQL integers.
    CONSTRAINT account_persona_state_revision_nonnegative
        CHECK (revision >= 0)
);

COMMENT ON TABLE account_persona_state IS
    'Per-account serialization lock and revision fence for remote persona state';
COMMENT ON COLUMN account_persona_state.revision IS
    'Latest committed fresh operation sequence; identical replay does not advance it';

-- Exact persona installations retain immutable public content identity. The
-- 64-installation quota is checked under the owning state-row lock so existing
-- exact installations remain idempotent at the quota boundary.
CREATE TABLE account_persona_installations (
    -- Account-scoped state owner.
    account_id UUID NOT NULL
        REFERENCES account_persona_state(account_id) ON DELETE CASCADE,
    -- Canonical public pack name.
    pack_name TEXT NOT NULL,
    -- Exact immutable public version string.
    version TEXT NOT NULL,
    -- SHA-256 digest of the exact verified archive bytes.
    content_hash BYTEA NOT NULL,
    -- Timestamp of the first successful attachment to this account.
    installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One account may attach an exact public version only once.
    CONSTRAINT account_persona_installations_pkey
        PRIMARY KEY (account_id, pack_name, version),
    -- Active selections and growth rows bind the full tenant and content key.
    CONSTRAINT account_persona_installations_exact_unique
        UNIQUE (account_id, pack_name, version, content_hash),
    -- Installed content must remain an exact known catalog version.
    CONSTRAINT account_persona_installations_catalog_fkey
        FOREIGN KEY (pack_name, version, content_hash)
        REFERENCES pack_versions (pack_name, version, content_hash)
        ON DELETE RESTRICT,
    -- Content identities are exact SHA-256 values.
    CONSTRAINT account_persona_installations_hash_length
        CHECK (octet_length(content_hash) = 32),
    -- Names match the portable manifest boundary used by the domain contract.
    CONSTRAINT account_persona_installations_name_shape
        CHECK (
            octet_length(pack_name) BETWEEN 1 AND 64
            AND pack_name ~ '^[A-Za-z0-9_-]+$'
            AND pack_name !~ '\.\.'
        ),
    -- Versions match the portable exact-version boundary used by the domain contract.
    CONSTRAINT account_persona_installations_version_shape
        CHECK (
            octet_length(version) BETWEEN 1 AND 64
            AND version ~ '^[A-Za-z0-9._+-]+$'
            AND version !~ '\.\.'
        )
);

COMMENT ON TABLE account_persona_installations IS
    'Exact verified public persona versions attached to one authenticated account';

-- Stable installation-time ordering supports bounded keyset pagination.
CREATE INDEX account_persona_installations_page_idx
    ON account_persona_installations (
        account_id,
        installed_at,
        pack_name,
        version
    );

-- One exact installed version may be active for an account at a time. Deleting
-- an active installation is refused until the selection is explicitly changed.
CREATE TABLE account_active_personas (
    -- Account whose connector-wide active selection is recorded.
    account_id UUID PRIMARY KEY,
    -- Exact installed root pack name.
    pack_name TEXT NOT NULL,
    -- Exact installed root version.
    version TEXT NOT NULL,
    -- Exact installed root content hash.
    content_hash BYTEA NOT NULL,
    -- Timestamp of the latest successful active-selection mutation.
    selected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The active identity must be one exact installation owned by this account.
    CONSTRAINT account_active_personas_installation_fkey
        FOREIGN KEY (account_id, pack_name, version, content_hash)
        REFERENCES account_persona_installations (
            account_id,
            pack_name,
            version,
            content_hash
        )
        ON DELETE RESTRICT,
    -- Content identities are exact SHA-256 values.
    CONSTRAINT account_active_personas_hash_length
        CHECK (octet_length(content_hash) = 32)
);

COMMENT ON TABLE account_active_personas IS
    'Single account-level active persona bound to one exact installation';

-- Global-only V1 preferences retain deterministic integer bias semantics. The
-- 64-row quota and exact bump/decay transitions are enforced transactionally.
CREATE TABLE account_persona_preferences (
    -- Account-scoped state owner.
    account_id UUID NOT NULL
        REFERENCES account_persona_state(account_id) ON DELETE CASCADE,
    -- Installed active pack name receiving the learned bias.
    pack_name TEXT NOT NULL,
    -- Exact signed bias in milli-units, equivalent to local +/-0.2 clamping.
    bias_millis SMALLINT NOT NULL,
    -- Number of bump or decay mutations incorporated into this row.
    mutation_count BIGINT NOT NULL,
    -- Timestamp of the latest preference mutation.
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One global-only preference row exists per account and pack name.
    CONSTRAINT account_persona_preferences_pkey
        PRIMARY KEY (account_id, pack_name),
    -- Bias is clamped to the local orchestrator's exact integer bounds.
    CONSTRAINT account_persona_preferences_bias_bounded
        CHECK (bias_millis BETWEEN -200 AND 200),
    -- Mutation counts use the complete unsigned 32-bit domain contract.
    CONSTRAINT account_persona_preferences_count_bounded
        CHECK (mutation_count BETWEEN 1 AND 4294967295),
    -- Preference targets use canonical public pack names.
    CONSTRAINT account_persona_preferences_name_shape
        CHECK (
            octet_length(pack_name) BETWEEN 1 AND 64
            AND pack_name ~ '^[A-Za-z0-9_-]+$'
            AND pack_name !~ '\.\.'
        )
);

COMMENT ON TABLE account_persona_preferences IS
    'Bounded global-only integer selection preferences for one account';

-- Every fresh mutation stores one bounded typed receipt at the committed
-- account revision. The trusted Rust adapter constructs the closed receipt
-- enum without secrets; the database independently checks its object shape,
-- matching kind, and serialized byte bound. The adapter enforces the
-- 10,000-row account quota under the state lock before a new operation insert.
CREATE TABLE account_persona_operations (
    -- Account-scoped state owner; RESTRICT preserves replay evidence.
    account_id UUID NOT NULL
        REFERENCES account_persona_state(account_id) ON DELETE RESTRICT,
    -- Caller-selected non-nil idempotency identifier.
    operation_id UUID NOT NULL,
    -- Positive sequence equal to the account revision committed by this mutation.
    sequence BIGINT NOT NULL,
    -- Exact bounded remote mutation tool name.
    tool_name TEXT NOT NULL,
    -- Positive canonical request-hashing schema version.
    request_schema_version INTEGER NOT NULL,
    -- SHA-256 digest of the canonical operation-specific request.
    request_hash BYTEA NOT NULL,
    -- Closed typed receipt JSON constructed by the trusted Rust adapter.
    receipt JSONB NOT NULL,
    -- Timestamp at which the state change and receipt committed.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Idempotency identifiers are isolated by account.
    CONSTRAINT account_persona_operations_pkey
        PRIMARY KEY (account_id, operation_id),
    -- A fresh account revision can identify at most one operation.
    CONSTRAINT account_persona_operations_sequence_unique
        UNIQUE (account_id, sequence),
    -- Growth rows bind both the operation identity and its committed sequence.
    CONSTRAINT account_persona_operations_growth_reference_unique
        UNIQUE (account_id, operation_id, sequence),
    -- Nil UUIDs are not valid idempotency identifiers.
    CONSTRAINT account_persona_operations_id_non_nil
        CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    -- Committed mutation revisions are strictly positive.
    CONSTRAINT account_persona_operations_sequence_positive
        CHECK (sequence > 0),
    -- Only the four V1 remote mutation tools may create replay evidence.
    CONSTRAINT account_persona_operations_tool_known
        CHECK (tool_name IN (
            'frameshift_install',
            'frameshift_use',
            'frameshift_grow_append',
            'frameshift_prefs'
        )),
    -- V1 canonical request hashing is immutable until a later schema migration.
    CONSTRAINT account_persona_operations_schema_version_current
        CHECK (request_schema_version = 1),
    -- Canonical request identities are exact SHA-256 values.
    CONSTRAINT account_persona_operations_request_hash_length
        CHECK (octet_length(request_hash) = 32),
    -- Receipts are closed JSON objects rather than arbitrary scalar payloads.
    CONSTRAINT account_persona_operations_receipt_object
        CHECK (jsonb_typeof(receipt) = 'object'),
    -- Each mutation tool stores only its matching closed receipt variant kind.
    CONSTRAINT account_persona_operations_receipt_kind_matches_tool
        CHECK (
            receipt ? 'kind'
            AND jsonb_typeof(receipt -> 'kind') = 'string'
            AND (
                (tool_name = 'frameshift_install'
                    AND receipt ->> 'kind' = 'install')
                OR (tool_name = 'frameshift_use'
                    AND receipt ->> 'kind' = 'set_active')
                OR (tool_name = 'frameshift_grow_append'
                    AND receipt ->> 'kind' = 'append_growth')
                OR (tool_name = 'frameshift_prefs'
                    AND receipt ->> 'kind' = 'mutate_preference')
            )
        ),
    -- Stored canonical JSON text cannot exceed the receipt byte budget.
    CONSTRAINT account_persona_operations_receipt_bounded
        CHECK (octet_length(receipt::text) <= 8192)
);

COMMENT ON TABLE account_persona_operations IS
    'Append-only idempotency evidence with bounded typed mutation receipts';
COMMENT ON COLUMN account_persona_operations.receipt IS
    'Rust enforces the closed non-secret fields; SQL enforces object, kind, and byte bounds';

-- Stable revision ordering supports account-scoped operation pagination.
CREATE INDEX account_persona_operations_page_idx
    ON account_persona_operations (account_id, sequence, operation_id);

-- Reject direct or cascaded changes to committed replay evidence.
CREATE FUNCTION reject_account_persona_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account persona operations are immutable';
END
$$;

COMMENT ON FUNCTION reject_account_persona_operation_mutation() IS
    'Rejects UPDATE, DELETE, and TRUNCATE attempts against committed operation evidence';

-- Enforce append-only operation evidence independently of application behavior.
CREATE TRIGGER account_persona_operations_immutable
BEFORE UPDATE OR DELETE ON account_persona_operations
FOR EACH ROW EXECUTE FUNCTION reject_account_persona_operation_mutation();

COMMENT ON TRIGGER account_persona_operations_immutable
    ON account_persona_operations IS
    'Prevents mutation or deletion of committed idempotency evidence';

-- Reject table-wide erasure, which does not invoke row DELETE triggers.
CREATE TRIGGER account_persona_operations_no_truncate
BEFORE TRUNCATE ON account_persona_operations
FOR EACH STATEMENT EXECUTE FUNCTION reject_account_persona_operation_mutation();

COMMENT ON TRIGGER account_persona_operations_no_truncate
    ON account_persona_operations IS
    'Prevents TRUNCATE from bypassing row-level immutable evidence protection';

-- Growth entries retain the exact installed identity admitted by the server.
-- The 1,000-row per-account/pack quota is enforced under the owning state lock.
CREATE TABLE account_persona_growth_entries (
    -- Account-scoped half of the tenant-composite entry identity.
    account_id UUID NOT NULL,
    -- Caller-selected non-nil entry identifier, reusable only across accounts.
    entry_id UUID NOT NULL,
    -- Exact installed pack name receiving this authenticated user state.
    pack_name TEXT NOT NULL,
    -- Exact installed version receiving this authenticated user state.
    version TEXT NOT NULL,
    -- Exact installed archive hash receiving this authenticated user state.
    content_hash BYTEA NOT NULL,
    -- Positive monotonic account/persona ordering value.
    sequence BIGINT NOT NULL,
    -- Exact structurally admitted UTF-8 growth text.
    text TEXT NOT NULL,
    -- SHA-256 digest of the exact UTF-8 text bytes.
    text_hash BYTEA NOT NULL,
    -- Timestamp at which the growth mutation committed.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Idempotency operation that committed this entry.
    operation_id UUID NOT NULL,
    -- Entry identifiers are isolated by account rather than globally unique.
    CONSTRAINT account_persona_growth_entries_pkey
        PRIMARY KEY (account_id, entry_id),
    -- One mutation operation may append at most one growth entry.
    CONSTRAINT account_persona_growth_entries_operation_unique
        UNIQUE (account_id, operation_id),
    -- Exact account/persona/version/hash ordering cannot be duplicated.
    CONSTRAINT account_persona_growth_entries_sequence_unique
        UNIQUE (account_id, pack_name, version, content_hash, sequence),
    -- Persona ordering spans versions so a name cannot reuse an earlier sequence.
    CONSTRAINT account_persona_growth_entries_name_sequence_unique
        UNIQUE (account_id, pack_name, sequence),
    -- Growth may only bind an exact installation retained by the same account.
    CONSTRAINT account_persona_growth_entries_installation_fkey
        FOREIGN KEY (account_id, pack_name, version, content_hash)
        REFERENCES account_persona_installations (
            account_id,
            pack_name,
            version,
            content_hash
        )
        ON DELETE RESTRICT,
    -- Domain and operation rows may be inserted in either order in one transaction.
    CONSTRAINT account_persona_growth_entries_operation_fkey
        FOREIGN KEY (account_id, operation_id, sequence)
        REFERENCES account_persona_operations (
            account_id,
            operation_id,
            sequence
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    -- Nil UUIDs are not valid stable growth identities.
    CONSTRAINT account_persona_growth_entries_id_non_nil
        CHECK (entry_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    -- Growth ordering values are allocated only by committed account mutations.
    CONSTRAINT account_persona_growth_entries_sequence_positive
        CHECK (sequence > 0),
    -- Growth text is non-empty and bounded by exact UTF-8 byte length.
    CONSTRAINT account_persona_growth_entries_text_bounded
        CHECK (octet_length(text) BETWEEN 1 AND 4096),
    -- Installed content and growth text identities are exact SHA-256 values.
    CONSTRAINT account_persona_growth_entries_hash_lengths
        CHECK (
            octet_length(content_hash) = 32
            AND octet_length(text_hash) = 32
        )
);

COMMENT ON TABLE account_persona_growth_entries IS
    'Exact authenticated account growth bound to an installed persona and creating operation';
COMMENT ON COLUMN account_persona_growth_entries.text IS
    'Authenticated user state, not publisher-signed pack content or trusted instructions';

-- Reject any rewrite or erasure of growth already bound to immutable evidence.
CREATE FUNCTION reject_account_persona_growth_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account persona growth entries are immutable';
END
$$;

COMMENT ON FUNCTION reject_account_persona_growth_mutation() IS
    'Rejects UPDATE, DELETE, and TRUNCATE attempts against committed growth entries';

-- Prevent text and its digest from being replaced together after admission.
CREATE TRIGGER account_persona_growth_entries_immutable
BEFORE UPDATE OR DELETE ON account_persona_growth_entries
FOR EACH ROW EXECUTE FUNCTION reject_account_persona_growth_mutation();

COMMENT ON TRIGGER account_persona_growth_entries_immutable
    ON account_persona_growth_entries IS
    'Prevents mutation or deletion of committed authenticated growth';

-- Reject table-wide erasure, which does not invoke row DELETE triggers.
CREATE TRIGGER account_persona_growth_entries_no_truncate
BEFORE TRUNCATE ON account_persona_growth_entries
FOR EACH STATEMENT EXECUTE FUNCTION reject_account_persona_growth_mutation();

COMMENT ON TRIGGER account_persona_growth_entries_no_truncate
    ON account_persona_growth_entries IS
    'Prevents TRUNCATE from bypassing row-level growth immutability';

-- Stable chronological account/pack pagination is independent of version ties.
CREATE INDEX account_persona_growth_entries_page_idx
    ON account_persona_growth_entries (
        account_id,
        pack_name,
        sequence,
        entry_id
    );

-- Exact-root reverse sequence supports newest-first bounded render selection.
CREATE INDEX account_persona_growth_entries_render_idx
    ON account_persona_growth_entries (
        account_id,
        pack_name,
        version,
        content_hash,
        sequence DESC,
        entry_id DESC
    );

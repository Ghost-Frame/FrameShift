-- Expand-only account and publisher identity substrate.
-- Existing author keys and pack signer evidence remain authoritative until the
-- later compatibility backfill explicitly links them to publisher identities.

CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT accounts_issuer_subject_unique UNIQUE (issuer, subject),
    CONSTRAINT accounts_issuer_not_blank CHECK (btrim(issuer) <> ''),
    CONSTRAINT accounts_subject_not_blank CHECK (btrim(subject) <> '')
);

CREATE INDEX accounts_subject_lookup_idx ON accounts (issuer, subject);

CREATE TABLE publisher_profiles (
    id UUID PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    biography TEXT,
    moderation_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (moderation_status IN ('pending', 'approved', 'suspended', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT publisher_handle_normalized CHECK (handle = lower(handle)),
    CONSTRAINT publisher_handle_shape CHECK (handle ~ '^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$'),
    CONSTRAINT publisher_display_name_not_blank CHECK (btrim(display_name) <> '')
);

CREATE INDEX publisher_profiles_handle_idx ON publisher_profiles (handle);

CREATE TABLE publisher_memberships (
    account_id UUID NOT NULL REFERENCES accounts(id),
    publisher_id UUID NOT NULL REFERENCES publisher_profiles(id),
    role TEXT NOT NULL CHECK (role IN ('owner')),
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_id, publisher_id)
);

CREATE INDEX publisher_memberships_publisher_idx
    ON publisher_memberships (publisher_id, state, role);

CREATE TABLE publisher_keys (
    id UUID PRIMARY KEY,
    publisher_id UUID NOT NULL REFERENCES publisher_profiles(id),
    public_key BYTEA NOT NULL UNIQUE,
    label TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT publisher_key_length CHECK (octet_length(public_key) = 32),
    CONSTRAINT publisher_key_label_not_blank CHECK (btrim(label) <> ''),
    CONSTRAINT publisher_key_revocation_consistent CHECK (
        (state = 'active' AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX publisher_keys_publisher_idx
    ON publisher_keys (publisher_id, state, created_at);

CREATE TABLE publisher_audit_events (
    id UUID PRIMARY KEY,
    actor_account_id UUID REFERENCES accounts(id),
    publisher_id UUID NOT NULL REFERENCES publisher_profiles(id),
    action TEXT NOT NULL,
    target_key_id UUID REFERENCES publisher_keys(id),
    target_version TEXT,
    request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT publisher_audit_action_not_blank CHECK (btrim(action) <> ''),
    CONSTRAINT publisher_audit_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX publisher_audit_events_publisher_time_idx
    ON publisher_audit_events (publisher_id, created_at DESC);
CREATE INDEX publisher_audit_events_actor_time_idx
    ON publisher_audit_events (actor_account_id, created_at DESC)
    WHERE actor_account_id IS NOT NULL;

ALTER TABLE packs
    ADD COLUMN publisher_id UUID REFERENCES publisher_profiles(id);
CREATE INDEX packs_publisher_id_idx ON packs (publisher_id) WHERE publisher_id IS NOT NULL;

ALTER TABLE pack_versions
    ADD COLUMN publisher_key_id UUID REFERENCES publisher_keys(id);
CREATE INDEX pack_versions_publisher_key_id_idx
    ON pack_versions (publisher_key_id) WHERE publisher_key_id IS NOT NULL;

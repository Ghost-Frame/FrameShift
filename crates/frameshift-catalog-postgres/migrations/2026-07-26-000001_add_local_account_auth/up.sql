-- Expand-only first-party credential and revocable-session substrate.
-- No route consumes these tables until recovery and abuse controls are ready.

CREATE TABLE account_password_credentials (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    normalized_email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_version SMALLINT NOT NULL DEFAULT 1 CHECK (password_version > 0),
    pepper_version SMALLINT NOT NULL CHECK (pepper_version > 0),
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_password_email_normalized CHECK (
        normalized_email = lower(btrim(normalized_email))
    ),
    CONSTRAINT account_password_email_not_blank CHECK (normalized_email <> ''),
    CONSTRAINT account_password_email_length CHECK (
        octet_length(normalized_email) <= 320
    ),
    CONSTRAINT account_password_hash_phc CHECK (
        password_hash LIKE '$argon2id$%'
        AND octet_length(password_hash) <= 512
    ),
    CONSTRAINT account_password_timestamps_consistent CHECK (
        password_changed_at >= created_at
        AND updated_at >= created_at
        AND (email_verified_at IS NULL OR email_verified_at >= created_at)
    )
);

CREATE TABLE account_sessions (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    token_digest BYTEA NOT NULL UNIQUE,
    client_kind TEXT NOT NULL CHECK (client_kind IN ('browser', 'desktop', 'cli')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT account_session_token_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT account_session_expiry_order CHECK (
        last_seen_at >= created_at
        AND last_seen_at <= absolute_expires_at
        AND idle_expires_at > created_at
        AND absolute_expires_at >= idle_expires_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE INDEX account_sessions_active_account_idx
    ON account_sessions (account_id, absolute_expires_at)
    WHERE revoked_at IS NULL;

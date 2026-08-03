-- Expand-only first-party authentication hardening substrate.
-- Raw access, refresh, MFA, recovery, challenge, and authorization-code
-- secrets never enter these tables. Callers persist only SHA-256 digests or
-- authenticated ciphertext produced under deployment-managed keys.

ALTER TABLE account_sessions
    ADD COLUMN access_expires_at TIMESTAMPTZ;

UPDATE account_sessions
SET access_expires_at = LEAST(idle_expires_at, absolute_expires_at);

ALTER TABLE account_sessions
    ALTER COLUMN access_expires_at SET NOT NULL,
    ADD COLUMN mfa_verified_at TIMESTAMPTZ,
    ADD CONSTRAINT account_session_access_expiry_order CHECK (
        access_expires_at > created_at
        AND access_expires_at <= absolute_expires_at
    ),
    ADD CONSTRAINT account_session_mfa_time_order CHECK (
        mfa_verified_at IS NULL OR mfa_verified_at <= last_seen_at
    );

COMMENT ON COLUMN account_sessions.token_digest IS
    'SHA-256 digest of the current short-lived access token';

CREATE INDEX account_sessions_active_access_idx
    ON account_sessions (token_digest, access_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE account_session_refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES account_sessions(id),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    token_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT account_refresh_token_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT account_refresh_token_generation_unique UNIQUE (
        session_id,
        generation
    ),
    CONSTRAINT account_refresh_token_time_order CHECK (
        expires_at > created_at
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    )
);

CREATE INDEX account_refresh_token_session_history_idx
    ON account_session_refresh_tokens (session_id, generation DESC);

CREATE TABLE account_mfa_authenticators (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'disabled')),
    secret_ciphertext BYTEA NOT NULL,
    secret_nonce BYTEA NOT NULL,
    secret_key_version SMALLINT NOT NULL CHECK (secret_key_version > 0),
    pending_expires_at TIMESTAMPTZ,
    last_used_timestep BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    CONSTRAINT account_mfa_ciphertext_bounded CHECK (
        octet_length(secret_ciphertext) BETWEEN 16 AND 4096
    ),
    CONSTRAINT account_mfa_nonce_length CHECK (
        octet_length(secret_nonce) = 24
    ),
    CONSTRAINT account_mfa_state_shape CHECK (
        (
            state = 'pending'
            AND pending_expires_at > created_at
            AND activated_at IS NULL
            AND disabled_at IS NULL
            AND last_used_timestep IS NULL
        ) OR (
            state = 'active'
            AND pending_expires_at IS NULL
            AND activated_at IS NOT NULL
            AND activated_at >= created_at
            AND disabled_at IS NULL
        ) OR (
            state = 'disabled'
            AND pending_expires_at IS NULL
            AND disabled_at IS NOT NULL
            AND disabled_at >= created_at
        )
    )
);

CREATE UNIQUE INDEX account_mfa_one_pending_idx
    ON account_mfa_authenticators (account_id)
    WHERE state = 'pending';

CREATE UNIQUE INDEX account_mfa_one_active_idx
    ON account_mfa_authenticators (account_id)
    WHERE state = 'active';

CREATE TABLE account_mfa_recovery_codes (
    id UUID PRIMARY KEY,
    authenticator_id UUID NOT NULL REFERENCES account_mfa_authenticators(id),
    code_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT account_mfa_recovery_digest_length CHECK (
        octet_length(code_digest) = 32
    ),
    CONSTRAINT account_mfa_recovery_time_order CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    )
);

CREATE INDEX account_mfa_recovery_authenticator_idx
    ON account_mfa_recovery_codes (authenticator_id, consumed_at);

CREATE TABLE account_mfa_login_challenges (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    token_digest BYTEA NOT NULL UNIQUE,
    client_kind TEXT NOT NULL CHECK (client_kind IN ('browser', 'desktop', 'cli')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT account_mfa_challenge_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT account_mfa_challenge_time_order CHECK (
        expires_at > created_at
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    )
);

CREATE INDEX account_mfa_challenge_account_idx
    ON account_mfa_login_challenges (account_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE account_native_authorization_codes (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    token_digest BYTEA NOT NULL UNIQUE,
    client_kind TEXT NOT NULL CHECK (client_kind IN ('desktop', 'cli')),
    redirect_uri TEXT NOT NULL,
    pkce_challenge BYTEA NOT NULL,
    mfa_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT account_native_code_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT account_native_code_pkce_length CHECK (
        octet_length(pkce_challenge) = 32
    ),
    CONSTRAINT account_native_code_redirect_bounded CHECK (
        char_length(redirect_uri) BETWEEN 1 AND 2048
    ),
    CONSTRAINT account_native_code_time_order CHECK (
        expires_at > created_at
        AND (mfa_verified_at IS NULL OR mfa_verified_at <= created_at)
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    )
);

CREATE INDEX account_native_code_account_idx
    ON account_native_authorization_codes (account_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE account_auth_audit_events (
    id UUID PRIMARY KEY,
    event_kind TEXT NOT NULL CHECK (event_kind IN (
        'session_created',
        'session_refreshed',
        'session_replay_revoked',
        'mfa_enrollment_started',
        'mfa_enrollment_activated',
        'mfa_disabled',
        'mfa_challenge_created',
        'mfa_challenge_completed',
        'native_authorization_code_created',
        'native_authorization_code_consumed',
        'authentication_rejected'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'rejected')),
    account_id UUID REFERENCES accounts(id),
    session_id UUID REFERENCES account_sessions(id),
    client_kind TEXT CHECK (client_kind IN ('browser', 'desktop', 'cli')),
    identifier_tag BYTEA,
    network_tag BYTEA,
    reason_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT account_auth_audit_identifier_tag_length CHECK (
        identifier_tag IS NULL OR octet_length(identifier_tag) = 32
    ),
    CONSTRAINT account_auth_audit_network_tag_length CHECK (
        network_tag IS NULL OR octet_length(network_tag) = 32
    ),
    CONSTRAINT account_auth_audit_reason_code_shape CHECK (
        reason_code IS NULL
        OR reason_code ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'
    )
);

CREATE INDEX account_auth_audit_account_time_idx
    ON account_auth_audit_events (account_id, created_at DESC, id);

CREATE INDEX account_auth_audit_kind_time_idx
    ON account_auth_audit_events (event_kind, created_at DESC, id);

CREATE FUNCTION reject_account_auth_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'account authentication audit events are immutable';
END
$$;

CREATE TRIGGER account_auth_audit_events_immutable
BEFORE UPDATE OR DELETE ON account_auth_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_account_auth_audit_event_mutation();

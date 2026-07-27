CREATE TABLE account_invites (
    id UUID PRIMARY KEY,
    request_id UUID UNIQUE REFERENCES account_invite_requests(id),
    normalized_email TEXT NOT NULL,
    token_digest BYTEA NOT NULL UNIQUE,
    issued_by_account_id UUID REFERENCES accounts(id),
    is_bootstrap BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_invites_token_digest_len CHECK (octet_length(token_digest) = 32),
    CONSTRAINT account_invites_email_normalized CHECK (
        normalized_email = lower(btrim(normalized_email))
        AND normalized_email LIKE '%@%'
        AND char_length(normalized_email) BETWEEN 3 AND 320
    ),
    CONSTRAINT account_invites_authority_shape CHECK (
        (is_bootstrap AND request_id IS NULL AND issued_by_account_id IS NULL)
        OR
        (NOT is_bootstrap AND request_id IS NOT NULL AND issued_by_account_id IS NOT NULL)
    ),
    CONSTRAINT account_invites_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT account_invites_consumption_after_creation CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    ),
    CONSTRAINT account_invites_revocation_after_creation CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    ),
    CONSTRAINT account_invites_terminal_state_exclusive CHECK (
        consumed_at IS NULL OR revoked_at IS NULL
    )
);

CREATE INDEX account_invites_active_digest_idx
    ON account_invites (token_digest, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX account_invites_email_created_idx
    ON account_invites (normalized_email, created_at DESC);

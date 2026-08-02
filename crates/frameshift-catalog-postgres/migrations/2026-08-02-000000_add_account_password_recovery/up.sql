-- Add digest-only reset tokens and an encrypted, lease-driven delivery outbox.

CREATE TABLE account_password_recovery_tokens (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account_password_credentials(account_id) ON DELETE CASCADE,
    token_digest BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT account_password_recovery_token_digest_length CHECK (
        octet_length(token_digest) = 32
    ),
    CONSTRAINT account_password_recovery_token_expiry_order CHECK (
        expires_at > created_at
    ),
    CONSTRAINT account_password_recovery_token_consumption_order CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    ),
    CONSTRAINT account_password_recovery_token_revocation_order CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    ),
    CONSTRAINT account_password_recovery_token_terminal_exclusive CHECK (
        consumed_at IS NULL OR revoked_at IS NULL
    )
);

CREATE UNIQUE INDEX account_password_recovery_tokens_one_active_account_idx
    ON account_password_recovery_tokens (account_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX account_password_recovery_tokens_active_digest_idx
    ON account_password_recovery_tokens (token_digest, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX account_password_recovery_tokens_account_created_idx
    ON account_password_recovery_tokens (account_id, created_at DESC);

CREATE TABLE account_password_recovery_outbox (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account_password_credentials(account_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('reset', 'password_changed')),
    recipient TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    key_version SMALLINT NOT NULL CHECK (key_version > 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        attempt_count BETWEEN 0 AND 1000
    ),
    last_attempt_at TIMESTAMPTZ,
    claim_id UUID,
    claimed_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ,
    provider_message_id TEXT,
    failed_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT account_password_recovery_outbox_recipient_normalized CHECK (
        recipient = lower(btrim(recipient))
        AND recipient LIKE '%@%'
        AND char_length(recipient) BETWEEN 3 AND 320
    ),
    CONSTRAINT account_password_recovery_outbox_ciphertext_length CHECK (
        octet_length(ciphertext) BETWEEN 16 AND 262144
    ),
    CONSTRAINT account_password_recovery_outbox_nonce_length CHECK (
        octet_length(nonce) = 24
    ),
    CONSTRAINT account_password_recovery_outbox_expiry_order CHECK (
        next_attempt_at >= created_at
        AND next_attempt_at < expires_at
    ),
    CONSTRAINT account_password_recovery_outbox_attempt_shape CHECK (
        (attempt_count = 0 AND last_attempt_at IS NULL)
        OR (attempt_count > 0 AND last_attempt_at IS NOT NULL)
    ),
    CONSTRAINT account_password_recovery_outbox_claim_shape CHECK (
        (claim_id IS NULL AND claimed_at IS NULL)
        OR (
            claim_id IS NOT NULL
            AND claimed_at IS NOT NULL
            AND claimed_at = last_attempt_at
            AND claimed_at < expires_at
        )
    ),
    CONSTRAINT account_password_recovery_outbox_terminal_exclusive CHECK (
        sent_at IS NULL OR failed_at IS NULL
    ),
    CONSTRAINT account_password_recovery_outbox_terminal_claim_released CHECK (
        (sent_at IS NULL AND failed_at IS NULL)
        OR (claim_id IS NULL AND claimed_at IS NULL)
    ),
    CONSTRAINT account_password_recovery_outbox_provider_id_shape CHECK (
        (sent_at IS NULL AND provider_message_id IS NULL)
        OR (
            sent_at IS NOT NULL
            AND provider_message_id IS NOT NULL
            AND provider_message_id = btrim(provider_message_id)
            AND octet_length(provider_message_id) BETWEEN 1 AND 256
            AND provider_message_id !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT account_password_recovery_outbox_error_code_shape CHECK (
        last_error_code IS NULL
        OR last_error_code ~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'
    ),
    CONSTRAINT account_password_recovery_outbox_failure_has_code CHECK (
        failed_at IS NULL OR last_error_code IS NOT NULL
    ),
    CONSTRAINT account_password_recovery_outbox_timestamp_order CHECK (
        expires_at > created_at
        AND (last_attempt_at IS NULL OR last_attempt_at >= created_at)
        AND (sent_at IS NULL OR sent_at >= created_at)
        AND (failed_at IS NULL OR failed_at >= created_at)
    )
);

CREATE INDEX account_password_recovery_outbox_ready_idx
    ON account_password_recovery_outbox (next_attempt_at, expires_at, created_at, id)
    WHERE sent_at IS NULL AND failed_at IS NULL;

CREATE INDEX account_password_recovery_outbox_stale_claim_idx
    ON account_password_recovery_outbox (claimed_at, next_attempt_at, id)
    WHERE sent_at IS NULL AND failed_at IS NULL AND claim_id IS NOT NULL;

CREATE INDEX account_password_recovery_outbox_account_created_idx
    ON account_password_recovery_outbox (account_id, created_at DESC);

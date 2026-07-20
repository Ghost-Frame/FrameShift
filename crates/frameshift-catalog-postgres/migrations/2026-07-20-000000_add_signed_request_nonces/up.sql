-- Shared nonce claims close signed-request replay across server instances.
CREATE TABLE signed_request_nonces (
    pubkey      BYTEA       NOT NULL CHECK (octet_length(pubkey) = 32),
    nonce       TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (pubkey, nonce)
);

CREATE INDEX idx_signed_request_nonces_expires_at
    ON signed_request_nonces (expires_at);

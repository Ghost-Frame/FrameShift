-- Remove encrypted recovery delivery state before its digest-only token source.

DROP
    TABLE account_password_recovery_outbox;
DROP
    TABLE account_password_recovery_tokens;

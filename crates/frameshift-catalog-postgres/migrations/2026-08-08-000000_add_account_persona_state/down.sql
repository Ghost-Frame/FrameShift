-- Reverse the account-scoped cloud persona state migration in dependency order.
-- This explicit rollback destroys connector state and replay evidence and is
-- intended only for controlled migration rollback, never runtime account removal.

-- Growth depends on both exact installations and immutable operation evidence.
DROP TRIGGER account_persona_growth_entries_no_truncate
    ON account_persona_growth_entries;
DROP TRIGGER account_persona_growth_entries_immutable
    ON account_persona_growth_entries;
DROP FUNCTION reject_account_persona_growth_mutation();
DROP
    TABLE account_persona_growth_entries;

-- Remove the immutability boundary before dropping its owning operation table.
DROP TRIGGER account_persona_operations_no_truncate
    ON account_persona_operations;
DROP TRIGGER account_persona_operations_immutable
    ON account_persona_operations;
DROP FUNCTION reject_account_persona_operation_mutation();
DROP
    TABLE account_persona_operations;

-- Mutable account-owned projections reverse after immutable evidence is gone.
DROP
    TABLE account_persona_preferences;
DROP
    TABLE account_active_personas;
DROP
    TABLE account_persona_installations;
DROP
    TABLE account_persona_state;

-- Remove the exact catalog identity key only after all referencing rows are gone.
ALTER TABLE pack_versions
    DROP CONSTRAINT pack_versions_exact_content_unique;

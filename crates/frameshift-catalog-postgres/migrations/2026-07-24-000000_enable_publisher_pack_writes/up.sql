-- Publisher signing keys are first-class pack authorities. Their raw public
-- key remains in the historical author_pubkey columns, while publisher_key_id
-- provides the referential link for account-backed writes.

ALTER TABLE packs
    DROP CONSTRAINT packs_current_author_fkey,
    ADD CONSTRAINT packs_current_author_length
        CHECK (octet_length(current_author) = 32);

ALTER TABLE pack_versions
    DROP CONSTRAINT pack_versions_author_pubkey_fkey,
    ADD CONSTRAINT pack_versions_author_pubkey_length
        CHECK (octet_length(author_pubkey) = 32);

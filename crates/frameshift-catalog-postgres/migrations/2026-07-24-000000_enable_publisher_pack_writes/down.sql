ALTER TABLE pack_versions
    DROP CONSTRAINT pack_versions_author_pubkey_length,
    ADD CONSTRAINT pack_versions_author_pubkey_fkey
        FOREIGN KEY (author_pubkey) REFERENCES authors(pubkey) NOT VALID;

ALTER TABLE packs
    DROP CONSTRAINT packs_current_author_length,
    ADD CONSTRAINT packs_current_author_fkey
        FOREIGN KEY (current_author) REFERENCES authors(pubkey) NOT VALID;

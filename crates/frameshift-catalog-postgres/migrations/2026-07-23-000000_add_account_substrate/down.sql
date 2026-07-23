DROP INDEX IF EXISTS pack_versions_publisher_key_id_idx;
ALTER TABLE pack_versions DROP COLUMN IF EXISTS publisher_key_id;

DROP INDEX IF EXISTS packs_publisher_id_idx;
ALTER TABLE packs DROP COLUMN IF EXISTS publisher_id;

DROP TABLE IF EXISTS publisher_audit_events;
DROP TABLE IF EXISTS publisher_keys;
DROP TABLE IF EXISTS publisher_memberships;
DROP TABLE IF EXISTS publisher_profiles;
DROP TABLE IF EXISTS accounts;

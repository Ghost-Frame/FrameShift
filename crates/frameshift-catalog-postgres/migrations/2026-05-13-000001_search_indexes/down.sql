-- Reverse of 2026-05-13-000001_search_indexes/up.sql.

DROP INDEX IF EXISTS idx_packs_fts;
DROP INDEX IF EXISTS idx_packs_tags_gin;
DROP INDEX IF EXISTS idx_packs_downloads;
DROP INDEX IF EXISTS idx_pack_versions_published;
DROP INDEX IF EXISTS idx_pack_versions_author;

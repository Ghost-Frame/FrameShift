-- Search and sort indexes for the frameshift catalog.
--
-- These indexes are separated from the schema migration so that the base tables
-- can be created quickly in test environments before the slower GIN index builds.

-- Fast lookup of all versions published by a given author.
CREATE INDEX idx_pack_versions_author ON pack_versions(author_pubkey);

-- Efficient sort of versions by publication date (newest first).
CREATE INDEX idx_pack_versions_published ON pack_versions(published_at DESC);

-- Efficient sort of packs by total download count (most downloaded first).
CREATE INDEX idx_packs_downloads ON packs(total_downloads DESC);

-- GIN index for array containment queries on tags (e.g. tags @> ARRAY['roleplay']).
CREATE INDEX idx_packs_tags_gin ON packs USING GIN (tags);

-- GIN index for full-text search over pack name and description.
-- Uses the 'english' dictionary for stemming and stop-word removal.
-- Query side uses plainto_tsquery('english', ?) to safely handle user input.
CREATE INDEX idx_packs_fts ON packs USING GIN (to_tsvector('english', description || ' ' || name));

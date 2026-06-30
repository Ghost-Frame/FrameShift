-- Audit table for individual download events, used to compute trending velocity.
--
-- Each row records a single download of a specific pack version. The trending
-- sort mode in `search_packs` counts rows in this table within a rolling 7-day
-- window to rank packs by recent activity rather than all-time totals.
--
-- No foreign key to `packs` is intentional: download events may arrive for
-- versions that are later tombstoned, and we do not want orphaned downloads to
-- block cleanup. The application layer validates pack existence before inserting.

CREATE TABLE pack_downloads (
    -- Surrogate primary key; bigserial to accommodate high download volumes.
    id              BIGSERIAL    NOT NULL PRIMARY KEY,
    -- Name of the pack that was downloaded; matches packs.name but no FK constraint.
    pack_name       TEXT         NOT NULL,
    -- Semver version string that was downloaded.
    version         TEXT         NOT NULL,
    -- UTC timestamp of the download event; defaults to current time.
    downloaded_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Composite index on (pack_name, downloaded_at) supports the trending query:
--   SELECT pack_name, COUNT(*) FROM pack_downloads
--   WHERE downloaded_at >= NOW() - INTERVAL '7 days'
--   GROUP BY pack_name
-- Postgres can satisfy both the WHERE filter and the GROUP BY key from this index.
CREATE INDEX idx_pack_downloads_name_ts
    ON pack_downloads (pack_name, downloaded_at);

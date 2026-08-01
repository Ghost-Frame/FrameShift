-- Support stable bounded version-history reads without sorting every pack row.
CREATE INDEX idx_pack_versions_pack_published_version
    ON pack_versions (pack_name, published_at, version);

DROP TABLE IF EXISTS pack_telemetry;
ALTER TABLE pack_versions DROP COLUMN IF EXISTS conformance_bundle_hash;
ALTER TABLE pack_versions DROP COLUMN IF EXISTS conformance_score;

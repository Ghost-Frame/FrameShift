-- Conformance score embedded from the pack's signed conformance_baseline.
ALTER TABLE pack_versions ADD COLUMN conformance_score REAL;
ALTER TABLE pack_versions ADD COLUMN conformance_bundle_hash TEXT;

-- Templated telemetry signals, accumulated per pack + version.
-- signal_kind: 'selection_count' | 'auto_select_count' | 'conformance_score'
--            | 'rule_cited' | 'skill_friction' (extensible; server validates the set)
-- signal_key: rule id / skill name / bundle hash / '' for whole-pack counters.
CREATE TABLE pack_telemetry (
    pack_name   TEXT             NOT NULL REFERENCES packs(name),
    version     TEXT             NOT NULL DEFAULT '',
    signal_kind TEXT             NOT NULL,
    signal_key  TEXT             NOT NULL DEFAULT '',
    count       BIGINT           NOT NULL DEFAULT 0,
    value       DOUBLE PRECISION,
    updated_at  TIMESTAMPTZ      NOT NULL DEFAULT now(),
    PRIMARY KEY (pack_name, version, signal_kind, signal_key)
);
CREATE INDEX pack_telemetry_pack_idx ON pack_telemetry (pack_name);

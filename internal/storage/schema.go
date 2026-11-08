package storage

type migration struct {
	Version     int
	Description string
	SQL         string
}

// migrations lists versioned schema migrations in ascending order.
var migrations = []migration{
	{
		Version:     1,
		Description: "initial schema: scans and scan_reports with indexes",
		SQL: `
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    overall_score INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT '',
    policy_id TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'completed',
    schema_version TEXT NOT NULL DEFAULT 'bouclier-risk/v1',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_reports (
    scan_id TEXT PRIMARY KEY,
    report_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);
CREATE INDEX IF NOT EXISTS idx_scans_overall_score ON scans(overall_score);
`,
	},
	{
		Version:     2,
		Description: "threat intelligence schema: sources, indicators, and sync runs",
		SQL: `
CREATE TABLE IF NOT EXISTS intel_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    update_interval_seconds INTEGER NOT NULL DEFAULT 86400,
    attribution TEXT NOT NULL DEFAULT '',
    license TEXT NOT NULL DEFAULT '',
    format TEXT NOT NULL DEFAULT 'json',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_sync_runs (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'success',
    imported_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (source_id) REFERENCES intel_sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intel_indicators (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL DEFAULT '',
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'threat-intelligence',
    confidence INTEGER NOT NULL DEFAULT 80,
    severity TEXT NOT NULL DEFAULT 'high',
    first_seen TEXT,
    last_seen TEXT,
    expires_at TEXT,
    ingested_at TEXT NOT NULL,
    source_ref TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (source_id) REFERENCES intel_sources(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_intel_ind_source_val ON intel_indicators(source_id, indicator_type, value);
CREATE INDEX IF NOT EXISTS idx_intel_ind_lookup ON intel_indicators(indicator_type, value);
CREATE INDEX IF NOT EXISTS idx_intel_ind_expires ON intel_indicators(expires_at);
CREATE INDEX IF NOT EXISTS idx_intel_ind_category ON intel_indicators(category);
CREATE INDEX IF NOT EXISTS idx_intel_sync_source ON intel_sync_runs(source_id, started_at DESC);
`,
	},
	{
		Version:     3,
		Description: "persist SHA-256 integrity digests for scan reports",
		SQL:         `ALTER TABLE scan_reports ADD COLUMN report_hash TEXT NOT NULL DEFAULT '';`,
	},
	{
		Version:     4,
		Description: "add auth_header to intel_sources (legacy)",
		SQL:         `ALTER TABLE intel_sources ADD COLUMN auth_header TEXT NOT NULL DEFAULT '';`,
	},
	{
		Version:     5,
		Description: "replace plaintext auth_header with auth_header_env reference and purge plaintext secrets",
		SQL: `
ALTER TABLE intel_sources ADD COLUMN auth_header_env TEXT NOT NULL DEFAULT '';
UPDATE intel_sources SET auth_header = '';
ALTER TABLE intel_sources DROP COLUMN auth_header;
`,
	},
	{
		Version:     6,
		Description: "store external report registry commitments",
		SQL: `
CREATE TABLE scan_report_anchors (
    scan_id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    transaction_hash TEXT NOT NULL DEFAULT '',
    report_hash TEXT NOT NULL,
    risk_level INTEGER NOT NULL,
    anchored_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
`,
	},
}

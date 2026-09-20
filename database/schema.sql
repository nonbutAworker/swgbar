-- SWGBar SQLite Schema DDL
-- SQLite schema for persistent application data.
-- Enable WAL, foreign keys, and supporting indexes.

PRAGMA foreign_keys = ON;

-- 1. Schema migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
);

-- 2. Network epochs
CREATE TABLE IF NOT EXISTS network_epochs (
    id TEXT PRIMARY KEY,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER,
    route_digest TEXT NOT NULL,
    name TEXT NOT NULL
);

-- 3. Capture sessions
CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    generation INTEGER NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER
);

-- 4. Source applications
CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    bundle_id TEXT,
    team_id TEXT,
    display_name TEXT,
    app_path_cipher BLOB,
    uid INTEGER NOT NULL
);

-- 5. Normalized targets with encrypted hostnames
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    host_hmac TEXT NOT NULL UNIQUE,
    host_cipher BLOB NOT NULL,
    port INTEGER NOT NULL,
    is_ip_only INTEGER NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS targets_port_idx ON targets(port);

-- 6. Observations: the core evidence records
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    source_instance_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('system_flow', 'native_probe', 'browser_request')),
    object_kind TEXT NOT NULL,
    generation INTEGER NOT NULL,
    epoch_id TEXT NOT NULL REFERENCES network_epochs(id),
    target_id TEXT REFERENCES targets(id),
    observed_at_ms INTEGER NOT NULL,
    stage TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    request_key TEXT,
    probe_job_id TEXT,
    remote_ip_cipher BLOB,
    proxy_endpoint TEXT,
    app_id TEXT REFERENCES applications(id),
    is_own_traffic INTEGER NOT NULL DEFAULT 0,
    loss_context TEXT,
    egress_interface TEXT,
    route_type TEXT,
    UNIQUE(source_instance_id, request_key)
);
CREATE INDEX IF NOT EXISTS observations_window_idx ON observations(epoch_id, source, observed_at_ms DESC);
CREATE INDEX IF NOT EXISTS observations_target_idx ON observations(target_id, observed_at_ms DESC);

-- 7. Transport deduplication and idempotency
CREATE TABLE IF NOT EXISTS ingest_dedup (
    source_instance TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    received_at_ms INTEGER NOT NULL,
    PRIMARY KEY(source_instance, sequence)
);

-- 8. Certificates and public-key fingerprints
CREATE TABLE IF NOT EXISTS certificates (
    cert_id TEXT PRIMARY KEY, -- SHA256(DER)
    spki_id TEXT NOT NULL,   -- SHA256(RawSubjectPublicKeyInfo)
    der_cipher BLOB NOT NULL,
    san_cipher BLOB,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before_ms INTEGER NOT NULL,
    not_after_ms INTEGER NOT NULL,
    is_ca INTEGER NOT NULL DEFAULT 0,
    key_usage TEXT,
    signature_algorithm TEXT,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS certificates_spki_idx ON certificates(spki_id);

-- 9. Observation-to-certificate associations for presented and validated chains
CREATE TABLE IF NOT EXISTS observation_certificates (
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
    role TEXT NOT NULL CHECK(role IN ('leaf', 'intermediate', 'root')),
    chain_type TEXT NOT NULL CHECK(chain_type IN ('presented', 'verified')),
    ordinal INTEGER NOT NULL,
    PRIMARY KEY(observation_id, chain_type, ordinal)
);

-- 10. Native and public trust evaluation records
CREATE TABLE IF NOT EXISTS trust_evaluations (
    id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    engine TEXT NOT NULL CHECK(engine IN ('native_apple', 'go_pkix')),
    result TEXT NOT NULL CHECK(result IN ('accepted', 'rejected', 'error')),
    error_code TEXT,
    verified_path_json TEXT,
    baseline_version TEXT,
    evaluated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS trust_evaluations_obs_idx ON trust_evaluations(observation_id);

-- 11. Immutable classification revisions
CREATE TABLE IF NOT EXISTS classifications (
    id TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    verdict TEXT NOT NULL CHECK(verdict IN ('confirmed_inspection', 'suspected_inspection', 'public_path', 'expected_private', 'unknown', 'excluded')),
    reason TEXT NOT NULL,
    classified_at_ms INTEGER NOT NULL,
    UNIQUE(observation_id, revision)
);
CREATE INDEX IF NOT EXISTS classifications_obs_rev_idx ON classifications(observation_id, revision DESC);

-- View of the latest classification for each observation
CREATE VIEW IF NOT EXISTS current_classifications AS
SELECT c.*
FROM classifications c
INNER JOIN (
    SELECT observation_id, MAX(revision) AS max_revision
    FROM classifications
    GROUP BY observation_id
) m ON c.observation_id = m.observation_id AND c.revision = m.max_revision;

-- 12. CA clusters
CREATE TABLE IF NOT EXISTS ca_clusters (
    id TEXT PRIMARY KEY,
    ca_key_id TEXT NOT NULL UNIQUE,
    ca_name TEXT NOT NULL,
    identity_kind TEXT NOT NULL CHECK(identity_kind IN ('inspection', 'suspected', 'public', 'expected_private', 'direct_leaf')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

-- 13. Cluster-to-certificate associations
CREATE TABLE IF NOT EXISTS cluster_certificates (
    cluster_id TEXT NOT NULL REFERENCES ca_clusters(id) ON DELETE CASCADE,
    cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
    PRIMARY KEY(cluster_id, cert_id)
);

-- 14. Rules
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('inspection_ca', 'expected_private', 'probe_exclude', 'capture_exclude', 'intranet_allowed')),
    match_type TEXT NOT NULL CHECK(match_type IN ('cert_fingerprint', 'ca_spki', 'domain_exact', 'domain_suffix')),
    match_value TEXT NOT NULL,
    domain_scope TEXT,
    app_scope TEXT,
    origin TEXT NOT NULL CHECK(origin IN ('user', 'config', 'system')),
    explanation TEXT NOT NULL,
    expires_at_ms INTEGER,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rules_lookup_idx ON rules(kind, match_type, match_value);

-- 15. Asynchronous probe tasks
CREATE TABLE IF NOT EXISTS probe_jobs (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id),
    state TEXT NOT NULL CHECK(state IN ('queued', 'resolving', 'connecting', 'tunneling', 'handshaking', 'evaluating', 'completed', 'failed', 'cancelled')),
    deadline_ms INTEGER NOT NULL,
    error TEXT,
    created_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS probe_jobs_state_idx ON probe_jobs(state, deadline_ms);

-- 16. Timeline and audit events
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    time_ms INTEGER NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time_idx ON events(time_ms DESC);

-- 17. Historical snapshot metrics
CREATE TABLE IF NOT EXISTS metric_snapshots (
    id TEXT PRIMARY KEY,
    metric_kind TEXT NOT NULL,
    epoch_id TEXT NOT NULL REFERENCES network_epochs(id),
    window_seconds INTEGER NOT NULL,
    generated_at_ms INTEGER NOT NULL,
    counts_json TEXT NOT NULL,
    partial INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS metric_snapshots_epoch_idx ON metric_snapshots(epoch_id, metric_kind, generated_at_ms DESC);

-- 18. Coverage and gap intervals
CREATE TABLE IF NOT EXISTS coverage_intervals (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL,
    loss INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL
);

-- 19. Configuration with optimistic revision locking
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
);

-- 20. Idempotent operation receipts
CREATE TABLE IF NOT EXISTS command_receipts (
    operation_id TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS command_receipts_expires_idx ON command_receipts(expires_at_ms);

-- Indexes accelerate request-count sorting, CA clustering, and certificate chain joins.
CREATE INDEX IF NOT EXISTS targets_req_count_idx ON targets(request_count DESC);
CREATE INDEX IF NOT EXISTS cluster_certs_idx ON cluster_certificates(cluster_id, cert_id);
CREATE INDEX IF NOT EXISTS obs_certs_cert_id_idx ON observation_certificates(cert_id);

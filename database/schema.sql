-- SWGBar SQLite Schema DDL
-- 遵循技术方案 v1.1 第 31-32 章
-- 启用 WAL、外键与索引优化

PRAGMA foreign_keys = ON;

-- 1. 迁移记录表
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at_ms INTEGER NOT NULL
);

-- 2. 网络阶段表
CREATE TABLE IF NOT EXISTS network_epochs (
    id TEXT PRIMARY KEY,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER,
    route_digest TEXT NOT NULL,
    name TEXT NOT NULL
);

-- 3. 采集会话表
CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    generation INTEGER NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER
);

-- 4. 来源应用表
CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    bundle_id TEXT,
    team_id TEXT,
    display_name TEXT,
    app_path_cipher BLOB,
    uid INTEGER NOT NULL
);

-- 5. 目标表 (规范域名与加密存储)
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

-- 6. 业务观察表 (核心事实表)
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

-- 7. 传输去重表 (幂等处理)
CREATE TABLE IF NOT EXISTS ingest_dedup (
    source_instance TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    received_at_ms INTEGER NOT NULL,
    PRIMARY KEY(source_instance, sequence)
);

-- 8. 证书实体表 (证书去重与公钥指纹)
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

-- 9. 观察与证书关联表 (呈现链与验证链)
CREATE TABLE IF NOT EXISTS observation_certificates (
    observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
    role TEXT NOT NULL CHECK(role IN ('leaf', 'intermediate', 'root')),
    chain_type TEXT NOT NULL CHECK(chain_type IN ('presented', 'verified')),
    ordinal INTEGER NOT NULL,
    PRIMARY KEY(observation_id, chain_type, ordinal)
);

-- 10. 双轨信任验证记录表
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

-- 11. 不可变分类修订表
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

-- 视图：获取最新分类结果
CREATE VIEW IF NOT EXISTS current_classifications AS
SELECT c.*
FROM classifications c
INNER JOIN (
    SELECT observation_id, MAX(revision) AS max_revision
    FROM classifications
    GROUP BY observation_id
) m ON c.observation_id = m.observation_id AND c.revision = m.max_revision;

-- 12. CA 聚类表
CREATE TABLE IF NOT EXISTS ca_clusters (
    id TEXT PRIMARY KEY,
    ca_key_id TEXT NOT NULL UNIQUE,
    ca_name TEXT NOT NULL,
    identity_kind TEXT NOT NULL CHECK(identity_kind IN ('inspection', 'suspected', 'public', 'expected_private', 'direct_leaf')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

-- 13. CA 聚类与证书关联表
CREATE TABLE IF NOT EXISTS cluster_certificates (
    cluster_id TEXT NOT NULL REFERENCES ca_clusters(id) ON DELETE CASCADE,
    cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
    PRIMARY KEY(cluster_id, cert_id)
);

-- 14. 规则表
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

-- 15. 异步探测任务表
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

-- 16. UI 时间线与审计事件表
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    time_ms INTEGER NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time_idx ON events(time_ms DESC);

-- 17. 历史快照统计表
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

-- 18. 覆盖与断流区间表
CREATE TABLE IF NOT EXISTS coverage_intervals (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL,
    loss INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL
);

-- 19. 配置表 (乐观锁 revision)
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
);

-- 20. 幂等操作回执表
CREATE TABLE IF NOT EXISTS command_receipts (
    operation_id TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS command_receipts_expires_idx ON command_receipts(expires_at_ms);

-- 性能优化索引：加速按请求次数排序、CA 聚类与证书链关联
CREATE INDEX IF NOT EXISTS targets_req_count_idx ON targets(request_count DESC);
CREATE INDEX IF NOT EXISTS cluster_certs_idx ON cluster_certificates(cluster_id, cert_id);
CREATE INDEX IF NOT EXISTS obs_certs_cert_id_idx ON observation_certificates(cert_id);

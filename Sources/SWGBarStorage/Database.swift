//
// SWGBar / macOS menu bar TLS inspection detector
// SQLite database engine (Database.swift)
// Single-writer storage with WAL, foreign keys, timeouts, and immutable snapshot reads.
//

import Foundation
import SQLite3
import SWGBarContracts

public final class SQLiteDatabase: @unchecked Sendable {
    private var db: OpaquePointer?
    private let lock = NSRecursiveLock()
    private let path: String

    private var cachedStatements: [String: OpaquePointer] = [:]

    public init(path: String) throws {
        self.path = path
        var handle: OpaquePointer?
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        if sqlite3_open_v2(path, &handle, flags, nil) != SQLITE_OK {
            let errMsg = String(cString: sqlite3_errmsg(handle))
            sqlite3_close(handle)
            throw DatabaseError.openFailed(errMsg)
        }
        self.db = handle

        try configurePragmas()
        try createSchemaIfNeeded()
    }

    public static func inMemory() throws -> SQLiteDatabase {
        return try SQLiteDatabase(path: ":memory:")
    }

    deinit {
        for (_, stmt) in cachedStatements {
            sqlite3_finalize(stmt)
        }
        if let db = db {
            sqlite3_close(db)
        }
    }

    // MARK: - PRAGMA configuration

    private func configurePragmas() throws {
        try execute(sql: "PRAGMA foreign_keys = ON;")
        if path != ":memory:" {
            try execute(sql: "PRAGMA journal_mode = WAL;")
            try execute(sql: "PRAGMA synchronous = NORMAL;")
            try execute(sql: "PRAGMA cache_size = -8000;") // 8 MB page cache
            try execute(sql: "PRAGMA temp_store = MEMORY;")
        }
        try execute(sql: "PRAGMA busy_timeout = 5000;")
    }

    // MARK: - Schema initialization and migration

    private func createSchemaIfNeeded() throws {
        let ddl = """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            checksum TEXT NOT NULL,
            applied_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_epochs (
            id TEXT PRIMARY KEY,
            start_ms INTEGER NOT NULL,
            end_ms INTEGER,
            route_digest TEXT NOT NULL,
            name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capture_sessions (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            generation INTEGER NOT NULL,
            started_at_ms INTEGER NOT NULL,
            ended_at_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            bundle_id TEXT,
            team_id TEXT,
            display_name TEXT,
            app_path_cipher BLOB,
            uid INTEGER NOT NULL
        );

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

        CREATE TABLE IF NOT EXISTS ingest_dedup (
            source_instance TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            received_at_ms INTEGER NOT NULL,
            PRIMARY KEY(source_instance, sequence)
        );

        CREATE TABLE IF NOT EXISTS certificates (
            cert_id TEXT PRIMARY KEY,
            spki_id TEXT NOT NULL,
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

        CREATE TABLE IF NOT EXISTS observation_certificates (
            observation_id TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
            cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
            role TEXT NOT NULL CHECK(role IN ('leaf', 'intermediate', 'root')),
            chain_type TEXT NOT NULL CHECK(chain_type IN ('presented', 'verified')),
            ordinal INTEGER NOT NULL,
            PRIMARY KEY(observation_id, chain_type, ordinal)
        );

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

        CREATE VIEW IF NOT EXISTS current_classifications AS
        SELECT c.*
        FROM classifications c
        INNER JOIN (
            SELECT observation_id, MAX(revision) AS max_revision
            FROM classifications
            GROUP BY observation_id
        ) m ON c.observation_id = m.observation_id AND c.revision = m.max_revision;

        CREATE TABLE IF NOT EXISTS ca_clusters (
            id TEXT PRIMARY KEY,
            ca_key_id TEXT NOT NULL UNIQUE,
            ca_name TEXT NOT NULL,
            identity_kind TEXT NOT NULL CHECK(identity_kind IN ('inspection', 'suspected', 'public', 'expected_private', 'direct_leaf')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cluster_certificates (
            cluster_id TEXT NOT NULL REFERENCES ca_clusters(id) ON DELETE CASCADE,
            cert_id TEXT NOT NULL REFERENCES certificates(cert_id),
            PRIMARY KEY(cluster_id, cert_id)
        );

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

        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            time_ms INTEGER NOT NULL,
            entity_type TEXT,
            entity_id TEXT,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS events_time_idx ON events(time_ms DESC);

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

        CREATE TABLE IF NOT EXISTS coverage_intervals (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            start_ms INTEGER NOT NULL,
            end_ms INTEGER NOT NULL,
            loss INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1
        );

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
        """
        try execute(sql: ddl)
    }

    // MARK: - Execute statements

    public func execute(sql: String) throws {
        lock.lock()
        defer { lock.unlock() }
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let msg = err != nil ? String(cString: err!) : "Unknown error"
            sqlite3_free(err)
            throw DatabaseError.executionFailed(msg, sql: sql)
        }
    }

    public func transaction<T>(_ block: () throws -> T) throws -> T {
        try execute(sql: "BEGIN TRANSACTION;")
        do {
            let result = try block()
            try execute(sql: "COMMIT;")
            return result
        } catch {
            do {
                try execute(sql: "ROLLBACK;")
            } catch let rollbackError {
                AppLogger.shared.error("Database", "Transaction rollback failed; data may be inconsistent: \(rollbackError)")
            }
            throw error
        }
    }

    // MARK: - Prepared statements

    public func prepare(sql: String) throws -> SQLiteStatement {
        lock.lock()
        defer { lock.unlock() }
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw DatabaseError.prepareFailed(msg, sql: sql)
        }
        return SQLiteStatement(stmt: stmt!, lock: lock, isCached: false)
    }

    /// Reuse prepared statements to avoid reparsing SQL for frequent queries.
    public func withCachedStatement<T>(sql: String, _ block: (SQLiteStatement) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }

        let stmtPointer: OpaquePointer
        if let existing = cachedStatements[sql] {
            stmtPointer = existing
            sqlite3_reset(stmtPointer)
            sqlite3_clear_bindings(stmtPointer)
        } else {
            var newStmt: OpaquePointer?
            if sqlite3_prepare_v2(db, sql, -1, &newStmt, nil) != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(db))
                throw DatabaseError.prepareFailed(msg, sql: sql)
            }
            stmtPointer = newStmt!
            cachedStatements[sql] = stmtPointer
        }

        let wrapper = SQLiteStatement(stmt: stmtPointer, lock: lock, isCached: true)
        do {
            let result = try block(wrapper)
            wrapper.reset()
            return result
        } catch {
            wrapper.reset()
            throw error
        }
    }

    // Force a WAL checkpoint.
    public func checkpoint() throws {
        if path != ":memory:" {
            try execute(sql: "PRAGMA wal_checkpoint(TRUNCATE);")
        }
    }
}

public final class SQLiteStatement {
    private var stmt: OpaquePointer?
    private let lock: NSRecursiveLock
    private let isCached: Bool

    fileprivate init(stmt: OpaquePointer, lock: NSRecursiveLock, isCached: Bool = false) {
        self.stmt = stmt
        self.lock = lock
        self.isCached = isCached
    }

    deinit {
        if !isCached, let stmt = stmt {
            sqlite3_finalize(stmt)
        }
    }

    public func reset() {
        if let stmt = stmt {
            sqlite3_reset(stmt)
            sqlite3_clear_bindings(stmt)
        }
    }

    private static let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    public func bindNull(index: Int32) {
        sqlite3_bind_null(stmt, index)
    }

    public func bindText(_ text: String, index: Int32) {
        sqlite3_bind_text(stmt, index, (text as NSString).utf8String, -1, Self.SQLITE_TRANSIENT)
    }

    public func bindInt64(_ val: Int64, index: Int32) {
        sqlite3_bind_int64(stmt, index, val)
    }

    public func bindInt(_ val: Int, index: Int32) {
        sqlite3_bind_int(stmt, index, Int32(val))
    }

    public func bindBlob(_ data: Data, index: Int32) {
        _ = data.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, index, ptr.baseAddress, Int32(data.count), Self.SQLITE_TRANSIENT)
        }
    }

    public func step() -> Int32 {
        return sqlite3_step(stmt)
    }

    public func stepOrThrow() throws {
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE && rc != SQLITE_ROW {
            let dbHandle = sqlite3_db_handle(stmt)
            let msg = dbHandle != nil ? String(cString: sqlite3_errmsg(dbHandle)) : "error code \(rc)"
            let sqlStr: String
            if let sqlPtr = sqlite3_sql(stmt) {
                sqlStr = String(cString: sqlPtr)
            } else {
                sqlStr = "unknown"
            }
            throw DatabaseError.stepFailed("sqlite3_step failed: \(msg) (code \(rc)) on SQL: [\(sqlStr)]")
        }
    }

    public func columnText(index: Int32) -> String? {
        guard let text = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: text)
    }

    public func columnInt64(index: Int32) -> Int64 {
        return sqlite3_column_int64(stmt, index)
    }

    public func columnInt(index: Int32) -> Int {
        return Int(sqlite3_column_int(stmt, index))
    }

    public func columnBlob(index: Int32) -> Data? {
        guard let ptr = sqlite3_column_blob(stmt, index) else { return nil }
        let count = Int(sqlite3_column_bytes(stmt, index))
        return Data(bytes: ptr, count: count)
    }

    public func isNull(index: Int32) -> Bool {
        return sqlite3_column_type(stmt, index) == SQLITE_NULL
    }
}

public enum DatabaseError: Error, LocalizedError {
    case openFailed(String)
    case executionFailed(String, sql: String)
    case prepareFailed(String, sql: String)
    case stepFailed(String)

    public var errorDescription: String? {
        switch self {
        case .openFailed(let msg): return "openFailed: \(msg)"
        case .executionFailed(let msg, let sql): return "executionFailed: \(msg) (SQL: \(sql))"
        case .prepareFailed(let msg, let sql): return "prepareFailed: \(msg) (SQL: \(sql))"
        case .stepFailed(let msg): return "stepFailed: \(msg)"
        }
    }
}

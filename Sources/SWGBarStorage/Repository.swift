//
// SWGBar / macOS menu bar TLS inspection detector
// Storage repository (Repository.swift)
// Entity operations, encrypted field access, deduplication, and aggregation.
//

import Foundation
import SWGBarContracts

public final class StorageRepository: @unchecked Sendable {
    private let db: SQLiteDatabase
    private let crypto: StorageCrypto

    public init(db: SQLiteDatabase, crypto: StorageCrypto = .shared, performCleanup: Bool = false) {
        self.db = db
        self.crypto = crypto
        if performCleanup {
            try? cleanupPhantomPort443Targets()
        }
    }

    /// Combine writes in one SQLite transaction to reduce WAL synchronization.
    public func transaction<T>(_ block: () throws -> T) throws -> T {
        return try db.transaction(block)
    }

    // Cache decrypted immutable hostnames to avoid repeated AES-GCM operations.
    private var hostnameCache: [String: String] = [:]
    private let hostnameCacheLock = NSLock()

    // Cache host:port to target ID mappings to avoid repeated HMAC calculation and database lookup.
    private var targetIdCache: [String: String] = [:]
    private let targetIdCacheLock = NSLock()

    // Aggregate decryption failures into one periodic log entry rather than logging each failed row.
    private var decryptFailureCount: Int = 0
    private var lastDecryptFailureLogAt: TimeInterval = 0
    private let decryptFailureLock = NSLock()

    /// Record a field decryption failure and emit one summary per reporting window.
    private func noteDecryptFailure(scope: String) {
        decryptFailureLock.lock()
        decryptFailureCount += 1
        let now = ProcessInfo.processInfo.systemUptime
        let shouldLog = now - lastDecryptFailureLogAt >= 30.0
        let total = decryptFailureCount
        if shouldLog {
            lastDecryptFailureLogAt = now
            decryptFailureCount = 0
        }
        decryptFailureLock.unlock()

        if shouldLog {
            AppLogger.shared.warn("Storage", "Could not decrypt \(total) fields (latest scope: \(scope)); affected records were skipped")
        }
    }

    // MARK: - Network epochs (network_epochs)

    public func createEpoch(id: String, name: String, routeDigest: String, startMs: Int64) throws {
        let sql = "INSERT OR REPLACE INTO network_epochs (id, start_ms, route_digest, name) VALUES (?, ?, ?, ?);"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(id, index: 1)
        stmt.bindInt64(startMs, index: 2)
        stmt.bindText(routeDigest, index: 3)
        stmt.bindText(name, index: 4)
        _ = stmt.step()
    }

    // MARK: - Clear historical probe and target data
    public func clearAllHistoricalData() throws {
        try db.execute(sql: "DELETE FROM classifications;")
        try db.execute(sql: "DELETE FROM observation_certificates;")
        try db.execute(sql: "DELETE FROM trust_evaluations;")
        try db.execute(sql: "DELETE FROM observations;")
        try db.execute(sql: "DELETE FROM targets;")
        try db.execute(sql: "DELETE FROM events;")
        try db.execute(sql: "DELETE FROM settings WHERE key IN ('browser_history_imported', 'historical_baseline_probe_done');")
        hostnameCacheLock.lock()
        hostnameCache.removeAll()
        hostnameCacheLock.unlock()
        targetIdCacheLock.lock()
        targetIdCache.removeAll()
        targetIdCacheLock.unlock()
    }

    // MARK: - Settings (settings)

    public static let browserHistoryImportedKey = "browser_history_imported"

    public func getSetting(_ key: String) throws -> String? {
        let sql = "SELECT value FROM settings WHERE key = ?;"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(key, index: 1)
        guard stmt.step() == 100 else { return nil }
        return stmt.columnText(index: 0)
    }

    public func setSetting(_ key: String, value: String) throws {
        let sql = "INSERT OR REPLACE INTO settings (key, value, revision) VALUES (?, ?, 1);"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(key, index: 1)
        stmt.bindText(value, index: 2)
        _ = stmt.step()
    }

    public func hasCompletedBrowserHistoryImport() -> Bool {
        (try? getSetting(Self.browserHistoryImportedKey)) == "1"
    }

    public func markBrowserHistoryImportCompleted() throws {
        try setSetting(Self.browserHistoryImportedKey, value: "1")
    }

    public func hasAnyTargets() -> Bool {
        let sql = "SELECT 1 FROM targets LIMIT 1;"
        guard let stmt = try? db.prepare(sql: sql) else { return false }
        return stmt.step() == 100
    }

    public static let historicalBaselineProbeDoneKey = "historical_baseline_probe_done"

    public func hasCompletedHistoricalBaselineProbe() -> Bool {
        (try? getSetting(Self.historicalBaselineProbeDoneKey)) == "1"
    }

    public func markHistoricalBaselineProbeCompleted() throws {
        try setSetting(Self.historicalBaselineProbeDoneKey, value: "1")
    }

    // MARK: - Merge legacy phantom port-443 targets and their request counts
    public func cleanupPhantomPort443Targets() throws {
        guard let targets = try? listTargetsWithLatestVerdict(limit: 5000) else { return }
        var byHost: [String: [DomainRow]] = [:]
        for t in targets {
            byHost[t.hostname.lowercased(), default: []].append(t)
        }

        for (_, rows) in byHost {
            if rows.contains(where: { $0.port != 443 }),
               let row443 = rows.first(where: { $0.port == 443 }),
               let non443 = rows.filter({ $0.port != 443 }).max(by: { $0.requestCount < $1.requestCount }) {
                let maxCount = max(row443.requestCount, non443.requestCount)
                try? updateRequestCount(targetId: non443.targetId, count: maxCount)

                let delObsSql = "DELETE FROM observations WHERE target_id = ?;"
                if let delObs = try? db.prepare(sql: delObsSql) {
                    delObs.bindText(row443.targetId, index: 1)
                    _ = delObs.step()
                }

                let delTgtSql = "DELETE FROM targets WHERE id = ?;"
                if let delTgt = try? db.prepare(sql: delTgtSql) {
                    delTgt.bindText(row443.targetId, index: 1)
                    _ = delTgt.step()
                }
            }
        }
    }

    // MARK: - Targets (targets)

    public func getOrCreateTarget(hostname: String, port: Int, isIpOnly: Bool = false, requestCount: Int64 = 0) throws -> String {
        let effectivePort = port > 0 ? port : 443
        let targetKey = "\(hostname.lowercased()):\(effectivePort)"

        // 1. Try the in-memory cache first.
        targetIdCacheLock.lock()
        if let cachedId = targetIdCache[targetKey] {
            targetIdCacheLock.unlock()
            if requestCount > 0 {
                try? updateRequestCount(targetId: cachedId, count: requestCount)
            }
            return cachedId
        }
        targetIdCacheLock.unlock()

        // 2. On a cache miss, calculate the HMAC and query the database.
        let hmac = crypto.computeDomainHMAC(normalizedHost: targetKey)
        let checkSql = "SELECT id, request_count FROM targets WHERE host_hmac = ?;"
        let checkStmt = try db.prepare(sql: checkSql)
        checkStmt.bindText(hmac, index: 1)
        if checkStmt.step() == 100 /* SQLITE_ROW */, let existingId = checkStmt.columnText(index: 0) {
            targetIdCacheLock.lock()
            targetIdCache[targetKey] = existingId
            targetIdCacheLock.unlock()
            if requestCount > 0 {
                try updateRequestCount(targetId: existingId, count: requestCount)
            }
            return existingId
        }

        // Migrate a legacy hostname-only HMAC to the hostname/port key when the port is 443.
        if effectivePort == 443 {
            let oldHmac = crypto.computeDomainHMAC(normalizedHost: hostname.lowercased())
            let oldCheckStmt = try db.prepare(sql: "SELECT id, request_count FROM targets WHERE host_hmac = ?;")
            oldCheckStmt.bindText(oldHmac, index: 1)
            if oldCheckStmt.step() == 100, let oldId = oldCheckStmt.columnText(index: 0) {
                let updStmt = try db.prepare(sql: "UPDATE targets SET host_hmac = ?, port = ? WHERE id = ?;")
                updStmt.bindText(hmac, index: 1)
                updStmt.bindInt(effectivePort, index: 2)
                updStmt.bindText(oldId, index: 3)
                _ = updStmt.step()
                targetIdCacheLock.lock()
                targetIdCache[targetKey] = oldId
                targetIdCacheLock.unlock()
                if requestCount > 0 {
                    try updateRequestCount(targetId: oldId, count: requestCount)
                }
                return oldId
            }
        }

        let targetId = UUID().uuidString
        let cipher = try crypto.encryptString(hostname, table: "targets", primaryKey: targetId)
        let now = Int64(Date().timeIntervalSince1970 * 1000)

        let insertSql = "INSERT INTO targets (id, host_hmac, host_cipher, port, is_ip_only, request_count, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?);"
        let insertStmt = try db.prepare(sql: insertSql)
        insertStmt.bindText(targetId, index: 1)
        insertStmt.bindText(hmac, index: 2)
        insertStmt.bindBlob(cipher, index: 3)
        insertStmt.bindInt(effectivePort, index: 4)
        insertStmt.bindInt(isIpOnly ? 1 : 0, index: 5)
        insertStmt.bindInt64(requestCount, index: 6)
        insertStmt.bindInt64(now, index: 7)
        try insertStmt.stepOrThrow()

        targetIdCacheLock.lock()
        targetIdCache[targetKey] = targetId
        targetIdCacheLock.unlock()

        return targetId
    }

    public func getTargetHostAndPort(targetId: String) throws -> (hostname: String, port: Int)? {
        hostnameCacheLock.lock()
        let cachedHost = hostnameCache[targetId]
        hostnameCacheLock.unlock()

        let sql = "SELECT host_cipher, port FROM targets WHERE id = ?;"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(targetId, index: 1)
        if stmt.step() == 100 {
            let port = stmt.columnInt(index: 1)
            let effectivePort = port > 0 ? port : 443
            if let host = cachedHost {
                return (host, effectivePort)
            }
            if let blob = stmt.columnBlob(index: 0),
               let host = try? crypto.decryptString(blob, table: "targets", primaryKey: targetId) {
                hostnameCacheLock.lock()
                hostnameCache[targetId] = host
                hostnameCacheLock.unlock()
                return (host, effectivePort)
            }
        }
        return nil
    }

    public func getTargetHostname(targetId: String) throws -> String? {
        return try getTargetHostAndPort(targetId: targetId)?.hostname
    }

    public func getTargetRequestCount(targetId: String) throws -> Int64 {
        let sql = "SELECT request_count FROM targets WHERE id = ?;"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(targetId, index: 1)
        if stmt.step() == 100 {
            return stmt.columnInt64(index: 0)
        }
        return 0
    }

    /// Increment the target request count atomically in one SQL statement.
    public func atomicIncrementRequestCount(targetId: String, count: Int64 = 1) throws {
        let sql = "UPDATE targets SET request_count = request_count + ? WHERE id = ?;"
        try db.withCachedStatement(sql: sql) { stmt in
            stmt.bindInt64(count, index: 1)
            stmt.bindText(targetId, index: 2)
            _ = stmt.step()
        }
    }

    public func updateRequestCount(targetId: String, count: Int64) throws {
        let sql = "UPDATE targets SET request_count = ? WHERE id = ?;"
        try db.withCachedStatement(sql: sql) { stmt in
            stmt.bindInt64(count, index: 1)
            stmt.bindText(targetId, index: 2)
            _ = stmt.step()
        }
    }

    public func listTargetsWithLatestVerdict(limit: Int = 5000, sortByRequestCount: Bool = false) throws -> [DomainRow] {
        let orderClause = sortByRequestCount ? "t.request_count DESC, o.observed_at_ms DESC" : "o.observed_at_ms DESC"
        let sql = """
        WITH latest_obs AS (
            SELECT target_id, MAX(observed_at_ms) as max_time
            FROM observations
            GROUP BY target_id
        ),
        target_certs AS (
            SELECT
                o.target_id,
                ca.id AS cluster_id
            FROM observations o
            INNER JOIN latest_obs lo ON o.target_id = lo.target_id AND o.observed_at_ms = lo.max_time
            LEFT JOIN observation_certificates oc
                ON o.id = oc.observation_id
               AND oc.chain_type = 'presented'
               AND oc.ordinal = 1
            LEFT JOIN cluster_certificates clc ON oc.cert_id = clc.cert_id
            LEFT JOIN ca_clusters ca ON clc.cluster_id = ca.id
            GROUP BY o.target_id
        )
        SELECT t.id, t.host_cipher, t.port, t.is_ip_only, cc.verdict, o.source, o.observed_at_ms, t.request_count, tc.cluster_id
        FROM targets t
        LEFT JOIN latest_obs lo ON t.id = lo.target_id
        LEFT JOIN observations o ON t.id = o.target_id AND o.observed_at_ms = lo.max_time
        LEFT JOIN current_classifications cc ON o.id = cc.observation_id
        LEFT JOIN target_certs tc ON t.id = tc.target_id
        ORDER BY \(orderClause)
        LIMIT ?;
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindInt(limit, index: 1)

        var rows: [DomainRow] = []
        while stmt.step() == 100 {
            let tId = stmt.columnText(index: 0) ?? ""

            var hostname: String?
            hostnameCacheLock.lock()
            hostname = hostnameCache[tId]
            hostnameCacheLock.unlock()

            if hostname == nil {
                if let cipher = stmt.columnBlob(index: 1),
                   let decrypted = try? crypto.decryptString(cipher, table: "targets", primaryKey: tId) {
                    hostname = decrypted
                    hostnameCacheLock.lock()
                    hostnameCache[tId] = decrypted
                    hostnameCacheLock.unlock()
                } else {
                    noteDecryptFailure(scope: "targets.host_cipher")
                    continue
                }
            }
            guard let resolvedHost = hostname else { continue }

            let port = stmt.columnInt(index: 2)
            let isIpOnly = stmt.columnInt(index: 3) == 1
            let verdictStr = stmt.columnText(index: 4) ?? "unknown"
            let verdict = Verdict(rawValue: verdictStr) ?? .unknown
            let sourceStr = stmt.columnText(index: 5) ?? "native_probe"
            let source = EvidenceSource(rawValue: sourceStr) ?? .nativeProbe
            let observedMs = stmt.columnInt64(index: 6)
            let requestCount = stmt.columnInt64(index: 7)
            let certificateClusterId = stmt.columnText(index: 8)

            var row = DomainRow(
                targetId: tId,
                hostname: resolvedHost,
                port: port,
                verdict: verdict,
                discoveredApp: nil,
                evidenceSource: source,
                lastObservedMs: observedMs > 0 ? observedMs : Int64(Date().timeIntervalSince1970 * 1000),
                isIpOnly: isIpOnly,
                requestCount: requestCount
            )
            row.certificateClusterId = certificateClusterId
            rows.append(row)
        }
        return rows
    }

    /// Return at most limit unique hostname/port targets without observations.
    public func listTargetsNeverProbed(limit: Int = 50) throws -> [(targetId: String, hostname: String, port: Int)] {
        let sql = """
        SELECT t.id, t.host_cipher, t.port
        FROM targets t
        WHERE NOT EXISTS (
            SELECT 1 FROM observations o WHERE o.target_id = t.id
        )
        ORDER BY t.request_count DESC, t.created_at_ms ASC, t.id ASC
        LIMIT ?;
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindInt(limit, index: 1)
        var results: [(targetId: String, hostname: String, port: Int)] = []
        var seen = Set<String>()
        while stmt.step() == 100 {
            let id = stmt.columnText(index: 0) ?? ""
            let port = stmt.columnInt(index: 2)
            guard let blob = stmt.columnBlob(index: 1),
                  let host = try? crypto.decryptString(blob, table: "targets", primaryKey: id) else {
                noteDecryptFailure(scope: "targets.host_cipher")
                continue
            }
            let hostname = host.lowercased()
            let effectivePort = port > 0 ? port : 443
            let key = "\(hostname):\(effectivePort)"
            guard seen.insert(key).inserted else { continue }
            results.append((targetId: id, hostname: hostname, port: effectivePort))
        }
        return results
    }

    public func countTargetsNeverProbed() throws -> Int {
        let sql = """
        SELECT COUNT(*)
        FROM targets t
        WHERE NOT EXISTS (
            SELECT 1 FROM observations o WHERE o.target_id = t.id
        );
        """
        let stmt = try db.prepare(sql: sql)
        guard stmt.step() == 100 else { return 0 }
        return Int(stmt.columnInt64(index: 0))
    }

    public func countNeverProbed(amongTargetIds ids: [String]) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        let placeholders = Array(repeating: "?", count: ids.count).joined(separator: ",")
        let sql = """
        SELECT COUNT(*)
        FROM targets t
        WHERE t.id IN (\(placeholders))
          AND NOT EXISTS (
            SELECT 1 FROM observations o WHERE o.target_id = t.id
          );
        """
        let stmt = try db.prepare(sql: sql)
        for (i, id) in ids.enumerated() {
            stmt.bindText(id, index: Int32(i + 1))
        }
        guard stmt.step() == 100 else { return ids.count }
        return Int(stmt.columnInt64(index: 0))
    }

    public struct TargetDetailInfo: Sendable {
        public let hostname: String
        public let port: Int
        public let verdict: Verdict
        public let reason: String
        public let requestCount: Int64
        public let lastObservedMs: Int64
        public let remoteIp: String?
        public let source: EvidenceSource
        public let caName: String?
        public let caClusterId: String?
        public let egressInterface: String?
        public let routeType: String?
    }

    public func getTargetDetailInfo(targetId: String) throws -> TargetDetailInfo? {
        guard let targetInfo = try getTargetHostAndPort(targetId: targetId) else { return nil }
        let hostname = targetInfo.hostname
        let port = targetInfo.port
        let requestCount = (try? getTargetRequestCount(targetId: targetId)) ?? 0

        let sql = """
        WITH latest_obs AS (
            SELECT id, source, observed_at_ms, remote_ip_cipher, egress_interface, route_type
            FROM observations
            WHERE target_id = ?
            ORDER BY observed_at_ms DESC
            LIMIT 1
        )
        SELECT lo.id, lo.source, lo.observed_at_ms, lo.remote_ip_cipher, cc.verdict, cc.reason, c.id,
               COALESCE(NULLIF(inter_c.subject, ''), NULLIF(leaf_c.issuer, ''), c.ca_name, leaf_c.subject) AS ca_name,
               lo.egress_interface, lo.route_type
        FROM latest_obs lo
        LEFT JOIN current_classifications cc ON lo.id = cc.observation_id
        LEFT JOIN observation_certificates leaf_oc ON lo.id = leaf_oc.observation_id AND leaf_oc.ordinal = 0
        LEFT JOIN certificates leaf_c ON leaf_oc.cert_id = leaf_c.cert_id
        LEFT JOIN observation_certificates inter_oc ON lo.id = inter_oc.observation_id AND inter_oc.ordinal = 1
        LEFT JOIN certificates inter_c ON inter_oc.cert_id = inter_c.cert_id
        LEFT JOIN observation_certificates any_oc ON lo.id = any_oc.observation_id
        LEFT JOIN cluster_certificates clc ON any_oc.cert_id = clc.cert_id
        LEFT JOIN ca_clusters c ON clc.cluster_id = c.id
        LIMIT 1;
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(targetId, index: 1)

        if stmt.step() == 100 {
            let obsId = stmt.columnText(index: 0) ?? ""
            let sourceStr = stmt.columnText(index: 1) ?? "native_probe"
            let source = EvidenceSource(rawValue: sourceStr) ?? .nativeProbe
            let observedMs = stmt.columnInt64(index: 2)
            var remoteIp: String? = nil
            if let cipher = stmt.columnBlob(index: 3) {
                remoteIp = try? crypto.decryptString(cipher, table: "observations", primaryKey: obsId)
            }
            let verdictStr = stmt.columnText(index: 4) ?? "unknown"
            let verdict = Verdict(rawValue: verdictStr) ?? .unknown
            let reason = stmt.columnText(index: 5) ?? "Probe not completed"
            let caClusterId = stmt.columnText(index: 6)
            let caName = stmt.columnText(index: 7)
            let egressInterface = stmt.columnText(index: 8)
            let routeType = stmt.columnText(index: 9)

            return TargetDetailInfo(
                hostname: hostname,
                port: port,
                verdict: verdict,
                reason: reason,
                requestCount: requestCount,
                lastObservedMs: observedMs,
                remoteIp: remoteIp,
                source: source,
                caName: caName,
                caClusterId: caClusterId,
                egressInterface: egressInterface,
                routeType: routeType
            )
        }

        return TargetDetailInfo(
            hostname: hostname,
            port: port,
            verdict: .unknown,
            reason: "Discovered in browser history; awaiting an active probe",
            requestCount: requestCount,
            lastObservedMs: Int64(Date().timeIntervalSince1970 * 1000),
            remoteIp: nil,
            source: .browserRequest,
            caName: nil,
            caClusterId: nil,
            egressInterface: nil,
            routeType: nil
        )
    }

    // MARK: - Certificates (certificates)

    public func saveCertificate(
        certId: String,
        spkiId: String,
        derBytes: Data,
        subject: String,
        issuer: String,
        notBeforeMs: Int64,
        notAfterMs: Int64,
        isCa: Bool,
        keyUsage: [String],
        sigAlg: String
    ) throws {
        let derCipher = try crypto.encrypt(plainData: derBytes, table: "certificates", primaryKey: certId)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let kuStr = keyUsage.joined(separator: ",")

        let sql = """
        INSERT INTO certificates
        (cert_id, spki_id, der_cipher, subject, issuer, not_before_ms, not_after_ms, is_ca, key_usage, signature_algorithm, created_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cert_id) DO UPDATE SET
            issuer = CASE WHEN excluded.issuer != '' THEN excluded.issuer ELSE certificates.issuer END,
            subject = CASE WHEN excluded.subject != '' THEN excluded.subject ELSE certificates.subject END;
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(certId, index: 1)
        stmt.bindText(spkiId, index: 2)
        stmt.bindBlob(derCipher, index: 3)
        stmt.bindText(subject, index: 4)
        stmt.bindText(issuer, index: 5)
        stmt.bindInt64(notBeforeMs, index: 6)
        stmt.bindInt64(notAfterMs, index: 7)
        stmt.bindInt(isCa ? 1 : 0, index: 8)
        stmt.bindText(kuStr, index: 9)
        stmt.bindText(sigAlg, index: 10)
        stmt.bindInt64(now, index: 11)
        _ = stmt.step()
    }

    // MARK: - Observations (observations)

    public struct ObservationRecord {
        public let id: String
        public let sourceInstanceId: String
        public let source: EvidenceSource
        public let objectKind: String
        public let generation: Int
        public let epochId: String
        public let targetId: String
        public let observedAtMs: Int64
        public let stage: String
        public let scopeJson: String
        public let requestKey: String?
        public let probeJobId: String?
        public let remoteIp: String?
        public let proxyEndpoint: String?
        public let egressInterface: String?
        public let routeType: String?

        public init(
            id: String = UUID().uuidString,
            sourceInstanceId: String,
            source: EvidenceSource,
            objectKind: String = "probe",
            generation: Int,
            epochId: String,
            targetId: String,
            observedAtMs: Int64,
            stage: String = "completed",
            scopeJson: String = "{}",
            requestKey: String? = nil,
            probeJobId: String? = nil,
            remoteIp: String? = nil,
            proxyEndpoint: String? = nil,
            egressInterface: String? = nil,
            routeType: String? = nil
        ) {
            self.id = id
            self.sourceInstanceId = sourceInstanceId
            self.source = source
            self.objectKind = objectKind
            self.generation = generation
            self.epochId = epochId
            self.targetId = targetId
            self.observedAtMs = observedAtMs
            self.stage = stage
            self.scopeJson = scopeJson
            self.requestKey = requestKey
            self.probeJobId = probeJobId
            self.remoteIp = remoteIp
            self.proxyEndpoint = proxyEndpoint
            self.egressInterface = egressInterface
            self.routeType = routeType
        }
    }

    public func saveObservation(_ obs: ObservationRecord) throws {
        var ipCipher: Data? = nil
        if let ip = obs.remoteIp {
            do {
                ipCipher = try crypto.encryptString(ip, table: "observations", primaryKey: obs.id)
            } catch {
                AppLogger.shared.warn("Storage", "Cannot encrypt the remote IP; the observation will omit it: \(error)")
            }
        }

        let sql = """
        INSERT INTO observations
        (id, source_instance_id, source, object_kind, generation, epoch_id, target_id, observed_at_ms, stage, scope_json, request_key, probe_job_id, remote_ip_cipher, proxy_endpoint, egress_interface, route_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        try db.withCachedStatement(sql: sql) { stmt in
            stmt.bindText(obs.id, index: 1)
            stmt.bindText(obs.sourceInstanceId, index: 2)
            stmt.bindText(obs.source.rawValue, index: 3)
            stmt.bindText(obs.objectKind, index: 4)
            stmt.bindInt(obs.generation, index: 5)
            stmt.bindText(obs.epochId, index: 6)
            stmt.bindText(obs.targetId, index: 7)
            stmt.bindInt64(obs.observedAtMs, index: 8)
            stmt.bindText(obs.stage, index: 9)
            stmt.bindText(obs.scopeJson, index: 10)
            if let rk = obs.requestKey { stmt.bindText(rk, index: 11) } else { stmt.bindNull(index: 11) }
            if let pjid = obs.probeJobId { stmt.bindText(pjid, index: 12) } else { stmt.bindNull(index: 12) }
            if let cipher = ipCipher { stmt.bindBlob(cipher, index: 13) } else { stmt.bindNull(index: 13) }
            if let pe = obs.proxyEndpoint { stmt.bindText(pe, index: 14) } else { stmt.bindNull(index: 14) }
            if let iface = obs.egressInterface, !iface.isEmpty { stmt.bindText(iface, index: 15) } else { stmt.bindNull(index: 15) }
            if let rt = obs.routeType, !rt.isEmpty { stmt.bindText(rt, index: 16) } else { stmt.bindNull(index: 16) }
            try stmt.stepOrThrow()
        }
    }

    public func linkObservationCertificate(obsId: String, certId: String, role: String, chainType: String, ordinal: Int) throws {
        let sql = "INSERT OR REPLACE INTO observation_certificates (observation_id, cert_id, role, chain_type, ordinal) VALUES (?, ?, ?, ?, ?);"
        try db.withCachedStatement(sql: sql) { stmt in
            stmt.bindText(obsId, index: 1)
            stmt.bindText(certId, index: 2)
            stmt.bindText(role, index: 3)
            stmt.bindText(chainType, index: 4)
            stmt.bindInt(ordinal, index: 5)
            try stmt.stepOrThrow()
        }
    }

    // MARK: - Classifications (classifications)

    public func saveClassification(obsId: String, revision: Int64, verdict: Verdict, reason: String) throws {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let id = UUID().uuidString
        let sql = "INSERT OR REPLACE INTO classifications (id, observation_id, revision, verdict, reason, classified_at_ms) VALUES (?, ?, ?, ?, ?, ?);"
        try db.withCachedStatement(sql: sql) { stmt in
            stmt.bindText(id, index: 1)
            stmt.bindText(obsId, index: 2)
            stmt.bindInt64(revision, index: 3)
            stmt.bindText(verdict.rawValue, index: 4)
            stmt.bindText(reason, index: 5)
            stmt.bindInt64(now, index: 6)
            try stmt.stepOrThrow()
        }
    }

    // MARK: - CA clusters (ca_clusters)

    public func upsertCACluster(spkiSha256: String, caName: String, identityKind: String, certId: String) throws -> String {
        let checkSql = "SELECT id FROM ca_clusters WHERE ca_key_id = ?;"
        let checkStmt = try db.prepare(sql: checkSql)
        checkStmt.bindText(spkiSha256, index: 1)

        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let clusterId: String
        if checkStmt.step() == 100, let existingId = checkStmt.columnText(index: 0) {
            clusterId = existingId
            let updateSql = "UPDATE ca_clusters SET updated_at_ms = ?, identity_kind = ? WHERE id = ?;"
            let updateStmt = try db.prepare(sql: updateSql)
            updateStmt.bindInt64(now, index: 1)
            updateStmt.bindText(identityKind, index: 2)
            updateStmt.bindText(clusterId, index: 3)
            _ = updateStmt.step()
        } else {
            clusterId = UUID().uuidString
            let insertSql = "INSERT INTO ca_clusters (id, ca_key_id, ca_name, identity_kind, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?);"
            let insertStmt = try db.prepare(sql: insertSql)
            insertStmt.bindText(clusterId, index: 1)
            insertStmt.bindText(spkiSha256, index: 2)
            insertStmt.bindText(caName, index: 3)
            insertStmt.bindText(identityKind, index: 4)
            insertStmt.bindInt64(now, index: 5)
            insertStmt.bindInt64(now, index: 6)
            _ = insertStmt.step()
        }

        let linkSql = "INSERT OR IGNORE INTO cluster_certificates (cluster_id, cert_id) VALUES (?, ?);"
        let linkStmt = try db.prepare(sql: linkSql)
        linkStmt.bindText(clusterId, index: 1)
        linkStmt.bindText(certId, index: 2)
        _ = linkStmt.step()

        return clusterId
    }

    public func listCAClusters() throws -> [CADetail] {
        let sql = """
        SELECT
            c.id,
            c.ca_key_id,
            c.ca_name,
            c.identity_kind,
            (
                SELECT COUNT(DISTINCT o.target_id)
                FROM cluster_certificates cc2
                JOIN observation_certificates oc ON cc2.cert_id = oc.cert_id
                JOIN observations o ON oc.observation_id = o.id
                WHERE cc2.cluster_id = c.id
            ) as affected_count,
            COALESCE(cert.cert_id, c.ca_key_id) as cert_id,
            COALESCE(cert.spki_id, c.ca_key_id) as spki_id,
            COALESCE(cert.subject, c.ca_name) as subject,
            COALESCE(cert.issuer, '') as issuer,
            COALESCE(cert.not_before_ms, 0) as not_before_ms,
            COALESCE(cert.not_after_ms, 0) as not_after_ms
        FROM ca_clusters c
        LEFT JOIN (
            SELECT
                COALESCE(cc.cluster_id, '') as cluster_id,
                cert.cert_id,
                cert.spki_id,
                cert.subject,
                cert.issuer,
                cert.not_before_ms,
                cert.not_after_ms
            FROM certificates cert
            LEFT JOIN cluster_certificates cc ON cert.cert_id = cc.cert_id
            GROUP BY COALESCE(cc.cluster_id, cert.spki_id)
        ) cert ON (cert.cluster_id = c.id OR (c.ca_key_id != '' AND cert.spki_id = c.ca_key_id))
        ORDER BY affected_count DESC, c.updated_at_ms DESC;
        """
        return try db.withCachedStatement(sql: sql) { stmt in
            var list: [CADetail] = []
            while stmt.step() == 100 {
                let id = stmt.columnText(index: 0) ?? ""
                let spki = stmt.columnText(index: 1) ?? ""
                let name = stmt.columnText(index: 2) ?? ""
                let kind = stmt.columnText(index: 3) ?? "suspected"
                let affected = stmt.columnInt64(index: 4)
                let certSha = stmt.columnText(index: 5) ?? spki
                let certSpki = stmt.columnText(index: 6) ?? spki
                let subject = stmt.columnText(index: 7) ?? name
                let issuer = stmt.columnText(index: 8) ?? ""
                let notBefore = stmt.columnInt64(index: 9)
                let notAfter = stmt.columnInt64(index: 10)

                list.append(CADetail(
                    clusterId: id,
                    caName: name,
                    identityKind: kind,
                    hasUserAssertion: (kind == "inspection"),
                    subject: subject.isEmpty ? name : subject,
                    issuer: issuer,
                    validityFormatted: "",
                    certSha256: certSha,
                    spkiSha256: certSpki.isEmpty ? spki : certSpki,
                    extraTrustVerifiedPath: [name, "macOS System Trust"],
                    baselineStatus: (kind == "inspection" ? "Public path not established (inspection proxy)" : (kind == "public" ? "Public path" : "Public path not established")),
                    activeRule: (kind == "inspection" ? Rule(
                        ruleId: "rule_\(id)",
                        name: name,
                        kind: "inspection_ca",
                        matchType: "ca_name",
                        matchValue: name,
                        domainScope: nil,
                        origin: "system",
                        explanation: "TLS inspection proxy certificate",
                        expiresAtMs: nil,
                        revision: 1
                    ) : nil),
                    affectedDomainsCount: affected,
                    notBeforeMs: notBefore > 0 ? notBefore : nil,
                    notAfterMs: notAfter > 0 ? notAfter : nil
                ))
            }
            return list
        }
    }

    public func countDomainsForCA(caName: String) throws -> Int {
        guard !caName.isEmpty else { return 1 }
        let (total, _) = (try? countDistinctDomainsForCA(spki: "", caName: caName)) ?? (1, 1)
        return max(total, 1)
    }

    /// List distinct hostnames associated with certificates issued or inspected by this CA.
    public func listHostnamesForCA(clusterId: String = "", spki: String = "", caName: String = "") throws -> [String] {
        var hosts: [String] = []

        // 1. Prefer exact cluster_certificates associations when a clusterId is available.
        // Use the same association rules as affectedDomainsCount in the list and detail views.
        if !clusterId.isEmpty {
            let clusterSql = """
            SELECT DISTINCT t.id, t.host_cipher
            FROM targets t
            JOIN observations o ON t.id = o.target_id
            JOIN observation_certificates oc ON o.id = oc.observation_id
            JOIN cluster_certificates cc ON oc.cert_id = cc.cert_id
            WHERE cc.cluster_id = ?;
            """
            let cStmt = try db.prepare(sql: clusterSql)
            cStmt.bindText(clusterId, index: 1)
            while cStmt.step() == 100 {
                guard let tId = cStmt.columnText(index: 0) else { continue }
                var hostname: String?
                hostnameCacheLock.lock()
                hostname = hostnameCache[tId]
                hostnameCacheLock.unlock()

                if hostname == nil {
                    if let cipher = cStmt.columnBlob(index: 1),
                       let decrypted = try? crypto.decryptString(cipher, table: "targets", primaryKey: tId) {
                        hostname = decrypted
                        hostnameCacheLock.lock()
                        hostnameCache[tId] = decrypted
                        hostnameCacheLock.unlock()
                    }
                }
                if let h = hostname, !h.isEmpty {
                    hosts.append(h)
                }
            }
        }

        // 2. Fall back to SPKI, subject, or issuer matching for fixtures and offline roots.
        if hosts.isEmpty && (!spki.isEmpty || !caName.isEmpty) {
            let fallbackSql = """
            SELECT DISTINCT t.id, t.host_cipher
            FROM targets t
            JOIN observations o ON t.id = o.target_id
            JOIN observation_certificates oc ON o.id = oc.observation_id
            JOIN certificates cert ON oc.cert_id = cert.cert_id
            WHERE (? != '' AND cert.spki_id = ?)
               OR (? != '' AND cert.subject LIKE ?)
               OR (? != '' AND cert.issuer LIKE ?);
            """
            let stmt = try db.prepare(sql: fallbackSql)
            stmt.bindText(spki, index: 1)
            stmt.bindText(spki, index: 2)
            stmt.bindText(caName, index: 3)
            stmt.bindText("%\(caName)%", index: 4)
            stmt.bindText(caName, index: 5)
            stmt.bindText("%\(caName)%", index: 6)
            while stmt.step() == 100 {
                guard let tId = stmt.columnText(index: 0) else { continue }
                var hostname: String?
                hostnameCacheLock.lock()
                hostname = hostnameCache[tId]
                hostnameCacheLock.unlock()

                if hostname == nil {
                    if let cipher = stmt.columnBlob(index: 1),
                       let decrypted = try? crypto.decryptString(cipher, table: "targets", primaryKey: tId) {
                        hostname = decrypted
                        hostnameCacheLock.lock()
                        hostnameCache[tId] = decrypted
                        hostnameCacheLock.unlock()
                    }
                }
                if let h = hostname, !h.isEmpty {
                    hosts.append(h)
                }
            }
        }
        return hosts
    }

    /// Count distinct apex domains and all distinct hostnames associated with a CA.
    public func countDistinctDomainsForCA(spki: String, caName: String) throws -> (total: Int, apex: Int) {
        let hosts = try listHostnamesForCA(spki: spki, caName: caName)
        let uniqueHosts = Set(hosts)
        var apexSet = Set<String>()
        for h in uniqueHosts {
            apexSet.insert(DomainNormalizer.extractApexDomain(h))
        }
        return (uniqueHosts.count, apexSet.count)
    }

    public func upgradeUnknownToSuspectedForCA(caName: String) throws {
        guard !caName.isEmpty else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let sql = """
        INSERT INTO classifications (id, observation_id, revision, verdict, reason, classified_at_ms)
        SELECT lower(hex(randomblob(16))), cc.observation_id, cc.revision + 1, 'suspected_inspection', 'EXTRA_TRUST_RECURRENCE_ACROSS_PUBLIC_DOMAINS', ?
        FROM current_classifications cc
        JOIN observation_certificates oc ON cc.observation_id = oc.observation_id
        JOIN certificates cert ON oc.cert_id = cert.cert_id
        WHERE (cert.subject LIKE ? OR cert.issuer LIKE ?)
          AND cc.verdict = 'unknown'
          AND cc.reason LIKE '%EXTRA_PRIVATE_TRUST%';
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindInt64(now, index: 1)
        stmt.bindText("%\(caName)%", index: 2)
        stmt.bindText("%\(caName)%", index: 3)
        _ = stmt.step()
    }

    public func reclassifyObservationsForRule(_ rule: Rule) throws {
        guard rule.kind == "inspection_ca" else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let sql = """
        INSERT INTO classifications (id, observation_id, revision, verdict, reason, classified_at_ms)
        SELECT lower(hex(randomblob(16))), cc.observation_id, cc.revision + 1, 'confirmed_inspection', 'RULE_MATCH: ' || ?, ?
        FROM current_classifications cc
        JOIN observation_certificates oc ON cc.observation_id = oc.observation_id
        JOIN certificates cert ON oc.cert_id = cert.cert_id
        WHERE (cert.cert_id = ? OR cert.spki_id = ? OR cert.subject LIKE ? OR cert.issuer LIKE ?)
          AND cc.verdict NOT IN ('confirmed_inspection', 'public_path');
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(rule.explanation, index: 1)
        stmt.bindInt64(now, index: 2)
        stmt.bindText(rule.matchValue, index: 3)
        stmt.bindText(rule.matchValue, index: 4)
        stmt.bindText("%\(rule.matchValue)%", index: 5)
        stmt.bindText("%\(rule.matchValue)%", index: 6)
        _ = stmt.step()
    }

    // MARK: - Rules (rules)

    public func upsertRule(_ rule: Rule) throws {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let sql = """
        INSERT OR REPLACE INTO rules
        (id, kind, match_type, match_value, domain_scope, app_scope, origin, explanation, expires_at_ms, revision, created_at_ms, updated_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(rule.ruleId, index: 1)
        stmt.bindText(rule.kind, index: 2)
        stmt.bindText(rule.matchType, index: 3)
        stmt.bindText(rule.matchValue, index: 4)
        if let ds = rule.domainScope { stmt.bindText(ds, index: 5) } else { stmt.bindNull(index: 5) }
        if let as_ = rule.appScope { stmt.bindText(as_, index: 6) } else { stmt.bindNull(index: 6) }
        stmt.bindText(rule.origin, index: 7)
        stmt.bindText(rule.explanation, index: 8)
        if let exp = rule.expiresAtMs { stmt.bindInt64(exp, index: 9) } else { stmt.bindNull(index: 9) }
        stmt.bindInt64(rule.revision, index: 10)
        stmt.bindInt64(now, index: 11)
        stmt.bindInt64(now, index: 12)
        _ = stmt.step()

        // Saving an inspection_ca rule immediately reclassifies associated historical domains.
        if rule.kind == "inspection_ca" {
            do {
                try reclassifyObservationsForRule(rule)
            } catch {
                AppLogger.shared.error("Storage", "Rule-based reclassification failed; historical verdicts were not updated, rule=\(rule.ruleId): \(error)")
            }
        }
    }

    /// Upgrade historical observations associated with this CA to confirmed inspection.
    public func upgradeAllToConfirmedForCA(caName: String, spkiSha256: String) throws {
        guard !caName.isEmpty || !spkiSha256.isEmpty else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let sql = """
        INSERT INTO classifications (id, observation_id, revision, verdict, reason, classified_at_ms)
        SELECT lower(hex(randomblob(16))), cc.observation_id, cc.revision + 1, 'confirmed_inspection', 'AUTO_CONFIRMED_INTERCEPTION_CA', ?
        FROM current_classifications cc
        JOIN observation_certificates oc ON cc.observation_id = oc.observation_id
        JOIN certificates cert ON oc.cert_id = cert.cert_id
        WHERE (cert.spki_id = ? OR cert.subject LIKE ? OR cert.issuer LIKE ?)
          AND cc.verdict NOT IN ('confirmed_inspection', 'public_path');
        """
        let stmt = try db.prepare(sql: sql)
        stmt.bindInt64(now, index: 1)
        stmt.bindText(spkiSha256, index: 2)
        stmt.bindText("%\(caName)%", index: 3)
        stmt.bindText("%\(caName)%", index: 4)
        _ = stmt.step()

        // Also set the cluster's identity_kind to inspection.
        let clusterSql = "UPDATE ca_clusters SET identity_kind = 'inspection' WHERE ca_key_id = ? OR ca_name LIKE ?;"
        let cStmt = try db.prepare(sql: clusterSql)
        cStmt.bindText(spkiSha256, index: 1)
        cStmt.bindText("%\(caName)%", index: 2)
        _ = cStmt.step()
    }

    public func listRules() throws -> [Rule] {
        let sql = "SELECT id, kind, match_type, match_value, domain_scope, app_scope, origin, explanation, expires_at_ms, revision FROM rules ORDER BY updated_at_ms DESC;"
        let stmt = try db.prepare(sql: sql)
        var list: [Rule] = []
        while stmt.step() == 100 {
            let r = Rule(
                ruleId: stmt.columnText(index: 0) ?? "",
                name: stmt.columnText(index: 3) ?? "",
                kind: stmt.columnText(index: 1) ?? "",
                matchType: stmt.columnText(index: 2) ?? "",
                matchValue: stmt.columnText(index: 3) ?? "",
                domainScope: stmt.columnText(index: 4),
                appScope: stmt.columnText(index: 5),
                origin: stmt.columnText(index: 6) ?? "user",
                explanation: stmt.columnText(index: 7) ?? "",
                expiresAtMs: stmt.isNull(index: 8) ? nil : stmt.columnInt64(index: 8),
                revision: stmt.columnInt64(index: 9)
            )
            list.append(r)
        }
        return list
    }

    public func deleteRule(ruleId: String) throws {
        let sql = "DELETE FROM rules WHERE id = ?;"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(ruleId, index: 1)
        _ = stmt.step()
    }

    // MARK: - Events (events)

    public func logEvent(kind: String, title: String, detail: String, category: String, isChange: Bool = true) throws {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let id = UUID().uuidString
        let payload: [String: Any] = [
            "title": title,
            "detail": detail,
            "category": category,
            "is_change": isChange
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let jsonStr = String(data: jsonData, encoding: .utf8) ?? "{}"

        let sql = "INSERT INTO events (id, kind, time_ms, payload_json) VALUES (?, ?, ?, ?);"
        let stmt = try db.prepare(sql: sql)
        stmt.bindText(id, index: 1)
        stmt.bindText(kind, index: 2)
        stmt.bindInt64(now, index: 3)
        stmt.bindText(jsonStr, index: 4)
        _ = stmt.step()
    }

    public func listEvents(limit: Int = 50) throws -> [TimelineEvent] {
        let sql = "SELECT id, time_ms, kind, payload_json FROM events ORDER BY time_ms DESC LIMIT ?;"
        let stmt = try db.prepare(sql: sql)
        stmt.bindInt(limit, index: 1)

        let df = DateFormatter()
        df.dateFormat = "HH:mm"

        var events: [TimelineEvent] = []
        while stmt.step() == 100 {
            let id = stmt.columnText(index: 0) ?? ""
            let timeMs = stmt.columnInt64(index: 1)
            let kind = stmt.columnText(index: 2) ?? ""
            let payloadStr = stmt.columnText(index: 3) ?? "{}"

            var title = kind
            var detail = ""
            var category = "system"
            var isChange = true

            if let data = payloadStr.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                title = obj["title"] as? String ?? title
                detail = obj["detail"] as? String ?? detail
                category = obj["category"] as? String ?? category
                isChange = obj["is_change"] as? Bool ?? true
            }

            let date = Date(timeIntervalSince1970: TimeInterval(timeMs) / 1000.0)
            events.append(TimelineEvent(
                id: id,
                timeMs: timeMs,
                timeFormatted: df.string(from: date),
                kind: kind,
                title: title,
                detail: detail,
                category: category,
                isChange: isChange
            ))
        }
        return events
    }

    // MARK: - Metric aggregation and queries

    public func queryMetricCounts(source: EvidenceSource, epochId: String = "", windowStartMs: Int64 = 0, windowEndMs: Int64 = 0) throws -> MetricCounts {
        var whereClauses = ["source = ?", "is_own_traffic = 0"]
        if !epochId.isEmpty {
            whereClauses.append("epoch_id = ?")
        }
        if windowStartMs > 0 {
            whereClauses.append("observed_at_ms >= ?")
        }
        if windowEndMs > 0 {
            whereClauses.append("observed_at_ms < ?")
        }
        let whereSql = whereClauses.joined(separator: " AND ")

        var joinWhereClauses = ["o.source = ?"]
        if !epochId.isEmpty {
            joinWhereClauses.append("o.epoch_id = ?")
        }
        let joinWhereSql = joinWhereClauses.joined(separator: " AND ")

        let sql = """
        WITH latest_obs AS (
            SELECT target_id, MAX(observed_at_ms) as max_time
            FROM observations
            WHERE \(whereSql)
            GROUP BY target_id
        ),
        active_obs AS (
            SELECT o.id, o.target_id
            FROM observations o
            INNER JOIN latest_obs lo ON o.target_id = lo.target_id AND o.observed_at_ms = lo.max_time
            WHERE \(joinWhereSql)
        )
        SELECT cc.verdict, COUNT(*)
        FROM active_obs ao
        INNER JOIN current_classifications cc ON ao.id = cc.observation_id
        GROUP BY cc.verdict;
        """
        return try db.withCachedStatement(sql: sql) { stmt in
            var idx: Int32 = 1
            stmt.bindText(source.rawValue, index: idx); idx += 1
            if !epochId.isEmpty {
                stmt.bindText(epochId, index: idx); idx += 1
            }
            if windowStartMs > 0 {
                stmt.bindInt64(windowStartMs, index: idx); idx += 1
            }
            if windowEndMs > 0 {
                stmt.bindInt64(windowEndMs, index: idx); idx += 1
            }
            stmt.bindText(source.rawValue, index: idx); idx += 1
            if !epochId.isEmpty {
                stmt.bindText(epochId, index: idx); idx += 1
            }

            var confirmed: Int64 = 0
            var suspected: Int64 = 0
            var publicPath: Int64 = 0
            var expectedPrivate: Int64 = 0
            var unknown: Int64 = 0
            var excluded: Int64 = 0

            while stmt.step() == 100 {
                if let verdictStr = stmt.columnText(index: 0) {
                    let count = stmt.columnInt64(index: 1)
                    switch verdictStr {
                    case "confirmed_inspection": confirmed = count
                    case "suspected_inspection": suspected = count
                    case "public_path": publicPath = count
                    case "expected_private": expectedPrivate = count
                    case "unknown": unknown = count
                    case "excluded": excluded = count
                    default: break
                    }
                }
            }

            return MetricCounts(
                confirmed: confirmed,
                suspected: suspected,
                publicPath: publicPath,
                expectedPrivate: expectedPrivate,
                unknown: unknown,
                excluded: excluded
            )
        }
    }

    // MARK: - Retention and pruning

    public func pruneOldObservations(retentionHours: Int, maxCount: Int = 250000) throws -> (pruned: Int, reachedSoftLimit: Bool) {
        let cutoffMs = Int64((Date().timeIntervalSince1970 - Double(retentionHours * 3600)) * 1000)
        let deleteSql = "DELETE FROM observations WHERE observed_at_ms < ?;"
        let stmt = try db.prepare(sql: deleteSql)
        stmt.bindInt64(cutoffMs, index: 1)
        _ = stmt.step()

        // Check whether the total exceeds the soft limit.
        let countSql = "SELECT COUNT(*) FROM observations;"
        let countStmt = try db.prepare(sql: countSql)
        var total: Int64 = 0
        if countStmt.step() == 100 {
            total = countStmt.columnInt64(index: 0)
        }

        var reached = false
        if total > Int64(maxCount) {
            reached = true
            let excess = total - Int64(maxCount)
            let excessSql = """
            DELETE FROM observations WHERE id IN (
                SELECT id FROM observations ORDER BY observed_at_ms ASC LIMIT ?
            );
            """
            let excessStmt = try db.prepare(sql: excessSql)
            excessStmt.bindInt64(excess, index: 1)
            _ = excessStmt.step()
        }

        // Remove unreferenced certificates.
        let cleanCertSql = """
        DELETE FROM certificates WHERE cert_id NOT IN (
            SELECT DISTINCT cert_id FROM observation_certificates
        ) AND cert_id NOT IN (
            SELECT DISTINCT cert_id FROM cluster_certificates
        );
        """
        try db.execute(sql: cleanCertSql)
        try db.checkpoint()

        return (pruned: 0, reachedSoftLimit: reached)
    }
}

//
// SWGBar / macOS menu bar TLS inspection detector
// Storage and performance tests (DatabasePerformanceTests.swift)
// Exercise batch inserts, WAL-backed storage, aggregate queries, and retention.
//

import XCTest
import CryptoKit
@testable import SWGBarContracts
@testable import SWGBarStorage

final class DatabasePerformanceTests: XCTestCase {
    var db: SQLiteDatabase!
    var repo: StorageRepository!
    
    override func setUpWithError() throws {
        db = try SQLiteDatabase.inMemory()
        let testCrypto = StorageCrypto(testKey: SymmetricKey(size: .bits256))
        repo = StorageRepository(db: db, crypto: testCrypto)
    }
    
    override func tearDownWithError() throws {
        db = nil
        repo = nil
    }
    
    // MARK: - Field encryption and HMAC lookup
    func testCryptoAndHMACConsistency() throws {
        let testHost = "api.internal.corp.example"
        let targetId = try repo.getOrCreateTarget(hostname: testHost, port: 443)
        
        let retrieved = try repo.getTargetHostname(targetId: targetId)
        XCTAssertEqual(retrieved, testHost, "The decrypted hostname must match its original input")
        
        // Looking up the same hostname again must return the existing targetId.
        let secondId = try repo.getOrCreateTarget(hostname: testHost, port: 443)
        XCTAssertEqual(targetId, secondId, "Identical hostnames must resolve to one target through HMAC")
    }
    
    // MARK: - Batch writes and aggregate query performance (50 ms query target)
    func testL2ModelLayerBatchAndAggregation() throws {
        let epochId = "epoch-perf"
        try repo.createEpoch(id: epochId, name: "Performance test epoch", routeDigest: "digest-perf", startMs: 1000)
        
        let start = Date()
        let batchCount = 1000
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        try db.transaction {
            for i in 0..<batchCount {
                let targetId = try repo.getOrCreateTarget(hostname: "perf\(i).example.com", port: 443)
                let obs = StorageRepository.ObservationRecord(
                    id: "obs_perf_\(i)",
                    sourceInstanceId: "perf_batch",
                    source: .nativeProbe,
                    generation: 1,
                    epochId: epochId,
                    targetId: targetId,
                    observedAtMs: now - Int64(i * 10)
                )
                try repo.saveObservation(obs)
                
                let verdict: Verdict = (i % 10 == 0) ? .confirmedInspection : ((i % 5 == 0) ? .suspectedInspection : .publicPath)
                try repo.saveClassification(obsId: obs.id, revision: 1, verdict: verdict, reason: "BATCH_TEST")
            }
        }
        let insertDuration = Date().timeIntervalSince(start)
        XCTAssertLessThan(insertDuration, 1.5, "A transaction inserting 1,000 observations must finish within 1.5 seconds")
        
        // Measure aggregate query latency against the 50 ms target.
        let queryStart = Date()
        let counts = try repo.queryMetricCounts(
            source: .nativeProbe,
            epochId: epochId,
            windowStartMs: now - 3600_000,
            windowEndMs: now + 1000
        )
        let queryDurationMs = Date().timeIntervalSince(queryStart) * 1000.0
        
        XCTAssertEqual(counts.nApplicableTotal, Int64(batchCount))
        XCTAssertEqual(counts.confirmed, 100)
        XCTAssertEqual(counts.suspected, 100) // (i%5==0 and not i%10==0) = 100
        XCTAssertEqual(counts.publicPath, 800)
        XCTAssertLessThan(queryDurationMs, 50.0, "The aggregate query must finish within 50 ms (actual: \(queryDurationMs) ms)")
    }
    
    // MARK: - Retention and soft limits
    func testDataPruningAndRetention() throws {
        let epochId = "epoch-prune"
        try repo.createEpoch(id: epochId, name: "Retention test epoch", routeDigest: "digest-prune", startMs: 1000)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        // Insert observations from 25 hours ago and one hour ago.
        let oldTargetId = try repo.getOrCreateTarget(hostname: "old.example.com", port: 443)
        let obsOld = StorageRepository.ObservationRecord(
            id: "obs_old",
            sourceInstanceId: "prune_test",
            source: .nativeProbe,
            generation: 1,
            epochId: epochId,
            targetId: oldTargetId,
            observedAtMs: now - (25 * 3600 * 1000)
        )
        try repo.saveObservation(obsOld)
        
        let newTargetId = try repo.getOrCreateTarget(hostname: "new.example.com", port: 443)
        let obsNew = StorageRepository.ObservationRecord(
            id: "obs_new",
            sourceInstanceId: "prune_test",
            source: .nativeProbe,
            generation: 1,
            epochId: epochId,
            targetId: newTargetId,
            observedAtMs: now - (1 * 3600 * 1000)
        )
        try repo.saveObservation(obsNew)
        
        // Prune detailed observations using a 24-hour retention window.
        _ = try repo.pruneOldObservations(retentionHours: 24, maxCount: 250000)
        
        // Verify that the older observation was removed and the recent one remains.
        let checkOld = try db.prepare(sql: "SELECT COUNT(*) FROM observations WHERE id = 'obs_old';")
        _ = checkOld.step()
        XCTAssertEqual(checkOld.columnInt(index: 0), 0, "Records older than 25 hours must be pruned")
        
        let checkNew = try db.prepare(sql: "SELECT COUNT(*) FROM observations WHERE id = 'obs_new';")
        _ = checkNew.step()
        XCTAssertEqual(checkNew.columnInt(index: 0), 1, "Records from one hour ago must be retained")
    }
}

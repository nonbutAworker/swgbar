//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 存储与性能压力测试 (DatabasePerformanceTests.swift)
// 遵循技术方案 v1.1 第 34, 37, 38 章：L2/L5 负载目标、WAL 写入与聚合查询时延
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
    
    // MARK: - 字段加密与 HMAC 索引验证
    func testCryptoAndHMACConsistency() throws {
        let testHost = "api.internal.corp.example"
        let targetId = try repo.getOrCreateTarget(hostname: testHost, port: 443)
        
        let retrieved = try repo.getTargetHostname(targetId: targetId)
        XCTAssertEqual(retrieved, testHost, "解密后的域名必须与原始输入完全一致")
        
        // 再次获取同一域名，应当命中已存在的 targetId
        let secondId = try repo.getOrCreateTarget(hostname: testHost, port: 443)
        XCTAssertEqual(targetId, secondId, "相同域名必须通过 HMAC 唯一命中同一 target")
    }
    
    // MARK: - L2 模型层批量写入与聚合查询性能 (< 50ms 目标)
    func testL2ModelLayerBatchAndAggregation() throws {
        let epochId = "epoch-perf"
        try repo.createEpoch(id: epochId, name: "性能测试阶段", routeDigest: "digest-perf", startMs: 1000)
        
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
        XCTAssertLessThan(insertDuration, 1.5, "1000 条观测批量写入事务应在 1.5 秒内完成")
        
        // 测试聚合查询时延 (目标 < 50ms)
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
        XCTAssertLessThan(queryDurationMs, 50.0, "聚合查询在窗口内应当在 50ms 内完成 (实际: \(queryDurationMs)ms)")
    }
    
    // MARK: - 数据清理与软限额测试
    func testDataPruningAndRetention() throws {
        let epochId = "epoch-prune"
        try repo.createEpoch(id: epochId, name: "清理测试阶段", routeDigest: "digest-prune", startMs: 1000)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        // 插入一条 25 小时前的记录和一条 1 小时前的记录
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
        
        // 执行 24 小时明细保留裁剪
        _ = try repo.pruneOldObservations(retentionHours: 24, maxCount: 250000)
        
        // 验证旧记录被清理，新记录保留
        let checkOld = try db.prepare(sql: "SELECT COUNT(*) FROM observations WHERE id = 'obs_old';")
        _ = checkOld.step()
        XCTAssertEqual(checkOld.columnInt(index: 0), 0, "25小时前的明细应被裁剪")
        
        let checkNew = try db.prepare(sql: "SELECT COUNT(*) FROM observations WHERE id = 'obs_new';")
        _ = checkNew.step()
        XCTAssertEqual(checkNew.columnInt(index: 0), 1, "1小时前的明细应被保留")
    }
}

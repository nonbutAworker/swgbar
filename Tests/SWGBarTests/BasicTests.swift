import XCTest
import CryptoKit
@testable import SWGBarContracts
@testable import SWGBarStorage
@testable import SWGBarFilter
@testable import SWGBarAgent

final class BasicTests: XCTestCase {
    func testContractsAndSanity() {
        let counts = MetricCounts(confirmed: 100, suspected: 50, publicPath: 600, expectedPrivate: 50, unknown: 200, excluded: 45)
        XCTAssertEqual(counts.nApplicableTotal, 1000)
        XCTAssertEqual(counts.kClassifiedTotal, 800)
    }
    
    func testExtractApexDomain() {
        XCTAssertEqual(DomainNormalizer.extractApexDomain("api.github.com"), "github.com")
        XCTAssertEqual(DomainNormalizer.extractApexDomain("raw.githubusercontent.com"), "githubusercontent.com")
        XCTAssertEqual(DomainNormalizer.extractApexDomain("web.example.org"), "example.org")
        XCTAssertEqual(DomainNormalizer.extractApexDomain("git.internal.corp"), "internal.corp")
        XCTAssertEqual(DomainNormalizer.extractApexDomain("wiki.internal.corp"), "internal.corp")
        XCTAssertEqual(DomainNormalizer.extractApexDomain("baidu.com:443"), "baidu.com")
    }
    
    func testMultiTargetAutoConfirmationPattern() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        let caSPKI = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
        let caName = "CN=Enterprise Inspection CA"
        
        try repo.createEpoch(id: "ep-01", name: "test-epoch", routeDigest: "d1", startMs: 1000)
        
        // 目标 1: apple.com
        let t1 = try repo.getOrCreateTarget(hostname: "apple.com", port: 443)
        let o1 = StorageRepository.ObservationRecord(
            sourceInstanceId: "p1", source: .nativeProbe, objectKind: "probe",
            generation: 1, epochId: "ep-01", targetId: t1,
            observedAtMs: 1000, stage: "completed", scopeJson: "{}"
        )
        try repo.saveObservation(o1)
        try repo.saveCertificate(
            certId: "cert-apple-leaf", spkiId: "spki-apple-leaf", derBytes: Data([0x30]),
            subject: "CN=apple.com", issuer: caName,
            notBeforeMs: 1000, notAfterMs: 2000, isCa: false, keyUsage: [], sigAlg: "ECDSA"
        )
        try repo.linkObservationCertificate(obsId: o1.id, certId: "cert-apple-leaf", role: "leaf", chainType: "presented", ordinal: 0)
        try repo.saveClassification(obsId: o1.id, revision: 1, verdict: .unknown, reason: "EXTRA_PRIVATE_TRUST_NO_RECURRENCE")
        
        // 单个域名时，distinctApex 为 1
        var stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 1)
        XCTAssertEqual(stats.apex, 1)
        
        // 目标 2: github.com
        let t2 = try repo.getOrCreateTarget(hostname: "github.com", port: 443)
        let o2 = StorageRepository.ObservationRecord(
            sourceInstanceId: "p2", source: .nativeProbe, objectKind: "probe",
            generation: 1, epochId: "ep-01", targetId: t2,
            observedAtMs: 1100, stage: "completed", scopeJson: "{}"
        )
        try repo.saveObservation(o2)
        try repo.saveCertificate(
            certId: "cert-github-leaf", spkiId: "spki-github-leaf", derBytes: Data([0x30]),
            subject: "CN=github.com", issuer: caName,
            notBeforeMs: 1000, notAfterMs: 2000, isCa: false, keyUsage: [], sigAlg: "ECDSA"
        )
        try repo.linkObservationCertificate(obsId: o2.id, certId: "cert-github-leaf", role: "leaf", chainType: "presented", ordinal: 0)
        try repo.saveClassification(obsId: o2.id, revision: 1, verdict: .unknown, reason: "EXTRA_PRIVATE_TRUST_NO_RECURRENCE")
        
        // 拦截 2 个不同主域名，尚未超过 10 个域名阈值
        stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 2)
        XCTAssertEqual(stats.apex, 2)
        XCTAssertFalse(stats.total > 10, "2 个域名尚未超过 10 个阈值")
        
        // 继续添加至 11 个不同域名 (超过 10 个)
        for i in 3...11 {
            let host = "sub\(i).example.org"
            let t = try repo.getOrCreateTarget(hostname: host, port: 443)
            let o = StorageRepository.ObservationRecord(
                sourceInstanceId: "p\(i)", source: .nativeProbe, objectKind: "probe",
                generation: 1, epochId: "ep-01", targetId: t,
                observedAtMs: Int64(1100 + i * 10), stage: "completed", scopeJson: "{}"
            )
            try repo.saveObservation(o)
            try repo.saveCertificate(
                certId: "cert-leaf-\(i)", spkiId: "spki-leaf-\(i)", derBytes: Data([0x30]),
                subject: "CN=\(host)", issuer: caName,
                notBeforeMs: 1000, notAfterMs: 2000, isCa: false, keyUsage: [], sigAlg: "ECDSA"
            )
            try repo.linkObservationCertificate(obsId: o.id, certId: "cert-leaf-\(i)", role: "leaf", chainType: "presented", ordinal: 0)
            try repo.saveClassification(obsId: o.id, revision: 1, verdict: .suspectedInspection, reason: "EXTRA_TRUST_RECURRENCE")
        }
        
        // 超过 10 个不同域名，满足条件 2
        stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 11)
        XCTAssertTrue(stats.total > 10, "11 个域名超过 10 个阈值，满足自动确认条件")
        
        // 自动规则合成与一键全量升级
        let autoRule = Rule(
            ruleId: "auto_rule_test",
            name: caName,
            kind: "inspection_ca",
            matchType: "ca_spki",
            matchValue: caSPKI,
            domainScope: nil,
            origin: "system_auto",
            explanation: "满足SWG中间人特征: 无法通过公网校验、本机受信任根校验通过，且拦截超过10个不同域名 (\(stats.total) 个域名)",
            expiresAtMs: nil,
            revision: 1
        )
        try repo.upsertRule(autoRule)
        try repo.upgradeAllToConfirmedForCA(caName: caName, spkiSha256: caSPKI)
        
        // 验证历史观测已被回溯升级为 confirmed_inspection
        let targetsWithVerdict = try repo.listTargetsWithLatestVerdict(limit: 20)
        for t in targetsWithVerdict {
            XCTAssertEqual(t.verdict, .confirmedInspection, "目标 \(t.hostname) 应当已自动升级为 confirmedInspection")
        }
    }
    
    func testSWGAutoConfirmationTwoConditions() {
        let engine = ClassificationEngine.shared
        
        // 1. 公网校验通过：无论多少个域名，绝不能判定为确认解密 (必须为公共路径)
        let publicRes = engine.classify(
            hostname: "example.com", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: true,
            presentedCertIds: ["leaf", "digicert_g2"], presentedSpkiIds: ["leaf_spki", "root_spki"],
            caSubjects: ["CN=example.com", "CN=DigiCert Global Root G2"],
            isExtraTrustAnchor: false, caDomainRecurrenceCount: 50, rules: []
        )
        XCTAssertEqual(publicRes.verdict, .publicPath, "公网证书即便覆盖 50 个域名也必须是公共路径")
        
        // 2. 满足条件 1 (公网不通过 + 本地受信任根通过)，但条件 2 域名数 <= 10 (例如 1 个域名)
        let singleRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 1, rules: []
        )
        XCTAssertEqual(singleRes.verdict, .unknown, "仅出现 1 个域名时为未知")
        
        // 3. 满足条件 1，条件 2 域名数为 2..10 (例如 5 个域名) -> 疑似状态
        let suspectedRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 5, rules: []
        )
        XCTAssertEqual(suspectedRes.verdict, .suspectedInspection, "域名数 5 个 (<= 10) 时为疑似状态")
        
        let suspected10Res = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 10, rules: []
        )
        XCTAssertEqual(suspected10Res.verdict, .suspectedInspection, "域名数恰好 10 个时仍为疑似状态")
        
        // 4. 满足条件 1，且满足条件 2: 超过 10 个不同域名 (例如 11 个域名) -> 确认状态!
        let confirmedRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 11, rules: []
        )
        XCTAssertEqual(confirmedRes.verdict, .confirmedInspection, "同时满足条件 1 与条件 2 (域名数 11 > 10) 时必须为确认状态")
        XCTAssertTrue(confirmedRes.reason.contains("SWG_INTERCEPTION_CONFIRMED"))
    }
    
    func testNeverProbedBatchingCoversAllUniqueHostPorts() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        try repo.createEpoch(id: "ep-01", name: "test", routeDigest: "d", startMs: 1)
        
        let first = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 10)
        let dup = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 28)
        XCTAssertEqual(first, dup, "同一域名+端口必须去重为一条目标")
        
        let altPort = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 8443)
        XCTAssertNotEqual(first, altPort, "同一域名不同端口必须视为不同目标")
        
        for i in 0..<120 {
            _ = try repo.getOrCreateTarget(hostname: "host\(i).example.com", port: 443, requestCount: Int64(i + 1))
        }
        
        let all = try repo.listTargetsNeverProbed(limit: 1000)
        let uniqueKeys = Set(all.map { "\($0.hostname):\($0.port)" })
        XCTAssertEqual(all.count, uniqueKeys.count, "待探测列表不得出现重复的域名+端口")
        XCTAssertEqual(uniqueKeys.count, 122)
        XCTAssertTrue(uniqueKeys.contains("chat.deepseek.com:443"))
        XCTAssertTrue(uniqueKeys.contains("chat.deepseek.com:8443"))
        
        var remaining = uniqueKeys
        var batches = 0
        while true {
            let batch = try repo.listTargetsNeverProbed(limit: 50)
            if batch.isEmpty { break }
            XCTAssertLessThanOrEqual(batch.count, 50, "每批最多 50 个")
            batches += 1
            for item in batch {
                let key = "\(item.hostname):\(item.port)"
                XCTAssertTrue(remaining.contains(key), "批次中出现了未知或不该重复的目标 \(key)")
                remaining.remove(key)
                let obs = StorageRepository.ObservationRecord(
                    sourceInstanceId: "batch-\(batches)",
                    source: .nativeProbe,
                    generation: 1,
                    epochId: "ep-01",
                    targetId: item.targetId,
                    observedAtMs: Int64(batches * 1000)
                )
                try repo.saveObservation(obs)
            }
        }
        
        XCTAssertTrue(remaining.isEmpty, "分批探测结束后不得遗漏任何域名+端口: \(remaining)")
        XCTAssertEqual(batches, 3, "122 个目标应按 50/50/22 分成 3 批")
        XCTAssertEqual(try repo.listTargetsNeverProbed(limit: 50).count, 0)
    }
    
    func testBrowserHistoryImportRunsOnlyOnFirstLaunch() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        
        XCTAssertFalse(repo.hasCompletedBrowserHistoryImport(), "全新库不应视为已完成首次导入")
        XCTAssertFalse(repo.hasAnyTargets())
        
        try repo.markBrowserHistoryImportCompleted()
        XCTAssertTrue(repo.hasCompletedBrowserHistoryImport(), "标记后必须跳过后续启动导入")
        
        try repo.clearAllHistoricalData()
        XCTAssertFalse(repo.hasCompletedBrowserHistoryImport(), "清空本地数据后应允许再次首次导入")
        XCTAssertFalse(repo.hasCompletedHistoricalBaselineProbe(), "清空后历史基线探测标记也应重置")
        
        try repo.markHistoricalBaselineProbeCompleted()
        XCTAssertTrue(repo.hasCompletedHistoricalBaselineProbe())
        
        _ = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 1)
        XCTAssertTrue(repo.hasAnyTargets(), "已有目标时不应再当首次启动去扫浏览器历史")
    }
    
    func testProbeChannelWaitUntilIdleAfterBatch() async {
        let channel = DomainProbeChannel()
        let consumed = ProbeTargetCollector()
        
        let worker = Task {
            while let target = await channel.receive() {
                consumed.append(target)
                await channel.markFinished()
            }
        }
        
        for i in 0..<50 {
            await channel.send(host: "batch-\(i).example.com", port: 443, force: true)
        }
        await channel.waitUntilIdle()
        
        let got = consumed.snapshot()
        XCTAssertEqual(got.count, 50)
        XCTAssertEqual(Set(got.map { "\($0.host):\($0.port)" }).count, 50)
        
        await channel.closeOrReset()
        _ = await worker.value
    }
    
    func testCADetailChromeAlignmentAndDatabaseJoin() throws {
        // 1. 测试 CADetail DN 解析与兜底规则 (对齐 Chrome 基本信息)
        let ca1 = CADetail(
            clusterId: "c1",
            caName: "CN=DNSPod DV TLS RSA CA 2025,O=DNSPod\\, Inc.,C=CN",
            identityKind: "public",
            hasUserAssertion: false,
            subject: "CN=DNSPod DV TLS RSA CA 2025,O=DNSPod\\, Inc.,C=CN",
            issuer: "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US",
            validityFormatted: "",
            certSha256: "97b4ccf5a75b8612f326c74c64f2afa639da3c7c539bce9b2a817a655d6e5ffd",
            spkiSha256: "8cf2a04fa02ca49bd0b10aa7fdd36597a062f541c7ef93be5671d754de477ed4",
            extraTrustVerifiedPath: ["DNSPod DV TLS RSA CA 2025"],
            baselineStatus: "公共路径",
            activeRule: nil,
            affectedDomainsCount: 3,
            notBeforeMs: 1786060800000,
            notAfterMs: 1803254399000
        )
        
        let sub = ca1.subjectElements
        XCTAssertEqual(sub.cn, "DNSPod DV TLS RSA CA 2025")
        XCTAssertEqual(sub.o, "DNSPod, Inc.")
        XCTAssertEqual(sub.ou, "<未包含在证书中>")
        
        let iss = ca1.issuerElements
        XCTAssertEqual(iss.cn, "DigiCert Global Root G2")
        XCTAssertEqual(iss.o, "DigiCert Inc")
        XCTAssertEqual(iss.ou, "www.digicert.com")
        
        XCTAssertTrue(ca1.notBeforeFormatted.contains("2026年"))
        XCTAssertTrue(ca1.notAfterFormatted.contains("2027年"))
        
        // 2. 测试 SQLite 数据库关联查询提取真实证书与影响域
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        
        try repo.saveCertificate(
            certId: "cert-dnspod-ca",
            spkiId: "spki-dnspod-ca",
            derBytes: Data([0x30, 0x82]),
            subject: "CN=DNSPod DV TLS RSA CA 2025,O=DNSPod\\, Inc.,C=CN",
            issuer: "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US",
            notBeforeMs: 1786060800000,
            notAfterMs: 1803254399000,
            isCa: true,
            keyUsage: ["certSign"],
            sigAlg: "RSA-SHA256"
        )
        _ = try repo.upsertCACluster(
            spkiSha256: "spki-dnspod-ca",
            caName: "CN=DNSPod DV TLS RSA CA 2025,O=DNSPod\\, Inc.,C=CN",
            identityKind: "public",
            certId: "cert-dnspod-ca"
        )
        
        let clusters = try repo.listCAClusters()
        XCTAssertEqual(clusters.count, 1)
        let cluster = clusters[0]
        XCTAssertEqual(cluster.certSha256, "cert-dnspod-ca")
        XCTAssertEqual(cluster.issuer, "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US")
        XCTAssertEqual(cluster.issuerElements.cn, "DigiCert Global Root G2")
        XCTAssertEqual(cluster.issuerElements.o, "DigiCert Inc")
        XCTAssertEqual(cluster.issuerElements.ou, "www.digicert.com")
        XCTAssertEqual(cluster.notBeforeMs, 1786060800000)
        XCTAssertEqual(cluster.notAfterMs, 1803254399000)
    }

    /// 域名详情「关联证书」必须与域名列表同名，且携带的 clusterId 能在证书列表中精确命中，保证点击可正确跳转。
    func testDomainDetailAssociatedCertificateLinksToCertificateDetail() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db, crypto: StorageCrypto(testKey: SymmetricKey(size: .bits256)))
        let service = SnapshotService(repository: repo)
        try repo.createEpoch(id: "link-epoch", name: "Test", routeDigest: "test", startMs: 1)

        let caName = "关联证书跳转用 CA"
        let caId = "link-ca"
        try repo.saveCertificate(
            certId: caId, spkiId: caId, derBytes: Data([0x30]),
            subject: caName, issuer: "Test Root", notBeforeMs: 1, notAfterMs: 2,
            isCa: true, keyUsage: [], sigAlg: "test"
        )
        let clusterId = try repo.upsertCACluster(spkiSha256: caId, caName: caName, identityKind: "inspection", certId: caId)

        let target = try repo.getOrCreateTarget(hostname: "link.example.com", port: 443, requestCount: 3)
        let obs = StorageRepository.ObservationRecord(
            sourceInstanceId: "link-test", source: .nativeProbe, generation: 1,
            epochId: "link-epoch", targetId: target, observedAtMs: 10
        )
        try repo.saveObservation(obs)
        try repo.saveClassification(obsId: obs.id, revision: 1, verdict: .unknown, reason: "TEST")
        let leafId = "link-leaf"
        try repo.saveCertificate(
            certId: leafId, spkiId: leafId, derBytes: Data([0x31]),
            subject: "CN=link.example.com", issuer: caName, notBeforeMs: 1, notAfterMs: 2,
            isCa: false, keyUsage: [], sigAlg: "test"
        )
        try repo.linkObservationCertificate(obsId: obs.id, certId: leafId, role: "leaf", chainType: "presented", ordinal: 0)
        try repo.linkObservationCertificate(obsId: obs.id, certId: caId, role: "intermediate", chainType: "presented", ordinal: 1)

        let row = try XCTUnwrap(service.listDomains(search: "link.example.com").first)
        let jumpClusterId = try XCTUnwrap(row.certificateClusterId)

        // 详情页展示名取自列表行，两者必须完全一致
        XCTAssertEqual(row.certificateSummary, caName)
        XCTAssertEqual(jumpClusterId, clusterId)

        // 跳转目标必须能在证书列表中被唯一命中，否则点击会落到错误证书
        let clusters = service.listCAClusters(showAll: true)
        let matched = clusters.filter { $0.clusterId == jumpClusterId }
        XCTAssertEqual(matched.count, 1, "关联证书的 clusterId 必须在证书列表中唯一命中")
        XCTAssertEqual(matched.first?.caName, row.certificateSummary)
    }

    /// 版本比较是升级清理的唯一触发依据，误判会导致用户数据被错误删除，必须锁定行为。
    /// 项目尚未发布，表结构以建表语句为唯一事实来源，不依赖任何 ALTER TABLE 迁移。
    /// 本用例确保全新库一次建表即包含全部字段与索引。
    func testFreshSchemaContainsAllColumnsAndIndexes() throws {
        let db = try SQLiteDatabase.inMemory()

        func names(_ sql: String) throws -> Set<String> {
            let stmt = try db.prepare(sql: sql)
            var out = Set<String>()
            while stmt.step() == 100 {
                if let n = stmt.columnText(index: 0) { out.insert(n) }
            }
            return out
        }

        let obsCols = try names("SELECT name FROM pragma_table_info('observations');")
        XCTAssertTrue(obsCols.contains("egress_interface"), "建表语句必须直接包含 egress_interface")
        XCTAssertTrue(obsCols.contains("route_type"), "建表语句必须直接包含 route_type")

        let targetCols = try names("SELECT name FROM pragma_table_info('targets');")
        XCTAssertTrue(targetCols.contains("request_count"), "建表语句必须直接包含 request_count")

        let indexes = try names("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%';")
        XCTAssertTrue(indexes.contains("targets_req_count_idx"))
        XCTAssertTrue(indexes.contains("cluster_certs_idx"))
        XCTAssertTrue(indexes.contains("obs_certs_cert_id_idx"))
    }

    func testInstallationVersionComparison() {
        // 升级：应触发清理
        XCTAssertTrue(InstallationManager.isVersion("1.2", newerThan: "1.1"))
        XCTAssertTrue(InstallationManager.isVersion("2.0", newerThan: "1.9"))
        XCTAssertTrue(InstallationManager.isVersion("1.1.1", newerThan: "1.1"))
        // 数字段比较而非字符串比较：1.10 必须大于 1.9
        XCTAssertTrue(InstallationManager.isVersion("1.10", newerThan: "1.9"))

        // 同版本重启：不得清理
        XCTAssertFalse(InstallationManager.isVersion("1.1", newerThan: "1.1"))
        XCTAssertFalse(InstallationManager.isVersion("1.1.0", newerThan: "1.1"))

        // 降级：不得清理
        XCTAssertFalse(InstallationManager.isVersion("1.0", newerThan: "1.1"))
        XCTAssertFalse(InstallationManager.isVersion("1.9", newerThan: "1.10"))
    }

    func testDomainCertificateStatusMatchesCertificateList() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db, crypto: StorageCrypto(testKey: SymmetricKey(size: .bits256)))
        let service = SnapshotService(repository: repo)
        try repo.createEpoch(id: "badge-epoch", name: "Test", routeDigest: "test", startMs: 1)

        var expectedClusterIds: [String: String] = [:]
        for (index, kind) in ["inspection", "suspected", "public"].enumerated() {
            let caName = "证书列表展示名称-\(kind)"
            let caId = "badge-ca-\(kind)"
            try repo.saveCertificate(
                certId: caId, spkiId: caId, derBytes: Data([0x30]),
                subject: caName, issuer: "Test Root", notBeforeMs: 1, notAfterMs: 2,
                isCa: true, keyUsage: [], sigAlg: "test"
            )
            let clusterId = try repo.upsertCACluster(spkiSha256: caId, caName: caName, identityKind: kind, certId: caId)
            expectedClusterIds[kind] = clusterId
            let target = try repo.getOrCreateTarget(hostname: "\(kind).example.com", port: 8443, requestCount: 7)
            let obs = StorageRepository.ObservationRecord(
                sourceInstanceId: "badge-test", source: .nativeProbe, generation: 1,
                epochId: "badge-epoch", targetId: target, observedAtMs: Int64(index + 1)
            )
            try repo.saveObservation(obs)
            try repo.saveClassification(obsId: obs.id, revision: 1, verdict: .unknown, reason: "TEST_UNKNOWN")
            let leafId = "badge-leaf-\(kind)"
            try repo.saveCertificate(
                certId: leafId, spkiId: leafId, derBytes: Data([0x30]),
                subject: "CN=\(kind).example.com", issuer: "这个 issuer 不得作为列表名称", notBeforeMs: 1, notAfterMs: 2,
                isCa: false, keyUsage: [], sigAlg: "test"
            )
            try repo.linkObservationCertificate(obsId: obs.id, certId: leafId, role: "leaf", chainType: "presented", ordinal: 0)
            try repo.linkObservationCertificate(obsId: obs.id, certId: caId, role: "intermediate", chainType: "presented", ordinal: 1)
        }
        _ = try repo.getOrCreateTarget(hostname: "pending.example.com", port: 443)
        let before = service.listDomains()
        let cas = service.listCAClusters(showAll: true)
        XCTAssertEqual(before.count, 4)
        for row in before where row.hostname != "pending.example.com" {
            let kind = row.hostname.components(separatedBy: ".").first ?? ""
            let clusterId = try XCTUnwrap(expectedClusterIds[kind])
            let ca = try XCTUnwrap(cas.first { $0.clusterId == clusterId })
            XCTAssertEqual(row.certificateClusterId, ca.clusterId)
            XCTAssertEqual(row.certificateSummary, ca.caName)
            XCTAssertEqual(row.certificateIdentityKind, ca.identityKind)
            XCTAssertEqual(row.verdict, .unknown, "证书标签不得覆盖域名本身的探测判定")
            XCTAssertEqual(row.port, 8443)
            XCTAssertEqual(row.requestCount, 7)
        }
        let pending = try XCTUnwrap(before.first { $0.hostname == "pending.example.com" })
        XCTAssertNil(pending.certificateClusterId)
        XCTAssertNil(pending.certificateIdentityKind)
        XCTAssertEqual(pending.certificateSummary ?? "待探测证书", "待探测证书")

        // CA 状态变化后即使域名观测不变，刷新也必须更新标签并被 Equatable 检测到。
        _ = try repo.upsertCACluster(
            spkiSha256: "badge-ca-suspected", caName: "证书列表展示名称-suspected",
            identityKind: "inspection", certId: "badge-ca-suspected"
        )
        let updated = try XCTUnwrap(service.listDomains(search: "suspected.example.com").first)
        XCTAssertEqual(updated.certificateClusterId, expectedClusterIds["suspected"])
        XCTAssertEqual(updated.certificateSummary, "证书列表展示名称-suspected")
        XCTAssertEqual(updated.certificateIdentityKind, "inspection")
        XCTAssertNotEqual(updated, before.first { $0.targetId == updated.targetId })

        // 有证书名称但证书列表已无对应 CA 时，不沿用旧标签或回退到域名判定。
        try db.execute(sql: "DELETE FROM ca_clusters;")
        XCTAssertTrue(service.listDomains().allSatisfy {
            $0.certificateClusterId == nil && $0.certificateSummary == nil && $0.certificateIdentityKind == nil
        })
    }

    func testDomainCertificateStatusCodableCompatibility() throws {
        let row = DomainRow(
            targetId: "test", hostname: "example.com", port: 443, verdict: .unknown,
            discoveredApp: nil, evidenceSource: .nativeProbe, lastObservedMs: 1
        )
        let legacyData = try JSONEncoder().encode(row)
        let legacyRow = try JSONDecoder().decode(DomainRow.self, from: legacyData)
        XCTAssertNil(legacyRow.certificateIdentityKind)
        XCTAssertNil(legacyRow.certificateClusterId)

        var enriched = DomainRow(
            targetId: "test", hostname: "example.com", port: 443, verdict: .unknown,
            discoveredApp: nil, evidenceSource: .nativeProbe, lastObservedMs: 1,
            certificateSummary: "证书列表展示名称"
        )
        enriched.certificateClusterId = "cluster-public"
        enriched.certificateIdentityKind = "public"
        let data = try JSONEncoder().encode(enriched)
        XCTAssertEqual(try JSONDecoder().decode(DomainRow.self, from: data), enriched)
    }
}

private final class ProbeTargetCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [ProbeTarget] = []
    
    func append(_ target: ProbeTarget) {
        lock.lock()
        items.append(target)
        lock.unlock()
    }
    
    func snapshot() -> [ProbeTarget] {
        lock.lock()
        defer { lock.unlock() }
        return items
    }
}

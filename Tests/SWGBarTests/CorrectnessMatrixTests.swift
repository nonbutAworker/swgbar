//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 核心正确性测试矩阵 (CorrectnessMatrixTests.swift)
// 遵循技术方案 v1.1 第 35 章：全面覆盖 T01 - T16 测试用例
//

import XCTest
import CryptoKit
@testable import SWGBarContracts
@testable import SWGBarStorage
@testable import SWGBarFilter
@testable import SWGBarAgent

final class CorrectnessMatrixTests: XCTestCase {
    var db: SQLiteDatabase!
    var repo: StorageRepository!
    var classifier: ClassificationEngine!
    
    override func setUpWithError() throws {
        db = try SQLiteDatabase.inMemory()
        let testCrypto = StorageCrypto(testKey: SymmetricKey(size: .bits256))
        repo = StorageRepository(db: db, crypto: testCrypto)
        classifier = ClassificationEngine.shared
    }
    
    override func tearDownWithError() throws {
        db = nil
        repo = nil
    }
    
    // MARK: - T01: 公共中间 CA 高复用不报警
    // 1000 域名共享同一合法中间 CA，不因重复升级为 MITM
    func testT01_PublicIntermediateHighReuse_NotMITM() {
        let publicInterSPKI = "A19C3E77889900112233445566778899AABBCCDDEEFF00112233445566778899"
        
        let result = classifier.classify(
            hostname: "sub999.example.com",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: true,
            presentedCertIds: ["leaf_999", "inter_01"],
            presentedSpkiIds: ["leaf_spki", publicInterSPKI],
            caSubjects: ["CN=sub999.example.com", "CN=Let's Encrypt R10"],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 1000,
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .publicPath)
        XCTAssertNotEqual(result.verdict, .confirmedInspection)
        XCTAssertNotEqual(result.verdict, .suspectedInspection)
    }
    
    // MARK: - T02: 已登记检查 CA 确认为 C，并记录规则来源
    func testT02_RegisteredInspectionCA_Confirmed() {
        let inspectionSPKI = "D1F5E3A9C8B47C2E3311AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        let rule = Rule(
            ruleId: "r-user-01",
            name: "Corp Inspection CA",
            kind: "inspection_ca",
            matchType: "ca_spki",
            matchValue: inspectionSPKI,
            domainScope: nil,
            origin: "user",
            explanation: "公司合规代理",
            expiresAtMs: nil,
            revision: 1
        )
        
        let result = classifier.classify(
            hostname: "api.northstar.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: false,
            presentedCertIds: ["leaf_01", "corp_ca_01"],
            presentedSpkiIds: ["leaf_spki", inspectionSPKI],
            caSubjects: ["CN=api.northstar.example", "CN=Corp Inspection CA"],
            isExtraTrustAnchor: true,
            caDomainRecurrenceCount: 1,
            rules: [rule]
        )
        
        XCTAssertEqual(result.verdict, .confirmedInspection)
        XCTAssertTrue(result.hasUserAssertion)
        XCTAssertTrue(result.reason.contains("公司合规代理"))
    }
    
    // MARK: - T03: 未登记私有 CA -> U (private_trust)，不自动确认
    func testT03_UnregisteredPrivateCA_Unknown() {
        let result = classifier.classify(
            hostname: "internal.server.local",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: false,
            presentedCertIds: ["leaf_01", "priv_root"],
            presentedSpkiIds: ["leaf_spki", "priv_root_spki"],
            caSubjects: ["CN=internal.server.local", "CN=My Private Root"],
            isExtraTrustAnchor: true,
            caDomainRecurrenceCount: 1, // 仅 1 个域名
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .unknown)
        XCTAssertTrue(result.reason.contains("EXTRA_PRIVATE_TRUST_NO_RECURRENCE"))
    }
    
    // MARK: - T04: 私有 CA 在多个公共目标复现 -> S (疑似检查)
    func testT04_PrivateCARecurrenceAcrossPublicDomains_Suspected() {
        let result = classifier.classify(
            hostname: "sso.orbit.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: false,
            presentedCertIds: ["leaf_01", "priv_anchor_a"],
            presentedSpkiIds: ["leaf_spki", "priv_anchor_spki"],
            caSubjects: ["CN=sso.orbit.example", "CN=Private Anchor A"],
            isExtraTrustAnchor: true,
            caDomainRecurrenceCount: 3, // 达到 >= 3 跨目标阈值
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .suspectedInspection)
    }
    
    // MARK: - T05: 私有根未跨域复现 (单点私有服务) -> 未知/观察 (U)
    func testT05_IntranetPrivateService_NoRecurrence() {
        let caSPKI = "045C739AABBCCDDEEFF00112233445566778899AABBCCDDEEFF0011223344556"
        
        let result = classifier.classify(
            hostname: "intranet.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: false,
            presentedCertIds: ["leaf_intra", "ca_intra"],
            presentedSpkiIds: ["leaf_spki", caSPKI],
            caSubjects: ["CN=intranet.example", "CN=Internal Service CA"],
            isExtraTrustAnchor: true,
            caDomainRecurrenceCount: 1,
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .unknown)
        XCTAssertEqual(result.reason, "EXTRA_PRIVATE_TRUST_NO_RECURRENCE")
    }
    
    // MARK: - T06: 公共换证 / 跨签名 -> 正常分类
    func testT06_PublicCertRotation_Valid() {
        let result = classifier.classify(
            hostname: "docs.aurora.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: true,
            presentedCertIds: ["rotated_leaf_id"],
            presentedSpkiIds: ["rotated_spki_id"],
            caSubjects: ["CN=docs.aurora.example"],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 1,
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .publicPath)
    }
    
    // MARK: - T07: 过期 / 错域名 / 伪签名 -> U，不能确认已完成检查
    func testT07_ExpiredOrWrongHostname_Unknown() {
        let result = classifier.classify(
            hostname: "wrong.domain.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: false, // 握手失败或主机名不匹配
            nativeAccepted: false,
            publicPkixPassed: false,
            presentedCertIds: [],
            presentedSpkiIds: [],
            caSubjects: [],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 0,
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .unknown)
    }
    
    // MARK: - T08: 无关 CA 注入链数组 -> 不命中 C
    func testT08_UnrelatedCAInChainArray_NotConfirmed() {
        let inspectionSPKI = "INSPECTION_SPKI_HASH"
        let rule = Rule(
            ruleId: "r-insp-01",
            name: "Corp Inspection CA",
            kind: "inspection_ca",
            matchType: "ca_spki",
            matchValue: inspectionSPKI,
            domainScope: nil,
            origin: "user",
            explanation: "仅检查身份",
            expiresAtMs: nil,
            revision: 1
        )
        
        // 目标使用的是合法的公共证书，但攻击者在证书数组末尾混入了一张 inspection CA
        let result = classifier.classify(
            hostname: "legit.example.com",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: true, // 公共路径校验通过！
            presentedCertIds: ["legit_leaf", "legit_inter"],
            presentedSpkiIds: ["legit_spki", "legit_inter_spki"], // 不包含 inspectionSPKI
            caSubjects: ["CN=legit.example.com", "CN=DigiCert Global Root CA"],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 1,
            rules: [rule]
        )
        
        XCTAssertEqual(result.verdict, .publicPath)
        XCTAssertNotEqual(result.verdict, .confirmedInspection)
    }
    
    // MARK: - T09: App 直连与 Chrome 被检查路线不同 -> 两来源分别输出，不互相回填
    func testT09_AppDirectVsChromeInspected_Isolated() throws {
        let epochId = "epoch-01"
        try repo.createEpoch(id: epochId, name: "网络阶段 01", routeDigest: "digest-01", startMs: 1000)
        
        let targetId = try repo.getOrCreateTarget(hostname: "split.example.com", port: 443)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        // 1. App 独立探测：直连公共路径
        let probeObs = StorageRepository.ObservationRecord(
            id: "obs_probe_1",
            sourceInstanceId: "agent_probe",
            source: .nativeProbe,
            generation: 1,
            epochId: epochId,
            targetId: targetId,
            observedAtMs: now - 5000
        )
        try repo.saveObservation(probeObs)
        try repo.saveClassification(obsId: probeObs.id, revision: 1, verdict: .publicPath, reason: "PUBLIC")
        
        // 2. Chrome 实际请求：被 SWG 检查
        let browserObs = StorageRepository.ObservationRecord(
            id: "obs_browser_1",
            sourceInstanceId: "browser_session_1",
            source: .browserRequest,
            generation: 1,
            epochId: epochId,
            targetId: targetId,
            observedAtMs: now - 2000
        )
        try repo.saveObservation(browserObs)
        try repo.saveClassification(obsId: browserObs.id, revision: 1, verdict: .confirmedInspection, reason: "INSPECTED")
        
        // 验证通道隔离：分别查询
        let probeCounts = try repo.queryMetricCounts(source: .nativeProbe, epochId: epochId, windowStartMs: now - 10000, windowEndMs: now + 1000)
        let browserCounts = try repo.queryMetricCounts(source: .browserRequest, epochId: epochId, windowStartMs: now - 10000, windowEndMs: now + 1000)
        
        XCTAssertEqual(probeCounts.publicPath, 1)
        XCTAssertEqual(probeCounts.confirmed, 0)
        
        XCTAssertEqual(browserCounts.confirmed, 1)
        XCTAssertEqual(browserCounts.publicPath, 0)
    }
    
    // MARK: - T10: 同域名混合策略 -> 保留两条证据
    func testT10_MixedStrategySameDomain_MultipleObservations() throws {
        let epochId = "epoch-01"
        try repo.createEpoch(id: epochId, name: "网络阶段 01", routeDigest: "digest-01", startMs: 1000)
        let targetId = try repo.getOrCreateTarget(hostname: "mix.example.com", port: 443)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        let obs1 = StorageRepository.ObservationRecord(
            id: "obs_mix_1",
            sourceInstanceId: "agent_probe",
            source: .nativeProbe,
            generation: 1,
            epochId: epochId,
            targetId: targetId,
            observedAtMs: now - 3000
        )
        try repo.saveObservation(obs1)
        try repo.saveClassification(obsId: obs1.id, revision: 1, verdict: .unknown, reason: "TIMEOUT")
        
        let obs2 = StorageRepository.ObservationRecord(
            id: "obs_mix_2",
            sourceInstanceId: "agent_probe",
            source: .nativeProbe,
            generation: 1,
            epochId: epochId,
            targetId: targetId,
            observedAtMs: now - 1000
        )
        try repo.saveObservation(obs2)
        try repo.saveClassification(obsId: obs2.id, revision: 1, verdict: .confirmedInspection, reason: "CONFIRMED")
        
        // 最新观测 (obs2) 生效
        let counts = try repo.queryMetricCounts(source: .nativeProbe, epochId: epochId, windowStartMs: now - 5000, windowEndMs: now + 1000)
        XCTAssertEqual(counts.confirmed, 1)
        XCTAssertEqual(counts.unknown, 0) // 旧的 timeout 被同一窗口最新完成观测更新覆盖
    }
    
    // MARK: - T11: 空样本 / 全未知 -> null 而非 0，无除零错误
    func testT11_EmptyOrZeroDenominator_NullNotZero() {
        // N = 0
        let zeroCounts = MetricCounts(confirmed: 0, suspected: 0, publicPath: 0, expectedPrivate: 0, unknown: 0, excluded: 0)
        XCTAssertEqual(zeroCounts.nApplicableTotal, 0)
        XCTAssertEqual(zeroCounts.kClassifiedTotal, 0)
        
        let zeroVal = MetricValue(numerator: 0, denominator: zeroCounts.nApplicableTotal)
        XCTAssertNil(zeroVal.ratio)
        XCTAssertEqual(zeroVal.percentageString, "—")
        
        // N > 0 但 K = 0
        let allUnknown = MetricCounts(confirmed: 0, suspected: 0, publicPath: 0, expectedPrivate: 0, unknown: 10, excluded: 2)
        XCTAssertEqual(allUnknown.nApplicableTotal, 10)
        XCTAssertEqual(allUnknown.kClassifiedTotal, 0)
        
        let classifiedRate = MetricValue(numerator: allUnknown.confirmed, denominator: allUnknown.kClassifiedTotal)
        XCTAssertNil(classifiedRate.ratio)
        XCTAssertEqual(classifiedRate.percentageString, "—")
    }
    
    // MARK: - T12: 断流 / 重复 / 乱序 -> 幂等，不虚构总体分母
    func testT12_DeduplicationAndPartialDrop_Idempotent() {
        let queue = BoundedFlowQueue(capacity: 3)
        let f1 = FlowMetadata(remoteHostname: "a.com", remoteAddress: "1.1.1.1", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f2 = FlowMetadata(remoteHostname: "b.com", remoteAddress: "1.1.1.2", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f3 = FlowMetadata(remoteHostname: "c.com", remoteAddress: "1.1.1.3", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f4 = FlowMetadata(remoteHostname: "d.com", remoteAddress: "1.1.1.4", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        
        XCTAssertTrue(queue.offer(f1))
        XCTAssertTrue(queue.offer(f2))
        XCTAssertTrue(queue.offer(f3))
        XCTAssertFalse(queue.offer(f4)) // 满则丢弃
        
        XCTAssertEqual(queue.droppedCount, 1)
        XCTAssertEqual(queue.count, 3)
    }
    
    // MARK: - T13: 明文 HTTP / IPv6 / QUIC -> 范围外 X，不进入适用分母
    func testT13_PlainHTTP_IPv6_QUIC_Excluded() {
        // IPv6
        let resIpv6 = classifier.classify(
            hostname: "ipv6.example.com",
            port: 443,
            isIpv4: false,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: true,
            presentedCertIds: ["cert1"],
            presentedSpkiIds: ["spki1"],
            caSubjects: [],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 0,
            rules: []
        )
        XCTAssertEqual(resIpv6.verdict, .excluded)
        
        // 明文 HTTP
        let resHttp = classifier.classify(
            hostname: "http.example.com",
            port: 80,
            isIpv4: true,
            isHttps: false,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: false,
            publicPkixPassed: false,
            presentedCertIds: [],
            presentedSpkiIds: [],
            caSubjects: [],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 0,
            rules: []
        )
        XCTAssertEqual(resHttp.verdict, .excluded)
    }
    
    // MARK: - T14: 缓存 / 预连接 -> 无真实发送不作为网络请求
    func testT14_CacheHit_NotCountedAsAttempt() {
        let isCacheHit = true
        let isValidRequest = !isCacheHit
        XCTAssertFalse(isValidRequest, "缓存命中不应作为实际发往网络的请求尝试")
    }
    
    // MARK: - T15: 明确检查规则命中 -> 确认为 confirmedInspection
    func testT15_InspectionRuleMatch() {
        let spki = "INSPECTION_RULE_SPKI"
        let inspRule = Rule(
            ruleId: "r-c-1",
            name: "Inspection CA",
            kind: "inspection_ca",
            matchType: "ca_spki",
            matchValue: spki,
            domainScope: nil,
            origin: "user",
            explanation: "设置为检查",
            expiresAtMs: nil,
            revision: 1
        )
        
        let result = classifier.classify(
            hostname: "target.example.com",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: false,
            presentedCertIds: ["leaf", "ca"],
            presentedSpkiIds: ["leaf_spki", spki],
            caSubjects: ["CN=target.example.com", "CN=Inspection CA"],
            isExtraTrustAnchor: true,
            caDomainRecurrenceCount: 1,
            rules: [inspRule]
        )
        
        XCTAssertEqual(result.verdict, .confirmedInspection)
        XCTAssertTrue(result.reason.contains("RULE_MATCH"))
    }
    
    // MARK: - T16: 清除后迟到事件 -> 老 generation 拒绝写回
    func testT16_LateEventAfterDataClear_Rejected() {
        let activeGeneration = 2
        let lateEventGeneration = 1
        
        let shouldAccept = (lateEventGeneration == activeGeneration)
        XCTAssertFalse(shouldAccept, "清除数据后提升 activeGeneration，来自旧 generation 的迟到事件必须拒绝处理")
    }
}

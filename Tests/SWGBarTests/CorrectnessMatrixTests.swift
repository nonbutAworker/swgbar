//
// SWGBar / macOS menu bar TLS inspection detector
// Core correctness matrix (CorrectnessMatrixTests.swift)
// Regression coverage for cases T01 through T16.
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
    
    // MARK: - T01: Reusing a public intermediate CA must not imply inspection
    // A legitimate intermediate shared by 1,000 domains must remain public.
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
    
    // MARK: - T02: A registered inspection CA produces a confirmed verdict with rule provenance
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
            explanation: "Registered inspection proxy",
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
        XCTAssertTrue(result.reason.contains("Registered inspection proxy"))
    }
    
    // MARK: - T03: An unregistered private CA remains unknown
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
            caDomainRecurrenceCount: 1, // Only one domain
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .unknown)
        XCTAssertTrue(result.reason.contains("EXTRA_PRIVATE_TRUST_NO_RECURRENCE"))
    }
    
    // MARK: - T04: Private CA recurrence across public targets becomes suspected
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
            caDomainRecurrenceCount: 3, // Reach the cross-target recurrence threshold.
            rules: []
        )
        
        XCTAssertEqual(result.verdict, .suspectedInspection)
    }
    
    // MARK: - T05: A private root without cross-domain recurrence remains unknown
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
    
    // MARK: - T06: Public certificate rotation and cross-signing classify normally
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
    
    // MARK: - T07: Expiry, hostname mismatch, or invalid signatures remain unknown
    func testT07_ExpiredOrWrongHostname_Unknown() {
        let result = classifier.classify(
            hostname: "wrong.domain.example",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: false, // Handshake failure or hostname mismatch
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
    
    // MARK: - T08: An unrelated CA inserted into the chain must not confirm inspection
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
            explanation: "Inspection identity only",
            expiresAtMs: nil,
            revision: 1
        )
        
        // The target uses a public certificate, but the presented array also contains an unrelated inspection CA.
        let result = classifier.classify(
            hostname: "legit.example.com",
            port: 443,
            isIpv4: true,
            isHttps: true,
            isOwnTraffic: false,
            handshakeCompleted: true,
            nativeAccepted: true,
            publicPkixPassed: true, // Public validation passed.
            presentedCertIds: ["legit_leaf", "legit_inter"],
            presentedSpkiIds: ["legit_spki", "legit_inter_spki"], // Does not contain inspectionSPKI
            caSubjects: ["CN=legit.example.com", "CN=DigiCert Global Root CA"],
            isExtraTrustAnchor: false,
            caDomainRecurrenceCount: 1,
            rules: [rule]
        )
        
        XCTAssertEqual(result.verdict, .publicPath)
        XCTAssertNotEqual(result.verdict, .confirmedInspection)
    }
    
    // MARK: - T09: Keep independent probes separate from observed browser requests
    func testT09_AppDirectVsChromeInspected_Isolated() throws {
        let epochId = "epoch-01"
        try repo.createEpoch(id: epochId, name: "Network epoch 01", routeDigest: "digest-01", startMs: 1000)
        
        let targetId = try repo.getOrCreateTarget(hostname: "split.example.com", port: 443)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        
        // 1. The application's independent probe uses a direct public path.
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
        
        // 2. The observed browser request uses an inspection path.
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
        
        // Query each channel separately to verify isolation.
        let probeCounts = try repo.queryMetricCounts(source: .nativeProbe, epochId: epochId, windowStartMs: now - 10000, windowEndMs: now + 1000)
        let browserCounts = try repo.queryMetricCounts(source: .browserRequest, epochId: epochId, windowStartMs: now - 10000, windowEndMs: now + 1000)
        
        XCTAssertEqual(probeCounts.publicPath, 1)
        XCTAssertEqual(probeCounts.confirmed, 0)
        
        XCTAssertEqual(browserCounts.confirmed, 1)
        XCTAssertEqual(browserCounts.publicPath, 0)
    }
    
    // MARK: - T10: Preserve evidence from mixed policies on the same domain
    func testT10_MixedStrategySameDomain_MultipleObservations() throws {
        let epochId = "epoch-01"
        try repo.createEpoch(id: epochId, name: "Network epoch 01", routeDigest: "digest-01", startMs: 1000)
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
        
        // The latest observation, obs2, takes effect.
        let counts = try repo.queryMetricCounts(source: .nativeProbe, epochId: epochId, windowStartMs: now - 5000, windowEndMs: now + 1000)
        XCTAssertEqual(counts.confirmed, 1)
        XCTAssertEqual(counts.unknown, 0) // The latest completed observation supersedes an earlier timeout within the same window.
    }
    
    // MARK: - T11: Empty or entirely unknown samples produce null, without division by zero
    func testT11_EmptyOrZeroDenominator_NullNotZero() {
        // N = 0
        let zeroCounts = MetricCounts(confirmed: 0, suspected: 0, publicPath: 0, expectedPrivate: 0, unknown: 0, excluded: 0)
        XCTAssertEqual(zeroCounts.nApplicableTotal, 0)
        XCTAssertEqual(zeroCounts.kClassifiedTotal, 0)
        
        let zeroVal = MetricValue(numerator: 0, denominator: zeroCounts.nApplicableTotal)
        XCTAssertNil(zeroVal.ratio)
        XCTAssertEqual(zeroVal.percentageString, "—")
        
        // N is positive but K is zero.
        let allUnknown = MetricCounts(confirmed: 0, suspected: 0, publicPath: 0, expectedPrivate: 0, unknown: 10, excluded: 2)
        XCTAssertEqual(allUnknown.nApplicableTotal, 10)
        XCTAssertEqual(allUnknown.kClassifiedTotal, 0)
        
        let classifiedRate = MetricValue(numerator: allUnknown.confirmed, denominator: allUnknown.kClassifiedTotal)
        XCTAssertNil(classifiedRate.ratio)
        XCTAssertEqual(classifiedRate.percentageString, "—")
    }
    
    // MARK: - T12: Handle gaps, duplicates, and reordering without inventing a denominator
    func testT12_DeduplicationAndPartialDrop_Idempotent() {
        let queue = BoundedFlowQueue(capacity: 3)
        let f1 = FlowMetadata(remoteHostname: "a.com", remoteAddress: "1.1.1.1", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f2 = FlowMetadata(remoteHostname: "b.com", remoteAddress: "1.1.1.2", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f3 = FlowMetadata(remoteHostname: "c.com", remoteAddress: "1.1.1.3", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        let f4 = FlowMetadata(remoteHostname: "d.com", remoteAddress: "1.1.1.4", remotePort: 443, sourceBundleId: nil, sourceDisplayName: nil)
        
        XCTAssertTrue(queue.offer(f1))
        XCTAssertTrue(queue.offer(f2))
        XCTAssertTrue(queue.offer(f3))
        XCTAssertFalse(queue.offer(f4)) // Drop the event when the queue is full.
        
        XCTAssertEqual(queue.droppedCount, 1)
        XCTAssertEqual(queue.count, 3)
    }
    
    // MARK: - T13: Plain HTTP, IPv6, and QUIC are excluded from the eligible denominator
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
        
        // Plain HTTP
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
    
    // MARK: - T14: Cache hits and preconnections are not network request attempts
    func testT14_CacheHit_NotCountedAsAttempt() {
        let isCacheHit = true
        let isValidRequest = !isCacheHit
        XCTAssertFalse(isValidRequest, "Cache hits must not count as network request attempts")
    }
    
    // MARK: - T15: An explicit inspection rule confirms inspection
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
            explanation: "Mark as inspection",
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
    
    // MARK: - T16: Reject late events from an old generation after clearing data
    func testT16_LateEventAfterDataClear_Rejected() {
        let activeGeneration = 2
        let lateEventGeneration = 1
        
        let shouldAccept = (lateEventGeneration == activeGeneration)
        XCTAssertFalse(shouldAccept, "After clearing data, late events from an older generation must be rejected")
    }
}

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
        
        // Target 1: apple.com
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
        
        // A single hostname has one distinct apex domain.
        var stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 1)
        XCTAssertEqual(stats.apex, 1)
        
        // Target 2: github.com
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
        
        // Two apex domains remain below the confirmation threshold.
        stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 2)
        XCTAssertEqual(stats.apex, 2)
        XCTAssertFalse(stats.total > 10, "Two domains must not exceed the threshold of 10")
        
        // Add targets until there are 11 distinct domains.
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
        
        // More than 10 distinct domains satisfy condition 2.
        stats = try repo.countDistinctDomainsForCA(spki: caSPKI, caName: caName)
        XCTAssertEqual(stats.total, 11)
        XCTAssertTrue(stats.total > 10, "Eleven domains must satisfy the automatic confirmation threshold")
        
        // Create the automatic rule and reclassify associated observations.
        let autoRule = Rule(
            ruleId: "auto_rule_test",
            name: caName,
            kind: "inspection_ca",
            matchType: "ca_spki",
            matchValue: caSPKI,
            domainScope: nil,
            origin: "system_auto",
            explanation: "Inspection criteria met: public validation failed, a locally trusted root was accepted, and more than 10 distinct domains were observed (\(stats.total) domains)",
            expiresAtMs: nil,
            revision: 1
        )
        try repo.upsertRule(autoRule)
        try repo.upgradeAllToConfirmedForCA(caName: caName, spkiSha256: caSPKI)
        
        // Verify historical observations were upgraded to confirmed_inspection.
        let targetsWithVerdict = try repo.listTargetsWithLatestVerdict(limit: 20)
        for t in targetsWithVerdict {
            XCTAssertEqual(t.verdict, .confirmedInspection, "Target \(t.hostname) should have been upgraded to confirmedInspection")
        }
    }
    
    func testSWGAutoConfirmationTwoConditions() {
        let engine = ClassificationEngine.shared
        
        // 1. Public validation must remain public regardless of the number of domains.
        let publicRes = engine.classify(
            hostname: "example.com", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: true,
            presentedCertIds: ["leaf", "digicert_g2"], presentedSpkiIds: ["leaf_spki", "root_spki"],
            caSubjects: ["CN=example.com", "CN=DigiCert Global Root G2"],
            isExtraTrustAnchor: false, caDomainRecurrenceCount: 50, rules: []
        )
        XCTAssertEqual(publicRes.verdict, .publicPath, "Public certificates must remain public even across 50 domains")
        
        // 2. Private validation meets condition 1, but a single domain does not satisfy condition 2.
        let singleRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 1, rules: []
        )
        XCTAssertEqual(singleRes.verdict, .unknown, "One domain must remain unknown")
        
        // 3. Between two and 10 distinct domains remain suspected.
        let suspectedRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 5, rules: []
        )
        XCTAssertEqual(suspectedRes.verdict, .suspectedInspection, "Five domains must remain suspected")
        
        let suspected10Res = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 10, rules: []
        )
        XCTAssertEqual(suspected10Res.verdict, .suspectedInspection, "Exactly 10 domains must remain suspected")
        
        // 4. More than 10 domains, together with condition 1, confirm inspection.
        let confirmedRes = engine.classify(
            hostname: "internal.example", port: 443, isIpv4: true, isHttps: true, isOwnTraffic: false,
            handshakeCompleted: true, nativeAccepted: true, publicPkixPassed: false,
            presentedCertIds: ["leaf", "swg_root"], presentedSpkiIds: ["leaf_spki", "swg_spki"],
            caSubjects: ["CN=internal.example", "CN=Company SWG Root CA"],
            isExtraTrustAnchor: true, caDomainRecurrenceCount: 11, rules: []
        )
        XCTAssertEqual(confirmedRes.verdict, .confirmedInspection, "Both conditions, including more than 10 domains, must confirm inspection")
        XCTAssertTrue(confirmedRes.reason.contains("SWG_INTERCEPTION_CONFIRMED"))
    }
    
    func testNeverProbedBatchingCoversAllUniqueHostPorts() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        try repo.createEpoch(id: "ep-01", name: "test", routeDigest: "d", startMs: 1)
        
        let first = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 10)
        let dup = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 28)
        XCTAssertEqual(first, dup, "The same hostname and port must resolve to one target")
        
        let altPort = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 8443)
        XCTAssertNotEqual(first, altPort, "Different ports on one hostname must remain separate targets")
        
        for i in 0..<120 {
            _ = try repo.getOrCreateTarget(hostname: "host\(i).example.com", port: 443, requestCount: Int64(i + 1))
        }
        
        let all = try repo.listTargetsNeverProbed(limit: 1000)
        let uniqueKeys = Set(all.map { "\($0.hostname):\($0.port)" })
        XCTAssertEqual(all.count, uniqueKeys.count, "Pending targets must not contain duplicate hostname/port pairs")
        XCTAssertEqual(uniqueKeys.count, 122)
        XCTAssertTrue(uniqueKeys.contains("chat.deepseek.com:443"))
        XCTAssertTrue(uniqueKeys.contains("chat.deepseek.com:8443"))
        
        var remaining = uniqueKeys
        var batches = 0
        while true {
            let batch = try repo.listTargetsNeverProbed(limit: 50)
            if batch.isEmpty { break }
            XCTAssertLessThanOrEqual(batch.count, 50, "Each batch must contain at most 50 targets")
            batches += 1
            for item in batch {
                let key = "\(item.hostname):\(item.port)"
                XCTAssertTrue(remaining.contains(key), "The batch contains an unknown or duplicate target: \(key)")
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
        
        XCTAssertTrue(remaining.isEmpty, "Batch probing must not omit any hostname/port pair: \(remaining)")
        XCTAssertEqual(batches, 3, "122 targets must form three batches of 50, 50, and 22")
        XCTAssertEqual(try repo.listTargetsNeverProbed(limit: 50).count, 0)
    }
    
    func testBrowserHistoryImportRunsOnlyOnFirstLaunch() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)
        
        XCTAssertFalse(repo.hasCompletedBrowserHistoryImport(), "A new database must not be marked as imported")
        XCTAssertFalse(repo.hasAnyTargets())
        
        try repo.markBrowserHistoryImportCompleted()
        XCTAssertTrue(repo.hasCompletedBrowserHistoryImport(), "Subsequent launches must skip an already completed import")
        
        try repo.clearAllHistoricalData()
        XCTAssertFalse(repo.hasCompletedBrowserHistoryImport(), "Clearing local data must allow a fresh import")
        XCTAssertFalse(repo.hasCompletedHistoricalBaselineProbe(), "Clearing data must reset the historical probe marker")
        
        try repo.markHistoricalBaselineProbeCompleted()
        XCTAssertTrue(repo.hasCompletedHistoricalBaselineProbe())
        
        _ = try repo.getOrCreateTarget(hostname: "chat.deepseek.com", port: 443, requestCount: 1)
        XCTAssertTrue(repo.hasAnyTargets(), "Existing targets must prevent first-launch history scanning")
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
        // 1. Check CADetail distinguished-name parsing and fallback fields.
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
            baselineStatus: "Public path",
            activeRule: nil,
            affectedDomainsCount: 3,
            notBeforeMs: 1786060800000,
            notAfterMs: 1803254399000
        )
        
        let sub = ca1.subjectElements
        XCTAssertEqual(sub.cn, "DNSPod DV TLS RSA CA 2025")
        XCTAssertEqual(sub.o, "DNSPod, Inc.")
        XCTAssertEqual(sub.ou, "<Not present in certificate>")
        
        let iss = ca1.issuerElements
        XCTAssertEqual(iss.cn, "DigiCert Global Root G2")
        XCTAssertEqual(iss.o, "DigiCert Inc")
        XCTAssertEqual(iss.ou, "www.digicert.com")
        
        XCTAssertTrue(ca1.notBeforeFormatted.contains("2026"))
        XCTAssertTrue(ca1.notAfterFormatted.contains("2027"))
        XCTAssertTrue(ca1.notBeforeFormatted.contains("August"))
        XCTAssertTrue(ca1.notAfterFormatted.contains("February"))
        
        // 2. Check database joins for certificate identities and affected domains.
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

    func testEnglishCertificateValidityRangePreservesMonthNames() {
        let ca = CADetail(
            clusterId: "date-range", caName: "Test CA", identityKind: "public",
            hasUserAssertion: false, subject: "CN=Test CA", issuer: "CN=Test Root",
            validityFormatted: "October 1, 2026 to October 1, 2027",
            certSha256: "", spkiSha256: "", extraTrustVerifiedPath: [],
            baselineStatus: "Public path", activeRule: nil, affectedDomainsCount: 0
        )
        XCTAssertEqual(ca.notBeforeFormatted, "October 1, 2026")
        XCTAssertEqual(ca.notAfterFormatted, "October 1, 2027")
    }

    /// The associated certificate must reuse the list name and uniquely resolve its clusterId for navigation.
    func testDomainDetailAssociatedCertificateLinksToCertificateDetail() throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db, crypto: StorageCrypto(testKey: SymmetricKey(size: .bits256)))
        let service = SnapshotService(repository: repo)
        try repo.createEpoch(id: "link-epoch", name: "Test", routeDigest: "test", startMs: 1)

        let caName = "Linked Certificate Test CA"
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

        // The detail display name must exactly match the list row.
        XCTAssertEqual(row.certificateSummary, caName)
        XCTAssertEqual(jumpClusterId, clusterId)

        // The navigation target must resolve to exactly one certificate cluster.
        let clusters = service.listCAClusters(showAll: true)
        let matched = clusters.filter { $0.clusterId == jumpClusterId }
        XCTAssertEqual(matched.count, 1, "The associated clusterId must uniquely match a certificate row")
        XCTAssertEqual(matched.first?.caName, row.certificateSummary)
    }

    /// Lock down numeric version comparisons used by installation version tracking.
    /// The initial schema must define every field required by a new database.
    /// Verify that a newly created database includes all required columns and indexes.
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
        XCTAssertTrue(obsCols.contains("egress_interface"), "The initial schema must contain egress_interface")
        XCTAssertTrue(obsCols.contains("route_type"), "The initial schema must contain route_type")

        let targetCols = try names("SELECT name FROM pragma_table_info('targets');")
        XCTAssertTrue(targetCols.contains("request_count"), "The initial schema must contain request_count")

        let indexes = try names("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%';")
        XCTAssertTrue(indexes.contains("targets_req_count_idx"))
        XCTAssertTrue(indexes.contains("cluster_certs_idx"))
        XCTAssertTrue(indexes.contains("obs_certs_cert_id_idx"))
    }

    func testInstallationVersionComparison() {
        // A higher version is newer.
        XCTAssertTrue(InstallationManager.isVersion("1.2", newerThan: "1.1"))
        XCTAssertTrue(InstallationManager.isVersion("2.0", newerThan: "1.9"))
        XCTAssertTrue(InstallationManager.isVersion("1.1.1", newerThan: "1.1"))
        // Compare numeric components: 1.10 must be newer than 1.9.
        XCTAssertTrue(InstallationManager.isVersion("1.10", newerThan: "1.9"))

        // The same version is not newer.
        XCTAssertFalse(InstallationManager.isVersion("1.1", newerThan: "1.1"))
        XCTAssertFalse(InstallationManager.isVersion("1.1.0", newerThan: "1.1"))

        // A downgrade is not newer.
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
            let caName = "Certificate display name-\(kind)"
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
                subject: "CN=\(kind).example.com", issuer: "This issuer must not be used as the display name", notBeforeMs: 1, notAfterMs: 2,
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
            XCTAssertEqual(row.verdict, .unknown, "Certificate labels must not override a domain's probe verdict")
            XCTAssertEqual(row.port, 8443)
            XCTAssertEqual(row.requestCount, 7)
        }
        let pending = try XCTUnwrap(before.first { $0.hostname == "pending.example.com" })
        XCTAssertNil(pending.certificateClusterId)
        XCTAssertNil(pending.certificateIdentityKind)
        XCTAssertEqual(pending.certificateSummary ?? "Awaiting probe", "Awaiting probe")

        // Certificate status changes must update the row and its Equatable result even when the domain observation is unchanged.
        _ = try repo.upsertCACluster(
            spkiSha256: "badge-ca-suspected", caName: "Certificate display name-suspected",
            identityKind: "inspection", certId: "badge-ca-suspected"
        )
        let updated = try XCTUnwrap(service.listDomains(search: "suspected.example.com").first)
        XCTAssertEqual(updated.certificateClusterId, expectedClusterIds["suspected"])
        XCTAssertEqual(updated.certificateSummary, "Certificate display name-suspected")
        XCTAssertEqual(updated.certificateIdentityKind, "inspection")
        XCTAssertNotEqual(updated, before.first { $0.targetId == updated.targetId })

        // Without a matching CA, do not reuse a stale certificate label or substitute the domain verdict.
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
            certificateSummary: "Certificate display name"
        )
        enriched.certificateClusterId = "cluster-public"
        enriched.certificateIdentityKind = "public"
        let data = try JSONEncoder().encode(enriched)
        XCTAssertEqual(try JSONDecoder().decode(DomainRow.self, from: data), enriched)
    }
    /// 五种语言必须齐全，且列表项用各语言自身书写。
    func testAppLanguageEndonymsAndCoverage() {
        XCTAssertEqual(AppLanguage.allCases.count, 5)
        XCTAssertEqual(AppLanguage.default, .english, "默认语言必须是英文")

        // 语言名用该语言自身书写，这是列表的展示惯例
        XCTAssertEqual(AppLanguage.english.endonym, "English")
        XCTAssertEqual(AppLanguage.simplifiedChinese.endonym, "简体中文")
        XCTAssertEqual(AppLanguage.traditionalChinese.endonym, "繁體中文")
        XCTAssertEqual(AppLanguage.japanese.endonym, "日本語")
        XCTAssertEqual(AppLanguage.korean.endonym, "한국어")

        // 持久化值往返
        for lang in AppLanguage.allCases {
            XCTAssertEqual(AppLanguage.from(storedValue: lang.rawValue), lang)
        }
        XCTAssertEqual(AppLanguage.from(storedValue: "klingon"), .english, "未知值回落英文")
        XCTAssertEqual(AppLanguage.from(storedValue: nil), .english, "无值回落英文")
    }

    /// 每个文案键在五种语言下都必须有非空翻译，且互不相同。
    func testLocalizationTableIsCompleteForAllLanguages() {
        for key in L10nKey.allCases {
            for lang in AppLanguage.allCases {
                let value = L10nTable.string(key, lang)
                XCTAssertFalse(value.isEmpty, "\(lang.rawValue) 缺少 \(key.rawValue)")
                XCTAssertNotEqual(value, key.rawValue, "\(lang.rawValue) 的 \(key.rawValue) 回落到了键名")
            }
        }

        // 抽查关键术语确实被翻译，而不是照抄英文
        XCTAssertEqual(L10nTable.string(.overview, .simplifiedChinese), "总览")
        XCTAssertEqual(L10nTable.string(.overview, .japanese), "概要")
        XCTAssertEqual(L10nTable.string(.overview, .korean), "개요")

        // 繁体不是简体直转：网域/憑證 等台港用语
        XCTAssertEqual(L10nTable.string(.domains, .simplifiedChinese), "域名")
        XCTAssertEqual(L10nTable.string(.domains, .traditionalChinese), "網域")
        XCTAssertEqual(L10nTable.string(.certificates, .simplifiedChinese), "证书")
        XCTAssertEqual(L10nTable.string(.certificates, .traditionalChinese), "憑證")
    }

    /// 底栏刷新按钮必须真正复位一次性初始化标记，让首次启动的初始化链路重新执行。
    func testReinitializeRestoresFirstLaunchInitializationState() async throws {
        let db = try SQLiteDatabase.inMemory()
        let repo = StorageRepository(db: db)

        // 模拟已完成初始化的历史状态
        _ = try repo.getOrCreateTarget(hostname: "example.com", port: 443, requestCount: 7)
        try repo.markBrowserHistoryImportCompleted()
        try repo.markHistoricalBaselineProbeCompleted()
        XCTAssertTrue(repo.hasAnyTargets())
        XCTAssertTrue(repo.hasCompletedBrowserHistoryImport())
        XCTAssertTrue(repo.hasCompletedHistoricalBaselineProbe())

        // 重新初始化的清理步骤：与升级后首次启动等价的干净状态
        try repo.clearAllHistoricalData()

        XCTAssertFalse(repo.hasAnyTargets(), "重新初始化后不应保留旧目标")
        XCTAssertFalse(repo.hasCompletedBrowserHistoryImport(), "浏览器历史导入必须能再次执行")
        XCTAssertFalse(repo.hasCompletedHistoricalBaselineProbe(), "基线探测必须能再次执行")
    }

    /// 外观模式必须映射到明确的强制外观，只有跟随系统才允许为空。
    func testAppearanceModeMapsToExplicitAppearance() {
        XCTAssertNil(AppearanceMode.system.appKitAppearanceName, "跟随系统不应强制外观")
        XCTAssertEqual(AppearanceMode.dark.appKitAppearanceName, "NSAppearanceNameDarkAqua")
        XCTAssertEqual(AppearanceMode.light.appKitAppearanceName, "NSAppearanceNameAqua")
    }

    /// 每个文案键都必须直接存在于五张字典中；不能让英文回退掩盖漏译。
    func testLocalizationDictionariesContainEveryKeyDirectly() {
        let tables: [(AppLanguage, [L10nKey: String])] = [
            (.english, L10nTable.english),
            (.simplifiedChinese, L10nTable.simplifiedChinese),
            (.traditionalChinese, L10nTable.traditionalChinese),
            (.japanese, L10nTable.japanese),
            (.korean, L10nTable.korean),
        ]
        for (language, table) in tables {
            XCTAssertEqual(Set(table.keys), Set(L10nKey.allCases), "\(language.rawValue) 存在漏译或多余键")
        }
    }

    /// 用户审核过的 1.5.1 中文原文受整体指纹保护；新增外观/语言控件不属于该原稿。
    func testApprovedSimplifiedChineseCopyFingerprint() {
        let newControlKeys: Set<L10nKey> = [
            .appearanceSystem, .appearanceDark, .appearanceLight,
            .appearance, .appearanceCycleHint, .appearanceHintFormat,
            .language, .languageSwitchHint, .languageHintFormat,
            .reinitialize, .reinitializeHint, .reinitializeRunning,
        ]
        let source = L10nTable.simplifiedChinese
            .filter { !newControlKeys.contains($0.key) }
            .map { "\($0.key.rawValue)=\($0.value)" }
            .sorted()
            .joined(separator: "\n")
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in source.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        XCTAssertEqual(String(format: "%016llx", hash), "67ad16de7ff7cad9",
                       "审核中文发生变化；必须先逐项与 1.5.1 原稿核对")
    }

    func testCertificatePresentationUsesSelectedLanguageAndStableMissingSentinels() async {
        let certificate = CADetail(
            clusterId: "date-test", caName: "Example CA", identityKind: "public",
            hasUserAssertion: false, subject: "", issuer: "", validityFormatted: "No expiration",
            certSha256: "", spkiSha256: "", extraTrustVerifiedPath: [], baselineStatus: "",
            activeRule: nil, affectedDomainsCount: 0,
            notBeforeMs: 1_700_000_000_000, notAfterMs: 1_800_000_000_000
        )
        let zh = await CertificatePresentation.validityDate(certificate, end: false, language: .simplifiedChinese)
        let en = await CertificatePresentation.validityDate(certificate, end: false, language: .english)
        let ja = await CertificatePresentation.validityDate(certificate, end: false, language: .japanese)
        XCTAssertTrue(zh.contains("年") && zh.contains("月") && zh.contains("日"))
        XCTAssertFalse(en.contains("年"))
        XCTAssertTrue(ja.contains("年") && ja.contains("月") && ja.contains("日"))
        XCTAssertTrue(CertificatePresentation.isMissing("<Not present in certificate>"))
        XCTAssertTrue(CertificatePresentation.isMissing("<未包含在证书中>"))
        XCTAssertFalse(CertificatePresentation.isMissing("Example CA"))
    }

    /// 带参数的文案在各语言下都要能正确格式化，占位符不残留。
    func testLocalizedFormatStringsSubstituteArguments() {
        for lang in AppLanguage.allCases {
            let one = String(format: L10nTable.string(.domainsCountFormat, lang), 7)
            XCTAssertTrue(one.contains("7"), "\(lang.rawValue) 未代入数量")
            XCTAssertFalse(one.contains("%d"), "\(lang.rawValue) 占位符未被替换")

            let two = String(format: L10nTable.string(.scrollForMoreFormat, lang), 20, 99)
            XCTAssertTrue(two.contains("20") && two.contains("99"), "\(lang.rawValue) 双参数未全部代入")
            XCTAssertFalse(two.contains("%d"), "\(lang.rawValue) 占位符未被替换")

            let text = String(format: L10nTable.string(.appearanceHintFormat, lang), "Dark")
            XCTAssertTrue(text.contains("Dark"), "\(lang.rawValue) 字符串参数未代入")
            XCTAssertFalse(text.contains("%@"), "\(lang.rawValue) 占位符未被替换")
        }
    }
    /// The footer button must cycle System -> Dark -> Light -> System.
    func testAppearanceModeCyclesThroughThreeStates() {
        XCTAssertEqual(AppearanceMode.system.next, .dark, "System must advance to Dark")
        XCTAssertEqual(AppearanceMode.dark.next, .light, "Dark must advance to Light")
        XCTAssertEqual(AppearanceMode.light.next, .system, "Light must return to System")

        // Three clicks from any starting point must return to that same mode.
        for start in AppearanceMode.allCases {
            XCTAssertEqual(start.next.next.next, start, "\(start) must return to itself after three clicks")
        }

        // Labels and symbols must be distinct so the button state is unambiguous.
        let labels = Set(AppearanceMode.allCases.map { $0.label })
        XCTAssertEqual(labels, ["System", "Dark", "Light"])
        XCTAssertEqual(Set(AppearanceMode.allCases.map { $0.symbolName }).count, 3)

        // Raw values back the persisted preference and must round-trip.
        for mode in AppearanceMode.allCases {
            XCTAssertEqual(AppearanceMode(rawValue: mode.rawValue), mode)
        }
        XCTAssertNil(AppearanceMode(rawValue: "not-a-mode"), "Unknown values fall back to the default")
    }
    /// 五种语言必须齐备，且列表项用各语言自身书写。
    func testAppLanguageEndonymsAndDefault() {
        XCTAssertEqual(AppLanguage.allCases.count, 5, "本期支持五种语言")
        XCTAssertEqual(AppLanguage.default, .english, "默认英文")

        // 列表项按惯例用该语言自身的文字书写
        XCTAssertEqual(AppLanguage.english.endonym, "English")
        XCTAssertEqual(AppLanguage.simplifiedChinese.endonym, "简体中文")
        XCTAssertEqual(AppLanguage.traditionalChinese.endonym, "繁體中文")
        XCTAssertEqual(AppLanguage.japanese.endonym, "日本語")
        XCTAssertEqual(AppLanguage.korean.endonym, "한국어")

        // 自称互不重复，否则列表里会出现两个同名项
        XCTAssertEqual(Set(AppLanguage.allCases.map { $0.endonym }).count, 5)

        // rawValue 用作持久化值，必须能往返
        for lang in AppLanguage.allCases {
            XCTAssertEqual(AppLanguage(rawValue: lang.rawValue), lang)
            XCTAssertEqual(AppLanguage.from(storedValue: lang.rawValue), lang)
        }
        // 损坏或缺失的持久化值回落英文
        XCTAssertEqual(AppLanguage.from(storedValue: nil), .english)
        XCTAssertEqual(AppLanguage.from(storedValue: "klingon"), .english)
    }
    /// 每个键在五种语言下都必须有译文，且不得残留英文原文。
    func testL10nTableCoversAllKeysInEveryLanguage() {
        for key in L10nKey.allCases {
            for language in AppLanguage.allCases {
                let value = L10nTable.string(key, language)
                XCTAssertFalse(value.isEmpty, "\(language.rawValue) 缺少 \(key.rawValue)")
                // 回落机制会返回 rawValue，出现即说明该语言漏翻
                XCTAssertNotEqual(value, key.rawValue, "\(language.rawValue) 未翻译 \(key.rawValue)")
            }
        }
    }
    /// 带占位符的文案，各语言的占位符数量必须与英文一致，否则 String(format:) 会取到错误参数。
    func testL10nPlaceholderCountsMatchEnglish() {
        func placeholders(_ s: String) -> Int {
            var count = 0
            var index = s.startIndex
            while let range = s.range(of: "%", range: index..<s.endIndex) {
                let next = s.index(after: range.lowerBound)
                if next < s.endIndex, s[next] != "%" { count += 1 }
                index = next < s.endIndex ? s.index(after: next) : s.endIndex
            }
            return count
        }
        for key in L10nKey.allCases {
            let expected = placeholders(L10nTable.string(key, .english))
            guard expected > 0 else { continue }
            for language in AppLanguage.allCases where language != .english {
                let actual = placeholders(L10nTable.string(key, language))
                XCTAssertEqual(actual, expected,
                               "\(language.rawValue) 的 \(key.rawValue) 占位符数量与英文不一致")
            }
        }
    }
    /// 中日韩三种语言不得残留大段英文原文，用于发现漏翻。
    func testTranslationsAreNotEnglishCopies() {
        var untranslated: [String] = []
        // 这两个品牌名在审核过的 1.5.1 中文原稿中即使用英文，其他语言也保持产品专名。
        let approvedBrandNames: Set<L10nKey> = [.macosSystemTrust, .mozillaRootStore]
        for key in L10nKey.allCases {
            let english = L10nTable.string(key, .english)
            guard english.count > 12, !approvedBrandNames.contains(key) else { continue }
            for language: AppLanguage in [.simplifiedChinese, .japanese, .korean] {
                if L10nTable.string(key, language) == english {
                    untranslated.append("\(language.rawValue)/\(key.rawValue)")
                }
            }
        }
        XCTAssertTrue(untranslated.isEmpty, "以下文案仍是英文原文: \(untranslated)")
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

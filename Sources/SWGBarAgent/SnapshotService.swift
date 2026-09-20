//
// SWGBar / macOS menu bar TLS inspection detector
// Snapshot and view query service (SnapshotService.swift)
// Aggregate live data and provide a deterministic demonstration snapshot.
//

import Foundation
import SWGBarContracts
import SWGBarStorage

public final class SnapshotService: @unchecked Sendable {
    private let repository: StorageRepository

    public init(repository: StorageRepository = StorageRepository(db: try! SQLiteDatabase.inMemory())) {
        self.repository = repository
    }

    // MARK: - Overview snapshot (OverviewSnapshot)

    public func getOverviewSnapshot(
        metricKind: String = "probe_domain",
        epochId: String = "",
        windowSeconds: Int = 0,
        collectorState: CollectorState = .running
    ) -> OverviewSnapshot {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let windowStart: Int64 = (windowSeconds > 0) ? (nowMs - Int64(windowSeconds * 1000)) : 0
        let source: EvidenceSource = (metricKind == "actual_request") ? .browserRequest : .nativeProbe

        do {
            let counts = try repository.queryMetricCounts(source: source, epochId: epochId, windowStartMs: windowStart, windowEndMs: nowMs)
            let rules = try repository.listRules()
            let userRulesCount = rules.filter { $0.origin == "user" && $0.kind == "inspection_ca" }.count

            // Show five clusters using the certificate list's status order, then descending domain count.
            var topClusters: [CAClusterSummary] = []
            let allCAs = listCAClusters(showAll: true)
            for ca in allCAs.prefix(5) {
                topClusters.append(CAClusterSummary(
                    clusterId: ca.clusterId,
                    caName: ca.caName,
                    spkiSha256: ca.spkiSha256,
                    spkiShort: String(ca.spkiSha256.prefix(11)),
                    identityKind: ca.identityKind,
                    affectedDomainsCount: ca.affectedDomainsCount,
                    lastObservedMs: nowMs - 15000
                ))
            }

            return OverviewSnapshot(
                snapshotVersion: 1,
                generatedAtMs: nowMs,
                metricKind: metricKind,
                epochId: epochId,
                windowStartMs: windowStart,
                windowEndMs: nowMs,
                counts: counts,
                collectorState: collectorState,
                partial: false,
                partialReasons: [],
                ruleRevision: 1,
                baselineVersion: "2026.09.17",
                userAssertedConfirmed: Int64(userRulesCount),
                topClusters: topClusters,
                lastEvidenceAt: nowMs - 10000,
                lastSuccessAt: nowMs - 10000,
                queueSummary: QueueSummary(pendingProbeCount: 0, unknownCount: counts.unknown, activeProbes: 0)
            )
        } catch {
            return generateDemoSnapshot(metricKind: metricKind, epochId: epochId, windowSeconds: windowSeconds, collectorState: collectorState)
        }
    }

    // Generate the common demonstration fixture.
    public func generateDemoSnapshot(metricKind: String, epochId: String, windowSeconds: Int, collectorState: CollectorState = .running) -> OverviewSnapshot {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let windowStart = nowMs - Int64(windowSeconds * 1000)

        // Fixture: C=100, S=50, P=600, E=50, U=200; N=1000, K=800.
        let counts = MetricCounts(
            confirmed: 100,
            suspected: 50,
            publicPath: 600,
            expectedPrivate: 50,
            unknown: 200,
            excluded: 45
        )

        let topClusters = [
            CAClusterSummary(
                clusterId: "cluster-01",
                caName: "Corp Inspection CA",
                spkiSha256: "D1:F5:E3:A9:C8:B4:7C:2E:33:11:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
                spkiShort: "D1:F5:E3:A9",
                identityKind: "inspection",
                affectedDomainsCount: 68,
                lastObservedMs: nowMs - 60000
            ),
            CAClusterSummary(
                clusterId: "cluster-02",
                caName: "Private Anchor A",
                spkiSha256: "9D:6B:12:F4:7A:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:12:34:56:78:9A:BC:DE:F0:12:34:56:78",
                spkiShort: "9D:6B:12:F4",
                identityKind: "suspected",
                affectedDomainsCount: 42,
                lastObservedMs: nowMs - 120000
            ),
            CAClusterSummary(
                clusterId: "cluster-03",
                caName: "Public Intermediate 01",
                spkiSha256: "A1:9C:3E:77:88:99:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
                spkiShort: "A1:9C:3E:77",
                identityKind: "public",
                affectedDomainsCount: 600,
                lastObservedMs: nowMs - 180000
            )
        ]

        return OverviewSnapshot(
            snapshotVersion: 1,
            generatedAtMs: nowMs,
            metricKind: metricKind,
            epochId: epochId,
            windowStartMs: windowStart,
            windowEndMs: nowMs,
            counts: counts,
            collectorState: collectorState,
            partial: false,
            partialReasons: [],
            ruleRevision: 1,
            baselineVersion: "2026.09.17",
            userAssertedConfirmed: 1, // Includes a user-provided label.
            topClusters: topClusters,
            lastEvidenceAt: nowMs - 20000,
            lastSuccessAt: nowMs - 20000,
            queueSummary: QueueSummary(pendingProbeCount: 12, unknownCount: 200, activeProbes: 0)
        )
    }

    // MARK: - Domain list (domains.list)

    public func listDomains(
        search: String = "",
        statusFilter: String = "ALL",
        certFilter: String = "ALL",
        sourceFilter: String = "ALL",
        appFilter: String = "ALL",
        sort: String = "REQUEST_COUNT"
    ) -> [DomainRow] {
        let sortByCount = (sort == "REQUEST_COUNT")
        guard let liveRows = try? repository.listTargetsWithLatestVerdict(limit: 5000, sortByRequestCount: sortByCount) else {
            return []
        }
        // Resolve the certificate tab's cluster by its unique ID and reuse its display name and status.
        let certificatesByClusterId = Dictionary(uniqueKeysWithValues:
            listCAClusters(showAll: true).map { ($0.clusterId, $0) }
        )
        var filtered = liveRows.map { row in
            guard let clusterId = row.certificateClusterId,
                  let certificate = certificatesByClusterId[clusterId] else {
                return row
            }
            var enriched = DomainRow(
                targetId: row.targetId,
                hostname: row.hostname,
                port: row.port,
                verdict: row.verdict,
                discoveredApp: row.discoveredApp,
                evidenceSource: row.evidenceSource,
                lastObservedMs: row.lastObservedMs,
                isIpOnly: row.isIpOnly,
                requestCount: row.requestCount,
                certificateSummary: certificate.caName
            )
            enriched.certificateIdentityKind = certificate.identityKind
            enriched.certificateClusterId = clusterId
            return enriched
        }
        if !search.isEmpty {
            filtered = filtered.filter {
                $0.hostname.localizedCaseInsensitiveContains(search) ||
                "\($0.hostname):\($0.port)".localizedCaseInsensitiveContains(search)
            }
        }
        if statusFilter != "ALL" {
            filtered = filtered.filter { $0.verdict.rawValue.localizedCaseInsensitiveContains(statusFilter) }
        }
        if certFilter != "ALL" && !certFilter.isEmpty {
            filtered = filtered.filter { row in
                row.formattedCertSummary == certFilter ||
                (row.certificateSummary ?? "").localizedCaseInsensitiveContains(certFilter)
            }
        }
        // Sort NAME and STATUS modes in memory.
        switch sort {
        case "NAME":
            filtered.sort { $0.hostname < $1.hostname }
        case "STATUS":
            let order: [Verdict: Int] = [.confirmedInspection: 0, .suspectedInspection: 1, .unknown: 2, .expectedPrivate: 3, .publicPath: 4, .excluded: 5]
            filtered.sort { (order[$0.verdict] ?? 9) < (order[$1.verdict] ?? 9) }
        default:
            break // RECENT and REQUEST_COUNT are already sorted by SQL.
        }
        return filtered
    }

    /// Display the standard DIRECT or HTTP_CONNECT identifier, or a placeholder when unavailable.
    static func routeDisplayName(_ routeType: String?) -> String {
        guard let raw = routeType?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return "—"
        }
        return raw.uppercased()
    }

    // MARK: - Domain details (domains.get)

    public func getDomainDetail(targetId: String) -> DomainDetail {
        if let info = try? repository.getTargetDetailInfo(targetId: targetId) {
            let observedDate = Date(timeIntervalSince1970: Double(info.lastObservedMs) / 1000.0)

            // Use the latest observation timestamp and include the date to distinguish different days.
            let fullDf = DateFormatter()
            fullDf.locale = Locale(identifier: "en_US_POSIX")
            fullDf.dateFormat = "yyyy-MM-dd HH:mm:ss"
            let lastObservedStr = info.lastObservedMs > 0 ? fullDf.string(from: observedDate) : "—"

            let desc: String
            switch info.verdict {
            case .confirmedInspection:
                desc = "The certificate and local trust settings match a registered inspection identity. TLS inspection is confirmed for this probe."
            case .suspectedInspection:
                desc = "An additional private trust path appears across multiple public targets. The inspection operator has not been confirmed."
            case .publicPath:
                desc = "This probe passed public PKI validation. No private inspection path was identified."
            case .expectedPrivate:
                desc = "This target matches an expected private trust rule."
            case .unknown:
                desc = info.reason
            case .excluded:
                desc = "Excluded from monitoring by a user or system rule."
            }

            let extraPath: String
            if let ca = info.caName, !ca.isEmpty {
                extraPath = "Established: \(ca)"
            } else if info.verdict == .publicPath {
                extraPath = "No additional trust (standard system roots)"
            } else {
                extraPath = "A complete certificate chain has not been captured"
            }

            return DomainDetail(
                targetId: targetId,
                hostname: info.hostname,
                port: info.port,
                verdict: info.verdict,
                verdictDescription: desc,
                evidenceSource: info.source,
                lastObservedFormatted: lastObservedStr,
                endpointAddress: info.remoteIp != nil ? "\(info.remoteIp!) : \(info.port)" : "Local outbound connection",
                routingSummary: Self.routeDisplayName(info.routeType),
                egressInterface: (info.egressInterface?.isEmpty == false) ? info.egressInterface! : "—",
                handshakeStatus: info.verdict == .unknown ? "Not probed or pending" : "Complete",
                baselineVerdict: info.verdict == .publicPath ? "Public path established" : "Public path not established",
                extraTrustPath: extraPath,
                caClusterName: info.caName,
                caClusterId: info.caClusterId,
                requestCount: info.requestCount
            )
        }

        return DomainDetail(
            targetId: targetId,
            hostname: "unknown.domain",
            port: 443,
            verdict: .unknown,
            verdictDescription: "No history was found for this target",
            evidenceSource: .nativeProbe,
            lastObservedFormatted: "—",
            endpointAddress: "--",
            routingSummary: "—",
            egressInterface: "—",
            handshakeStatus: "Incomplete",
            baselineVerdict: "Unknown",
            extraTrustPath: "None",
            caClusterName: nil,
            caClusterId: nil,
            requestCount: 0
        )
    }

    // MARK: - CA cluster lists and details (clusters.list, clusters.get)

    public func listCAClusters(showAll: Bool = true, forceRefresh: Bool = false) -> [CADetail] {
        var allCAs: [CADetail] = []
        var seen = Set<String>()

        // 1. Load CA clusters observed in real network evidence from the database.
        if let dbClusters = try? repository.listCAClusters(), !dbClusters.isEmpty {
            for ca in dbClusters {
                if !seen.contains(ca.caName) {
                    seen.insert(ca.caName)
                    allCAs.append(ca)
                }
            }
        }

        // 2. Add local keychain roots, using the cache to avoid repeated IPC.
        let realCAs = NativeTrustEvaluator.shared.extractAllInstalledExtraTrustCAs(forceRefresh: forceRefresh)
        for ca in realCAs {
            if !seen.contains(ca.caName) {
                seen.insert(ca.caName)
                allCAs.append(ca)
            }
        }

        // Order by confirmed inspection, suspected inspection, then public trust.
        // Within each status, sort by affectedDomainsCount in descending order.
        func statusRank(_ kind: String) -> Int {
            switch kind {
            case "inspection": return 0
            case "suspected": return 1
            case "public": return 2
            default: return 3
            }
        }

        allCAs.sort { (a, b) -> Bool in
            let rankA = statusRank(a.identityKind)
            let rankB = statusRank(b.identityKind)
            if rankA != rankB {
                return rankA < rankB
            }
            if a.affectedDomainsCount != b.affectedDomainsCount {
                return a.affectedDomainsCount > b.affectedDomainsCount
            }
            return a.caName < b.caName
        }

        return showAll ? allCAs : allCAs.filter { $0.identityKind == "inspection" || $0.identityKind == "suspected" }
    }

    public func listHostnamesForCA(clusterId: String = "", spki: String = "", caName: String = "") -> [String] {
        return (try? repository.listHostnamesForCA(clusterId: clusterId, spki: spki, caName: caName)) ?? []
    }

    // MARK: - Timeline events (events.list)

    public func listTimelineEvents(onlyChanges: Bool = false) -> [TimelineEvent] {
        if let liveEvents = try? repository.listEvents(limit: 50) {
            return onlyChanges ? liveEvents.filter { $0.isChange } : liveEvents
        }
        return []
    }
}

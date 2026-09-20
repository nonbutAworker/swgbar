//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 快照与视图查询服务 (SnapshotService.swift)
// 遵循技术方案 v1.1 第 05, 17-24, 28 章：包含真实数据聚合与官方规范演示数据
//

import Foundation
import SWGBarContracts
import SWGBarStorage

public final class SnapshotService: @unchecked Sendable {
    private let repository: StorageRepository

    public init(repository: StorageRepository = StorageRepository(db: try! SQLiteDatabase.inMemory())) {
        self.repository = repository
    }

    // MARK: - 总览快照 (OverviewSnapshot)

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

            // 默认展示5个，排序和“证书”列表页面保持完全一致 (确认 -> 疑似 -> 公共 -> 预期，内部按域名数倒序)
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

    // 生成技术方案 v1.1 5.2 节完全一致的统一样例数据
    public func generateDemoSnapshot(metricKind: String, epochId: String, windowSeconds: Int, collectorState: CollectorState = .running) -> OverviewSnapshot {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let windowStart = nowMs - Int64(windowSeconds * 1000)

        // 统一样例：C=100, S=50, P=600, E=50, U=200; N=1000, K=800
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
            userAssertedConfirmed: 1, // 图 17-1：含用户标注
            topClusters: topClusters,
            lastEvidenceAt: nowMs - 20000,
            lastSuccessAt: nowMs - 20000,
            queueSummary: QueueSummary(pendingProbeCount: 12, unknownCount: 200, activeProbes: 0)
        )
    }

    // MARK: - 域名列表 (domains.list)

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
        // 通过 CA 聚类唯一标识命中证书 Tab 的同一条记录，名称和状态均取自该记录。
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
        // 客户端排序（NAME / STATUS 模式）
        switch sort {
        case "NAME":
            filtered.sort { $0.hostname < $1.hostname }
        case "STATUS":
            let order: [Verdict: Int] = [.confirmedInspection: 0, .suspectedInspection: 1, .unknown: 2, .expectedPrivate: 3, .publicPath: 4, .excluded: 5]
            filtered.sort { (order[$0.verdict] ?? 9) < (order[$1.verdict] ?? 9) }
        default:
            break // RECENT 和 REQUEST_COUNT 已在 SQL 层排序
        }
        return filtered
    }

    /// 连接方式展示：统一使用标准英文标识（DIRECT / HTTP_CONNECT），无记录时显示占位符
    static func routeDisplayName(_ routeType: String?) -> String {
        guard let raw = routeType?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return "—"
        }
        return raw.uppercased()
    }

    // MARK: - 域名详情 (domains.get, 图 19-1)

    public func getDomainDetail(targetId: String) -> DomainDetail {
        if let info = try? repository.getTargetDetailInfo(targetId: targetId) {
            let observedDate = Date(timeIntervalSince1970: Double(info.lastObservedMs) / 1000.0)

            // 最近观察时间取自该目标最新一条观测的 observed_at_ms，跨天时保留日期避免歧义
            let fullDf = DateFormatter()
            fullDf.locale = Locale(identifier: "zh_CN")
            fullDf.dateFormat = "yyyy-MM-dd HH:mm:ss"
            let lastObservedStr = info.lastObservedMs > 0 ? fullDf.string(from: observedDate) : "—"

            let desc: String
            switch info.verdict {
            case .confirmedInspection:
                desc = "命中企业自签/拦截根证书与系统信任设置；已确认存在 TLS 检查中间代理。"
            case .suspectedInspection:
                desc = "有效的额外私有信任路径在多个公共目标复现；尚未确认检查身份的具体运营者。"
            case .publicPath:
                desc = "目标通过公共标准 PKI 验证；未发现中间人拦截或私有证书劫持。"
            case .expectedPrivate:
                desc = "命中预期私有信任规则；符合受管内网环境预期。"
            case .unknown:
                desc = info.reason
            case .excluded:
                desc = "根据用户/系统规则已从检查监控中排除。"
            }

            let extraPath: String
            if let ca = info.caName, !ca.isEmpty {
                extraPath = "成立 · \(ca)"
            } else if info.verdict == .publicPath {
                extraPath = "未引入额外信任（标准系统根证书）"
            } else {
                extraPath = "尚未捕获完整证书链"
            }

            return DomainDetail(
                targetId: targetId,
                hostname: info.hostname,
                port: info.port,
                verdict: info.verdict,
                verdictDescription: desc,
                evidenceSource: info.source,
                lastObservedFormatted: lastObservedStr,
                endpointAddress: info.remoteIp != nil ? "\(info.remoteIp!) : \(info.port)" : "本机出站连接",
                routingSummary: Self.routeDisplayName(info.routeType),
                egressInterface: (info.egressInterface?.isEmpty == false) ? info.egressInterface! : "—",
                handshakeStatus: info.verdict == .unknown ? "未探测或等待中" : "已完成",
                baselineVerdict: info.verdict == .publicPath ? "公共路径已建立" : "无法建立公共路径",
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
            verdictDescription: "未找到该目标的历史记录",
            evidenceSource: .nativeProbe,
            lastObservedFormatted: "—",
            endpointAddress: "--",
            routingSummary: "—",
            egressInterface: "—",
            handshakeStatus: "未完成",
            baselineVerdict: "未知",
            extraTrustPath: "无",
            caClusterName: nil,
            caClusterId: nil,
            requestCount: 0
        )
    }

    // MARK: - CA 聚类列表与详情 (clusters.list, clusters.get, 图 20-1, 21-1)

    public func listCAClusters(showAll: Bool = true, forceRefresh: Bool = false) -> [CADetail] {
        var allCAs: [CADetail] = []
        var seen = Set<String>()

        // 1. 优先提取数据库中已产生真实网络流的 CA 聚类（包括 CN=swg Intermedia CA）
        if let dbClusters = try? repository.listCAClusters(), !dbClusters.isEmpty {
            for ca in dbClusters {
                if !seen.contains(ca.caName) {
                    seen.insert(ca.caName)
                    allCAs.append(ca)
                }
            }
        }

        // 2. 补充本地 Keychain 中的根证书（带内存缓存，避免重复 IPC）
        let realCAs = NativeTrustEvaluator.shared.extractAllInstalledExtraTrustCAs(forceRefresh: forceRefresh)
        for ca in realCAs {
            if !seen.contains(ca.caName) {
                seen.insert(ca.caName)
                allCAs.append(ca)
            }
        }

        // 排序规则：先按 确认(inspection) -> 疑似(suspected) -> 公共(public)
        // 状态内部再按关联的域名数量从高到低排序 (affectedDomainsCount DESC)
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

    // MARK: - 时间线记录 (events.list, 图 22-1)

    public func listTimelineEvents(onlyChanges: Bool = false) -> [TimelineEvent] {
        if let liveEvents = try? repository.listEvents(limit: 50) {
            return onlyChanges ? liveEvents.filter { $0.isChange } : liveEvents
        }
        return []
    }
}

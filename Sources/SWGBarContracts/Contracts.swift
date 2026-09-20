//
// SWGBar / macOS menu bar TLS inspection detector
// Core data transfer objects and contracts (Contracts.swift)
// Shared types for the application, storage, and RPC layers.
//

import Foundation

// MARK: - Base enumerations

public enum EvidenceSource: String, Codable, Sendable, CaseIterable {
    case systemFlow = "system_flow"
    case nativeProbe = "native_probe"
    case browserRequest = "browser_request"

    public var displayName: String {
        switch self {
        case .systemFlow: return "System flow metadata"
        case .nativeProbe: return "Independent application probe"
        case .browserRequest: return "Observed browser request"
        }
    }
}

public enum Verdict: String, Codable, Sendable, CaseIterable {
    case confirmedInspection = "confirmed_inspection"
    case suspectedInspection = "suspected_inspection"
    case publicPath = "public_path"
    case expectedPrivate = "expected_private"
    case unknown = "unknown"
    case excluded = "excluded"

    public var shortLabel: String {
        switch self {
        case .confirmedInspection: return "Confirmed"
        case .suspectedInspection: return "Suspected"
        case .publicPath: return "Public path"
        case .expectedPrivate: return "Expected private"
        case .unknown: return "Unknown"
        case .excluded: return "Excluded"
        }
    }
}

public enum CollectorState: String, Codable, Sendable {
    case unconfigured = "unconfigured"
    case authorizing = "authorizing"
    case running = "running"
    case paused = "paused"
    case degraded = "degraded"
}

// MARK: - Metrics and numeric values

public struct MetricValue: Codable, Sendable, Equatable {
    public let numerator: Int64
    public let denominator: Int64
    public let ratio: Double? // Range: 0...1; encode null when the denominator is zero.

    public init(numerator: Int64, denominator: Int64) {
        self.numerator = numerator
        self.denominator = denominator
        if denominator > 0 {
            self.ratio = Double(numerator) / Double(denominator)
        } else {
            self.ratio = nil
        }
    }

    public var percentageString: String {
        guard let r = ratio else { return "—" }
        return String(format: "%.1f%%", r * 100.0)
    }
}

public struct MetricCounts: Codable, Sendable, Equatable {
    public let confirmed: Int64
    public let suspected: Int64
    public let publicPath: Int64
    public let expectedPrivate: Int64
    public let unknown: Int64
    public let excluded: Int64

    public var nApplicableTotal: Int64 {
        confirmed + suspected + publicPath + expectedPrivate + unknown
    }

    public var kClassifiedTotal: Int64 {
        confirmed + suspected + publicPath + expectedPrivate
    }

    public init(confirmed: Int64, suspected: Int64, publicPath: Int64, expectedPrivate: Int64, unknown: Int64, excluded: Int64) {
        self.confirmed = confirmed
        self.suspected = suspected
        self.publicPath = publicPath
        self.expectedPrivate = expectedPrivate
        self.unknown = unknown
        self.excluded = excluded
    }
}

public struct MetricScope: Codable, Sendable, Equatable {
    public let addressFamily: String
    public let transport: String
    public let application: String
    public let status: String
    public let endpointSemantics: String

    public init(
        addressFamily: String = "ipv4",
        transport: String = "tcp",
        application: String = "https",
        status: String = "eligible",
        endpointSemantics: String = "first_hop_ipv4_target_may_be_unknown"
    ) {
        self.addressFamily = addressFamily
        self.transport = transport
        self.application = application
        self.status = status
        self.endpointSemantics = endpointSemantics
    }

    enum CodingKeys: String, CodingKey {
        case addressFamily = "address_family"
        case transport
        case application
        case status
        case endpointSemantics = "endpoint_semantics"
    }
}

// MARK: - Snapshot data transfer objects

public struct CAClusterSummary: Codable, Sendable, Identifiable, Equatable {
    public var id: String { clusterId }
    public let clusterId: String
    public let caName: String
    public let spkiSha256: String
    public let spkiShort: String
    public let identityKind: String // inspection / suspected / public / expected_private
    public let affectedDomainsCount: Int64
    public let lastObservedMs: Int64

    public init(
        clusterId: String,
        caName: String,
        spkiSha256: String,
        spkiShort: String,
        identityKind: String,
        affectedDomainsCount: Int64,
        lastObservedMs: Int64
    ) {
        self.clusterId = clusterId
        self.caName = caName
        self.spkiSha256 = spkiSha256
        self.spkiShort = spkiShort
        self.identityKind = identityKind
        self.affectedDomainsCount = affectedDomainsCount
        self.lastObservedMs = lastObservedMs
    }

    enum CodingKeys: String, CodingKey {
        case clusterId = "cluster_id"
        case caName = "ca_name"
        case spkiSha256 = "spki_sha256"
        case spkiShort = "spki_short"
        case identityKind = "identity_kind"
        case affectedDomainsCount = "affected_domains_count"
        case lastObservedMs = "last_observed_ms"
    }
}

public struct QueueSummary: Codable, Sendable, Equatable {
    public let pendingProbeCount: Int64
    public let unknownCount: Int64
    public let activeProbes: Int64

    public init(pendingProbeCount: Int64, unknownCount: Int64, activeProbes: Int64 = 0) {
        self.pendingProbeCount = pendingProbeCount
        self.unknownCount = unknownCount
        self.activeProbes = activeProbes
    }

    enum CodingKeys: String, CodingKey {
        case pendingProbeCount = "pending_probe_count"
        case unknownCount = "unknown_count"
        case activeProbes = "active_probes"
    }
}

public struct OverviewSnapshot: Codable, Sendable, Equatable {
    public let snapshotVersion: Int64
    public let generatedAtMs: Int64
    public let metricKind: String // "probe_domain" / "actual_request"
    public let scope: MetricScope
    public let epochId: String
    public let windowStartMs: Int64
    public let windowEndMs: Int64
    public let counts: MetricCounts
    public let confirmedRate: MetricValue
    public let suspectedRate: MetricValue
    public let evidenceCoverage: MetricValue
    public let classifiedConfirmedRate: MetricValue
    public var collectorState: CollectorState
    public let partial: Bool
    public let partialReasons: [String]
    public let ruleRevision: Int64
    public let baselineVersion: String
    public let userAssertedConfirmed: Int64
    public let topClusters: [CAClusterSummary]

    public let lastEvidenceAt: Int64?
    public let lastSuccessAt: Int64?
    public let queueSummary: QueueSummary?
    public let capabilityWarning: String?

    public init(
        snapshotVersion: Int64,
        generatedAtMs: Int64,
        metricKind: String,
        scope: MetricScope = MetricScope(),
        epochId: String,
        windowStartMs: Int64,
        windowEndMs: Int64,
        counts: MetricCounts,
        collectorState: CollectorState,
        partial: Bool = false,
        partialReasons: [String] = [],
        ruleRevision: Int64 = 1,
        baselineVersion: String = "2026.09.17",
        userAssertedConfirmed: Int64 = 0,
        topClusters: [CAClusterSummary] = [],
        lastEvidenceAt: Int64? = nil,
        lastSuccessAt: Int64? = nil,
        queueSummary: QueueSummary? = nil,
        capabilityWarning: String? = nil
    ) {
        self.snapshotVersion = snapshotVersion
        self.generatedAtMs = generatedAtMs
        self.metricKind = metricKind
        self.scope = scope
        self.epochId = epochId
        self.windowStartMs = windowStartMs
        self.windowEndMs = windowEndMs
        self.counts = counts

        let n = counts.nApplicableTotal
        let k = counts.kClassifiedTotal

        self.confirmedRate = MetricValue(numerator: counts.confirmed, denominator: n)
        self.suspectedRate = MetricValue(numerator: counts.suspected, denominator: n)
        self.evidenceCoverage = MetricValue(numerator: k, denominator: n)
        self.classifiedConfirmedRate = MetricValue(numerator: counts.confirmed, denominator: k)

        self.collectorState = collectorState
        self.partial = partial
        self.partialReasons = partialReasons
        self.ruleRevision = ruleRevision
        self.baselineVersion = baselineVersion
        self.userAssertedConfirmed = userAssertedConfirmed
        self.topClusters = topClusters
        self.lastEvidenceAt = lastEvidenceAt
        self.lastSuccessAt = lastSuccessAt
        self.queueSummary = queueSummary
        self.capabilityWarning = capabilityWarning
    }

    enum CodingKeys: String, CodingKey {
        case snapshotVersion = "snapshot_version"
        case generatedAtMs = "generated_at_ms"
        case metricKind = "metric_kind"
        case scope
        case epochId = "epoch_id"
        case windowStartMs = "window_start_ms"
        case windowEndMs = "window_end_ms"
        case counts
        case confirmedRate = "confirmed_rate"
        case suspectedRate = "suspected_rate"
        case evidenceCoverage = "evidence_coverage"
        case classifiedConfirmedRate = "classified_confirmed_rate"
        case collectorState = "collector_state"
        case partial
        case partialReasons = "partial_reasons"
        case ruleRevision = "rule_revision"
        case baselineVersion = "baseline_version"
        case userAssertedConfirmed = "user_asserted_confirmed"
        case topClusters = "top_clusters"
        case lastEvidenceAt = "last_evidence_at"
        case lastSuccessAt = "last_success_at"
        case queueSummary = "queue_summary"
        case capabilityWarning = "capability_warning"
    }
}

extension OverviewSnapshot {
    /// Confirmed inspection count Y: only domains with a confirmed inspection certificate.
    public var mitmHijackedCount: Int64 {
        counts.confirmed
    }

    /// Eligible HTTPS request or domain count X
    public var mitmTotalCount: Int64 {
        counts.nApplicableTotal
    }

    /// Inspection ratio Y / X (0.0 ... 1.0)
    public var mitmRatio: Double? {
        mitmTotalCount > 0 ? Double(mitmHijackedCount) / Double(mitmTotalCount) : nil
    }

    /// Detailed percentage text, for example "80.0%"
    public var mitmPercentageString: String {
        guard let r = mitmRatio else { return "—" }
        return String(format: "%.1f%%", r * 100.0)
    }

    /// Compact menu bar text, for example "MITM 80%"
    public var mitmMenuBarString: String {
        guard let r = mitmRatio else { return "MITM —" }
        return "MITM \(Int(round(r * 100.0)))%"
    }
}

// MARK: - Domain and target data transfer objects

public struct DomainRow: Codable, Sendable, Identifiable, Equatable {
    public var id: String { targetId }
    public let targetId: String
    public let hostname: String
    public let port: Int
    public let verdict: Verdict
    public let discoveredApp: String?
    public let evidenceSource: EvidenceSource
    public let lastObservedMs: Int64
    public let isIpOnly: Bool
    public let requestCount: Int64
    public let certificateSummary: String?
    /// The associated certificate's status is independent of the domain's probe verdict.
    public var certificateIdentityKind: String?
    /// Unique CA cluster ID used to resolve the matching certificate row.
    public var certificateClusterId: String?

    public init(
        targetId: String,
        hostname: String,
        port: Int,
        verdict: Verdict,
        discoveredApp: String?,
        evidenceSource: EvidenceSource,
        lastObservedMs: Int64,
        isIpOnly: Bool = false,
        requestCount: Int64 = 0,
        certificateSummary: String? = nil
    ) {
        self.targetId = targetId
        self.hostname = hostname
        self.port = port
        self.verdict = verdict
        self.discoveredApp = discoveredApp
        self.evidenceSource = evidenceSource
        self.lastObservedMs = lastObservedMs
        self.isIpOnly = isIpOnly
        self.requestCount = requestCount
        self.certificateSummary = certificateSummary
    }

    enum CodingKeys: String, CodingKey {
        case targetId = "target_id"
        case hostname
        case port
        case verdict
        case discoveredApp = "discovered_app"
        case evidenceSource = "evidence_source"
        case lastObservedMs = "last_observed_ms"
        case isIpOnly = "is_ip_only"
        case requestCount = "request_count"
        case certificateSummary = "certificate_summary"
        case certificateIdentityKind = "certificate_identity_kind"
        case certificateClusterId = "certificate_cluster_id"
    }
}

extension DomainRow {
    public static func formatCertSummary(_ raw: String?) -> String {
        guard let raw = raw, !raw.isEmpty else {
            return "Awaiting probe"
        }
        let parts = raw.components(separatedBy: ",")
        var cnPart: String? = nil
        var oPart: String? = nil
        for p in parts {
            let trimmed = p.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("CN=") {
                cnPart = String(trimmed.dropFirst(3))
            } else if trimmed.hasPrefix("O=") {
                oPart = String(trimmed.dropFirst(2))
            }
        }
        if let cn = cnPart {
            return cn
        } else if let o = oPart {
            return o
        }
        return raw
    }

    public var formattedCertSummary: String {
        return DomainRow.formatCertSummary(certificateSummary)
    }
}

public struct DomainDetail: Codable, Sendable, Equatable {
    public let targetId: String
    public let hostname: String
    public let port: Int
    public let verdict: Verdict
    public let verdictDescription: String
    public let evidenceSource: EvidenceSource
    /// Full observation timestamp, including the date, for activity details.
    public let lastObservedFormatted: String
    public let endpointAddress: String
    public let routingSummary: String
    public let egressInterface: String
    public let handshakeStatus: String
    public let baselineVerdict: String
    public let extraTrustPath: String
    public let caClusterName: String?
    public let caClusterId: String?
    public let requestCount: Int64

    public init(
        targetId: String,
        hostname: String,
        port: Int,
        verdict: Verdict,
        verdictDescription: String,
        evidenceSource: EvidenceSource,
        lastObservedFormatted: String = "",
        endpointAddress: String,
        routingSummary: String,
        egressInterface: String = "",
        handshakeStatus: String,
        baselineVerdict: String,
        extraTrustPath: String,
        caClusterName: String?,
        caClusterId: String?,
        requestCount: Int64 = 0
    ) {
        self.targetId = targetId
        self.hostname = hostname
        self.port = port
        self.verdict = verdict
        self.verdictDescription = verdictDescription
        self.evidenceSource = evidenceSource
        self.lastObservedFormatted = lastObservedFormatted
        self.endpointAddress = endpointAddress
        self.routingSummary = routingSummary
        self.egressInterface = egressInterface
        self.handshakeStatus = handshakeStatus
        self.baselineVerdict = baselineVerdict
        self.extraTrustPath = extraTrustPath
        self.caClusterName = caClusterName
        self.caClusterId = caClusterId
        self.requestCount = requestCount
    }

    enum CodingKeys: String, CodingKey {
        case targetId = "target_id"
        case hostname
        case port
        case verdict
        case verdictDescription = "verdict_description"
        case evidenceSource = "evidence_source"
        case lastObservedFormatted = "last_observed_formatted"
        case endpointAddress = "endpoint_address"
        case routingSummary = "routing_summary"
        case egressInterface = "egress_interface"
        case handshakeStatus = "handshake_status"
        case baselineVerdict = "baseline_verdict"
        case extraTrustPath = "extra_trust_path"
        case caClusterName = "ca_cluster_name"
        case caClusterId = "ca_cluster_id"
        case requestCount = "request_count"
    }
}

// MARK: - Certificate and CA cluster data transfer objects

public struct CADetail: Codable, Sendable, Equatable {
    public let clusterId: String
    public let caName: String
    public let identityKind: String
    public let hasUserAssertion: Bool
    public let subject: String
    public let issuer: String
    public let validityFormatted: String
    public let certSha256: String
    public let spkiSha256: String
    public let extraTrustVerifiedPath: [String]
    public let baselineStatus: String
    public let activeRule: Rule?
    public let affectedDomainsCount: Int64
    public let notBeforeMs: Int64?
    public let notAfterMs: Int64?

    public init(
        clusterId: String,
        caName: String,
        identityKind: String,
        hasUserAssertion: Bool,
        subject: String,
        issuer: String,
        validityFormatted: String,
        certSha256: String,
        spkiSha256: String,
        extraTrustVerifiedPath: [String],
        baselineStatus: String,
        activeRule: Rule?,
        affectedDomainsCount: Int64,
        notBeforeMs: Int64? = nil,
        notAfterMs: Int64? = nil
    ) {
        self.clusterId = clusterId
        self.caName = caName
        self.identityKind = identityKind
        self.hasUserAssertion = hasUserAssertion
        self.subject = subject
        self.issuer = issuer
        self.validityFormatted = validityFormatted
        self.certSha256 = certSha256
        self.spkiSha256 = spkiSha256
        self.extraTrustVerifiedPath = extraTrustVerifiedPath
        self.baselineStatus = baselineStatus
        self.activeRule = activeRule
        self.affectedDomainsCount = affectedDomainsCount
        self.notBeforeMs = notBeforeMs
        self.notAfterMs = notAfterMs
    }

    enum CodingKeys: String, CodingKey {
        case clusterId = "cluster_id"
        case caName = "ca_name"
        case identityKind = "identity_kind"
        case hasUserAssertion = "has_user_assertion"
        case subject
        case issuer
        case validityFormatted = "validity_formatted"
        case certSha256 = "cert_sha256"
        case spkiSha256 = "spki_sha256"
        case extraTrustVerifiedPath = "extra_trust_verified_path"
        case baselineStatus = "baseline_status"
        case activeRule = "active_rule"
        case affectedDomainsCount = "affected_domains_count"
        case notBeforeMs = "not_before_ms"
        case notAfterMs = "not_after_ms"
    }

    public static let certificateDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "EEEE, MMMM d, yyyy HH:mm:ss"
        return f
    }()

    public var notBeforeFormatted: String {
        if let ms = notBeforeMs, ms > 0 {
            let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000.0)
            return Self.certificateDateFormatter.string(from: date)
        }
        if !validityFormatted.isEmpty && validityFormatted != "No expiration" {
            if validityFormatted.contains(" to ") {
                let parts = validityFormatted.components(separatedBy: " to ")
                if !parts.isEmpty {
                    return parts[0].trimmingCharacters(in: .whitespaces)
                }
            }
            return validityFormatted
        }
        return "<Not present in certificate>"
    }

    public var notAfterFormatted: String {
        if let ms = notAfterMs, ms > 0 {
            let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000.0)
            return Self.certificateDateFormatter.string(from: date)
        }
        if !validityFormatted.isEmpty && validityFormatted != "No expiration" {
            if validityFormatted.contains(" to ") {
                let parts = validityFormatted.components(separatedBy: " to ")
                if parts.count > 1 {
                    return parts[1].trimmingCharacters(in: .whitespaces)
                }
            }
            return validityFormatted
        }
        return "<Not present in certificate>"
    }

    public static func parseDNElements(_ dn: String) -> (cn: String?, o: String?, ou: String?) {
        guard !dn.isEmpty else { return (nil, nil, nil) }
        var cn: String? = nil
        var o: String? = nil
        var ou: String? = nil

        let placeholder = "__ESCAPED_COMMA__"
        let safeStr = dn.replacingOccurrences(of: "\\,", with: placeholder)
        let parts = safeStr.components(separatedBy: ",")

        for part in parts {
            let item = part.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: placeholder, with: ",")
            if item.hasPrefix("CN=") {
                cn = String(item.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            } else if item.hasPrefix("O=") {
                o = String(item.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            } else if item.hasPrefix("OU=") {
                ou = String(item.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            }
        }
        return (cn, o, ou)
    }

    public var subjectElements: (cn: String, o: String, ou: String) {
        let p = Self.parseDNElements(subject)
        let fallbackCN: String = {
            if !caName.isEmpty {
                if caName.contains("CN=") {
                    return Self.parseDNElements(caName).cn ?? caName
                }
                return caName
            }
            return "<Not present in certificate>"
        }()
        return (
            cn: p.cn ?? fallbackCN,
            o: p.o ?? "<Not present in certificate>",
            ou: p.ou ?? "<Not present in certificate>"
        )
    }

    public var issuerElements: (cn: String, o: String, ou: String) {
        let p = Self.parseDNElements(issuer)
        let fallbackCN: String = {
            if issuer.isEmpty { return "<Not present in certificate>" }
            if issuer.contains("CN=") {
                return Self.parseDNElements(issuer).cn ?? "<Not present in certificate>"
            }
            return issuer
        }()
        return (
            cn: p.cn ?? fallbackCN,
            o: p.o ?? "<Not present in certificate>",
            ou: p.ou ?? "<Not present in certificate>"
        )
    }
}

// MARK: - Rule data transfer objects

public struct Rule: Codable, Sendable, Identifiable, Equatable {
    public var id: String { ruleId }
    public let ruleId: String
    public let name: String
    public let kind: String // inspection_ca / expected_private / probe_exclude / capture_exclude / intranet_allowed
    public let matchType: String // cert_fingerprint / ca_spki / domain_exact / domain_suffix
    public let matchValue: String
    public let domainScope: String?
    public let appScope: String?
    public let origin: String // user / config / system
    public let explanation: String
    public let expiresAtMs: Int64?
    public let revision: Int64

    public init(
        ruleId: String,
        name: String,
        kind: String,
        matchType: String,
        matchValue: String,
        domainScope: String?,
        appScope: String? = nil,
        origin: String,
        explanation: String,
        expiresAtMs: Int64?,
        revision: Int64
    ) {
        self.ruleId = ruleId
        self.name = name
        self.kind = kind
        self.matchType = matchType
        self.matchValue = matchValue
        self.domainScope = domainScope
        self.appScope = appScope
        self.origin = origin
        self.explanation = explanation
        self.expiresAtMs = expiresAtMs
        self.revision = revision
    }

    enum CodingKeys: String, CodingKey {
        case ruleId = "rule_id"
        case name
        case kind
        case matchType = "match_type"
        case matchValue = "match_value"
        case domainScope = "domain_scope"
        case appScope = "app_scope"
        case origin
        case explanation
        case expiresAtMs = "expires_at_ms"
        case revision
    }
}

// MARK: - Timeline event data transfer objects

public struct TimelineEvent: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let timeMs: Int64
    public let timeFormatted: String
    public let kind: String // new_ca / verdict_change / epoch_switch / budget_exhausted / adapter_disconnect / export_completed / rule_change / system
    public let title: String
    public let detail: String
    public let category: String
    public let isChange: Bool

    public init(
        id: String,
        timeMs: Int64,
        timeFormatted: String,
        kind: String,
        title: String,
        detail: String,
        category: String,
        isChange: Bool = true
    ) {
        self.id = id
        self.timeMs = timeMs
        self.timeFormatted = timeFormatted
        self.kind = kind
        self.title = title
        self.detail = detail
        self.category = category
        self.isChange = isChange
    }

    enum CodingKeys: String, CodingKey {
        case id
        case timeMs = "time_ms"
        case timeFormatted = "time_formatted"
        case kind
        case title
        case detail
        case category
        case isChange = "is_change"
    }
}

// MARK: - Configuration data transfer objects

public struct Configuration: Codable, Sendable, Equatable {
    public var launchAtLogin: Bool
    public var resumeAfterBoot: Bool
    public var appearance: String // "system" / "light" / "dark"
    public var menuBarContent: String // "icon_ratio" / "icon_only"
    public var defaultSource: String // "probe_domain" / "actual_request"
    public var defaultWindowSeconds: Int // 3600
    public var systemCaptureEnabled: Bool
    public var autoProbeEnabled: Bool
    public var probeRatePerMinute: Int // 12
    public var dailyBudget: Int // 1000
    public var lowPowerMode: String // "auto" / "off" / "on"
    public var browserEnhancedEnabled: Bool
    public var retentionDetailHours: Int // 24
    public var retentionSummaryDays: Int // 30
    public var privacyMaskEnabled: Bool
    public var notificationsEnabled: Bool
    public var revision: Int64

    public init(
        launchAtLogin: Bool = false,
        resumeAfterBoot: Bool = false,
        appearance: String = "system",
        menuBarContent: String = "icon_ratio",
        defaultSource: String = "probe_domain",
        defaultWindowSeconds: Int = 3600,
        systemCaptureEnabled: Bool = false,
        autoProbeEnabled: Bool = false,
        probeRatePerMinute: Int = 12,
        dailyBudget: Int = 1000,
        lowPowerMode: String = "auto",
        browserEnhancedEnabled: Bool = false,
        retentionDetailHours: Int = 24,
        retentionSummaryDays: Int = 30,
        privacyMaskEnabled: Bool = false,
        notificationsEnabled: Bool = false,
        revision: Int64 = 1
    ) {
        self.launchAtLogin = launchAtLogin
        self.resumeAfterBoot = resumeAfterBoot
        self.appearance = appearance
        self.menuBarContent = menuBarContent
        self.defaultSource = defaultSource
        self.defaultWindowSeconds = defaultWindowSeconds
        self.systemCaptureEnabled = systemCaptureEnabled
        self.autoProbeEnabled = autoProbeEnabled
        self.probeRatePerMinute = probeRatePerMinute
        self.dailyBudget = dailyBudget
        self.lowPowerMode = lowPowerMode
        self.browserEnhancedEnabled = browserEnhancedEnabled
        self.retentionDetailHours = retentionDetailHours
        self.retentionSummaryDays = retentionSummaryDays
        self.privacyMaskEnabled = privacyMaskEnabled
        self.notificationsEnabled = notificationsEnabled
        self.revision = revision
    }

    enum CodingKeys: String, CodingKey {
        case launchAtLogin = "launch_at_login"
        case resumeAfterBoot = "resume_after_boot"
        case appearance
        case menuBarContent = "menu_bar_content"
        case defaultSource = "default_source"
        case defaultWindowSeconds = "default_window_seconds"
        case systemCaptureEnabled = "system_capture_enabled"
        case autoProbeEnabled = "auto_probe_enabled"
        case probeRatePerMinute = "probe_rate_per_minute"
        case dailyBudget = "daily_budget"
        case lowPowerMode = "low_power_mode"
        case browserEnhancedEnabled = "browser_enhanced_enabled"
        case retentionDetailHours = "retention_detail_hours"
        case retentionSummaryDays = "retention_summary_days"
        case privacyMaskEnabled = "privacy_mask_enabled"
        case notificationsEnabled = "notifications_enabled"
        case revision
    }
}

// MARK: - RPC protocol and error wrappers

extension NSNotification.Name {
    public static let swgBarDataChanged = NSNotification.Name("SWGBarDataChangedNotification")
}

// MARK: - Domain normalization and parsing
public enum DomainNormalizer {
    /// Normalize case, remove trailing dots, convert to ASCII, and validate hostname labels.
    public static func normalize(hostname: String) -> String? {
        var host = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.isEmpty { return nil }

        // Reject strings containing a port.
        if host.contains(":") {
            if let portIdx = host.lastIndex(of: ":") {
                host = String(host[..<portIdx])
            }
        }

        // Remove the trailing dot.
        while host.hasSuffix(".") {
            host.removeLast()
        }
        if host.isEmpty { return nil }

        // Convert to lowercase.
        host = host.lowercased()

        // Reject control characters.
        for scalar in host.unicodeScalars {
            if scalar.value < 32 || scalar.value == 127 {
                return nil
            }
        }

        // Validate label lengths and reject empty labels.
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        for label in labels {
            if label.isEmpty || label.count > 63 {
                return nil
            }
        }
        if host.count > 253 { return nil }

        return host
    }

    /// Identify private, reserved, loopback, and link-local addresses.
    public static func isPrivateOrReservedIP(_ hostOrIP: String) -> Bool {
        let lower = hostOrIP.lowercased()
        if lower.hasSuffix(".local") || lower.hasSuffix(".internal") || lower.hasSuffix(".corp") || lower.hasSuffix(".lan") || lower == "localhost" {
            return true
        }

        let parts = hostOrIP.split(separator: ".")
        // A hostname that is not a four-part numeric IPv4 literal is eligible for further resolution.
        guard parts.count == 4,
              let p0 = Int(parts[0]),
              let p1 = Int(parts[1]),
              let p2 = Int(parts[2]),
              let p3 = Int(parts[3]),
              p0 >= 0 && p0 <= 255,
              p1 >= 0 && p1 <= 255,
              p2 >= 0 && p2 <= 255,
              p3 >= 0 && p3 <= 255 else {
            return false
        }

        // 127.0.0.0/8 Loopback
        if p0 == 127 { return true }
        // 10.0.0.0/8 RFC1918
        if p0 == 10 { return true }
        // 172.16.0.0/12 RFC1918
        if p0 == 172 && (p1 >= 16 && p1 <= 31) { return true }
        // 192.168.0.0/16 RFC1918
        if p0 == 192 && p1 == 168 { return true }
        // 169.254.0.0/16 Link-Local
        if p0 == 169 && p1 == 254 { return true }
        // 100.64.0.0/10 CGNAT
        if p0 == 100 && (p1 >= 64 && p1 <= 127) { return true }
        // 0.0.0.0/8 & 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved
        if p0 == 0 || p0 >= 224 { return true }

        return false
    }

    /// Extract an apex or registrable domain.
    public static func extractApexDomain(_ hostname: String) -> String {
        var host = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.contains(":") {
            if let portIdx = host.lastIndex(of: ":") {
                host = String(host[..<portIdx])
            }
        }
        while host.hasSuffix(".") { host.removeLast() }
        let parts = host.split(separator: ".")
        if parts.count <= 2 {
            return host
        }
        // Handle common two-part suffixes such as .com.cn, .net.cn, .org.cn, .co.uk, and .co.jp.
        let secondToLast = String(parts[parts.count - 2])
        let last = String(parts[parts.count - 1])
        let twoPartTLDs: Set<String> = [
            "com.cn", "org.cn", "net.cn", "edu.cn", "gov.cn",
            "co.uk", "org.uk", "co.jp", "com.hk", "org.hk"
        ]
        let suffix = "\(secondToLast).\(last)"
        if twoPartTLDs.contains(suffix) && parts.count >= 3 {
            return "\(parts[parts.count - 3]).\(suffix)"
        }
        return "\(parts[parts.count - 2]).\(last)"
    }
}

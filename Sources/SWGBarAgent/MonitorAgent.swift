//
// SWGBar / macOS menu bar TLS inspection detector
// Local coordination service (MonitorAgent.swift)
// Actor-based coordination for scheduling, immutable snapshots, and RPC routing.
//

import Foundation
import SWGBarContracts
import SWGBarStorage
import SWGBarFilter

public actor MonitorAgent {
    public static let shared = MonitorAgent()

    private let db: SQLiteDatabase
    private let repository: StorageRepository
    private let scheduler: ProbeScheduler
    private let bridge: CoreWorkerBridge
    private let classifier: ClassificationEngine
    private let epochManager: NetworkEpochManager
    public nonisolated let snapshotService: SnapshotService

    private var config: Configuration
    private var collectorState: CollectorState = .running
    private var activeGeneration: Int = 1
    private var pendingProbeFeederTask: Task<Void, Never>?
    public static let pendingProbeBatchSize = 50

    public init(databasePath: String? = nil) {
        let database: SQLiteDatabase
        if let path = databasePath {
            database = (try? SQLiteDatabase(path: path)) ?? (try! SQLiteDatabase.inMemory())
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            let dir = appSupport.appendingPathComponent("SWGBar", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let dbFile = dir.appendingPathComponent("swgbar.sqlite").path
            database = (try? SQLiteDatabase(path: dbFile)) ?? (try! SQLiteDatabase.inMemory())
        }

        self.db = database
        self.repository = StorageRepository(db: database)
        self.scheduler = ProbeScheduler()
        self.bridge = CoreWorkerBridge.shared
        self.classifier = ClassificationEngine.shared
        self.epochManager = NetworkEpochManager.shared
        self.snapshotService = SnapshotService(repository: self.repository)
        self.config = Configuration()

        let repo = self.repository
        self.epochManager.onEpochChanged = { newId, newName in
            try? repo.createEpoch(
                id: newId,
                name: newName,
                routeDigest: "digest-live",
                startMs: Int64(Date().timeIntervalSince1970 * 1000)
            )
        }
    }

    // MARK: - Load local keychain CAs and active connections
    public func populateLiveSystemData(enableBatchFeeder: Bool = true) async {
        // 1. Initialize the current network epoch.
        try? repository.createEpoch(
            id: epochManager.currentEpochId,
            name: epochManager.currentEpochName,
            routeDigest: "digest-live",
            startMs: Int64(Date().timeIntervalSince1970 * 1000)
        )

        // 2. Load additional trusted roots installed in the local keychain.
        let realCAs = NativeTrustEvaluator.shared.extractAllInstalledExtraTrustCAs()
        for ca in realCAs {
            _ = try? repository.upsertCACluster(
                spkiSha256: ca.spkiSha256,
                caName: ca.caName,
                identityKind: ca.identityKind,
                certId: ca.certSha256
            )
            if let rule = ca.activeRule {
                try? repository.upsertRule(rule)
            }
        }

        try? repository.logEvent(
            kind: "system",
            title: "Additional trusted certificates loaded from the local keychain",
            detail: "Found \(realCAs.count) additional trusted roots in the user and administrator domains",
            category: "system"
        )

        // 3. Reevaluate historical private CAs for automatic inspection confirmation.
        await autoConfirmMultiTargetCAs()

        // 4. Import browser history once to establish baseline targets and request counts.
        await importBrowserHistoryIfFirstLaunch()

        // 5. Start four concurrent workers consuming the probe channel.
        startChannelWorkers(workerCount: 4)

        // 5. Start outbound HTTPS metadata capture for local processes.
        startSystemNetworkSniffer()

        // 6. Probe the initial historical baseline in batches of 50; discover subsequent targets from capture.
        if enableBatchFeeder && !repository.hasCompletedHistoricalBaselineProbe() {
            startPendingProbeFeeder()
        }
    }

    // MARK: - Live network metadata and TLS probes

    /// Capture TLS SNI and connection reuse on any TCP port, with DNS address mapping.
    public func startSystemNetworkSniffer() {
        let sniffer = SystemPacketSniffer.shared
        sniffer.onTargetCaptured = { [weak self] host, port, remoteIp, egressInterface in
            Task { [weak self] in
                await self?.handleLiveCapturedDomain(host: host, port: port, remoteIp: remoteIp, egressInterface: egressInterface)
            }
        }
        sniffer.start()
    }

    /// Handle a hostname and port discovered by live capture.
    public func handleLiveCapturedDomain(host: String, port: Int = 443, remoteIp: String, egressInterface: String = "") async {
        guard collectorState == .running else { return }
        guard let normalized = DomainNormalizer.normalize(hostname: host) else { return }
        if DomainNormalizer.isPrivateOrReservedIP(normalized) { return }

        let effectivePort = port > 0 ? port : 443
        do {
            // 1. Increment the request count atomically in one SQL statement.
            let targetId = try repository.getOrCreateTarget(hostname: normalized, port: effectivePort)
            try repository.atomicIncrementRequestCount(targetId: targetId)

            // 2. Throttle UI count updates to one notification every 0.8 seconds.
            postDataChangedNotificationThrottled(minInterval: 0.8)

            // 3. Remember the latest observed outbound interface as a fallback for probe records.
            if !egressInterface.isEmpty {
                rememberEgressInterface(host: normalized, port: effectivePort, interface: egressInterface)
            }

            // 4. Enqueue the target so an available worker can start a TLS probe.
            await DomainProbeChannel.shared.send(host: normalized, port: effectivePort)
        } catch {
            AppLogger.shared.warn("Capture", "Could not persist captured target host=\(normalized):\(effectivePort): \(error)")
            return
        }
    }

    // MARK: - Outbound interfaces observed by network capture
    private var observedEgressInterfaces: [String: String] = [:]

    private func rememberEgressInterface(host: String, port: Int, interface: String) {
        if observedEgressInterfaces.count > 2000 {
            observedEgressInterfaces.removeAll()
        }
        observedEgressInterfaces["\(host):\(port)"] = interface
    }

    private func capturedEgressInterface(host: String, port: Int) -> String? {
        observedEgressInterfaces["\(host):\(port)"]
    }

    // MARK: - Throttle data-change notifications
    private var lastDataNotificationTime: TimeInterval = 0

    public func postDataChangedNotificationThrottled(minInterval: TimeInterval = 0.8) {
        let now = ProcessInfo.processInfo.systemUptime
        if now - lastDataNotificationTime < minInterval {
            return
        }
        lastDataNotificationTime = now

        DispatchQueue.main.async {
            NotificationCenter.default.post(name: .swgBarDataChanged, object: nil)
        }
    }

    // MARK: - Discover targets from browser history

    /// Import browser history once for a new local database; skip subsequent launches.
    public func importBrowserHistoryIfFirstLaunch() async {
        if repository.hasCompletedBrowserHistoryImport() {
            AppLogger.shared.info("BrowserHistory", "Skipping browser history import: already completed on first launch")
            return
        }
        // Existing targets indicate an earlier installation, so history should not be imported again.
        if repository.hasAnyTargets() {
            try? repository.markBrowserHistoryImportCompleted()
            AppLogger.shared.info("BrowserHistory", "Skipping browser history import: existing targets indicate a previous launch")
            return
        }
        await discoverDomainsFromBrowserHistory()
        try? repository.markBrowserHistoryImportCompleted()
    }

    /// Import HTTPS endpoints and their recorded request counts from browser history.
    public func discoverDomainsFromBrowserHistory() async {
        let scanner = BrowserHistoryScanner.shared
        let discovered = scanner.scanAllBrowserHistories()

        guard !discovered.isEmpty else { return }

        // Write discovered targets and update request counts.
        var importedCount = 0
        for domain in discovered {
            do {
                let targetId = try repository.getOrCreateTarget(hostname: domain.hostname, port: domain.port, requestCount: domain.requestCount)
                _ = targetId
                importedCount += 1
            } catch {
                continue
            }
        }

        AppLogger.shared.info("BrowserHistory", "Imported \(importedCount) baseline targets from local browser history")
        try? repository.logEvent(
            kind: "browser_discovery",
            title: "Browser history baseline loaded",
            detail: "Imported \(importedCount) targets from local Chromium browsers",
            category: "system"
        )
    }

    // MARK: - Concurrent channel workers

    private var channelWorkerTasks: [Task<Void, Never>] = []

    /// Start four concurrent workers consuming the target channel.
    public func startChannelWorkers(workerCount: Int = 4) {
        stopChannelWorkers()

        for _ in 0..<workerCount {
            let task = Task { [weak self] in
                while !Task.isCancelled {
                    guard let target = await DomainProbeChannel.shared.receive() else {
                        break
                    }
                    if Task.isCancelled {
                        await DomainProbeChannel.shared.markFinished()
                        break
                    }
                    guard let self = self else {
                        await DomainProbeChannel.shared.markFinished()
                        break
                    }
                    let state = await self.getCollectorState()
                    if state == .running {
                        // Probe the captured hostname and destination port with a TLS handshake.
                        _ = await self.startManualProbe(hostname: target.host, port: target.port)
                        await self.postDataChangedNotificationThrottled(minInterval: 0.8)
                    }
                    await DomainProbeChannel.shared.markFinished()
                }
            }
            channelWorkerTasks.append(task)
        }
    }

    /// Stop the worker pool.
    public func stopChannelWorkers() {
        for t in channelWorkerTasks {
            t.cancel()
        }
        channelWorkerTasks.removeAll()
        Task {
            await DomainProbeChannel.shared.closeOrReset()
        }
    }

    // MARK: - Probe the initial historical baseline in batches of 50

    public func startPendingProbeFeeder() {
        if let existing = pendingProbeFeederTask, !existing.isCancelled {
            return
        }
        pendingProbeFeederTask = Task { [weak self] in
            var batchIndex = 0
            while !Task.isCancelled {
                guard let self else { break }
                let state = await self.getCollectorState()
                guard state == .running else {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    continue
                }

                let batch = await self.loadNeverProbedBatch()
                if batch.isEmpty {
                    try? self.repository.markHistoricalBaselineProbeCompleted()
                    AppLogger.shared.info("ProbeFeeder", "Historical baseline probing is complete; new targets will be discovered from network metadata")
                    break
                }

                batchIndex += 1
                var seen = Set<String>()
                var sentIds: [String] = []
                for item in batch {
                    let key = "\(item.hostname.lowercased()):\(item.port)"
                    guard seen.insert(key).inserted else { continue }
                    await DomainProbeChannel.shared.send(host: item.hostname, port: item.port, force: true)
                    sentIds.append(item.targetId)
                }

                let remaining = await self.countNeverProbedTargets()
                AppLogger.shared.info(
                    "ProbeFeeder",
                    "Batch \(batchIndex): queued \(sentIds.count) unique host/port targets (limit \(Self.pendingProbeBatchSize)); \(remaining) targets still have no observations"
                )
                await self.waitUntilBatchProbed(targetIds: sentIds)
            }
            await self?.clearPendingProbeFeederTask()
        }
    }

    public func stopPendingProbeFeeder() {
        pendingProbeFeederTask?.cancel()
        pendingProbeFeederTask = nil
    }

    private func clearPendingProbeFeederTask() {
        pendingProbeFeederTask = nil
    }

    private func loadNeverProbedBatch() -> [(targetId: String, hostname: String, port: Int)] {
        (try? repository.listTargetsNeverProbed(limit: Self.pendingProbeBatchSize)) ?? []
    }

    private func countNeverProbedTargets() -> Int {
        (try? repository.countTargetsNeverProbed()) ?? 0
    }

    /// Wait only for this batch, so continuous live capture cannot block the next batch.
    private func waitUntilBatchProbed(targetIds: [String], timeoutSeconds: TimeInterval = 180) async {
        guard !targetIds.isEmpty else { return }
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline, !Task.isCancelled {
            let leftover = (try? repository.countNeverProbed(amongTargetIds: targetIds)) ?? targetIds.count
            if leftover == 0 { return }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    // MARK: - Clear historical probe data
    public func clearAllHistoricalData() {
        stopChannelWorkers()
        stopPendingProbeFeeder()
        Task {
            await DomainProbeChannel.shared.clearCooldowns()
        }
        try? repository.clearAllHistoricalData()
        startChannelWorkers(workerCount: 4)
    }

    // MARK: - State and configuration

    public func getCollectorState() -> CollectorState {
        return collectorState
    }

    public func setCollectorState(_ state: CollectorState) {
        self.collectorState = state
        if state == .paused {
            SystemPacketSniffer.shared.stop()
        } else if state == .running {
            SystemPacketSniffer.shared.start()
        }
        try? repository.logEvent(
            kind: "collector_state",
            title: state == .paused ? "Monitoring paused" : "Monitoring resumed",
            detail: "State changed to \(state.rawValue)",
            category: "system"
        )
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: .swgBarDataChanged, object: nil)
        }
    }

    // MARK: - Snapshots and view queries

    public func getOverviewSnapshot(metricKind: String? = nil, windowSeconds: Int? = nil) -> OverviewSnapshot {
        let kind = metricKind ?? "probe_domain"
        let window = windowSeconds ?? 0
        return snapshotService.getOverviewSnapshot(
            metricKind: kind,
            epochId: "",
            windowSeconds: window,
            collectorState: self.collectorState
        )
    }

    public func listDomains(
        search: String = "",
        statusFilter: String = "ALL",
        certFilter: String = "ALL",
        sourceFilter: String = "ALL",
        appFilter: String = "ALL",
        sort: String = "REQUEST_COUNT"
    ) -> [DomainRow] {
        return snapshotService.listDomains(
            search: search,
            statusFilter: statusFilter,
            certFilter: certFilter,
            sourceFilter: sourceFilter,
            appFilter: appFilter,
            sort: sort
        )
    }

    public func getDomainDetail(targetId: String) -> DomainDetail {
        return snapshotService.getDomainDetail(targetId: targetId)
    }

    public func listCAClusters(showAll: Bool = true, forceRefresh: Bool = false) -> [CADetail] {
        return snapshotService.listCAClusters(showAll: showAll, forceRefresh: forceRefresh)
    }

    public func listHostnamesForCA(clusterId: String = "", spki: String = "", caName: String = "") -> [String] {
        return (try? repository.listHostnamesForCA(clusterId: clusterId, spki: spki, caName: caName)) ?? []
    }

    public func listEvents(onlyChanges: Bool = false) -> [TimelineEvent] {
        return snapshotService.listTimelineEvents(onlyChanges: onlyChanges)
    }

    public func listRules() throws -> [Rule] {
        return try repository.listRules()
    }

    public func upsertRule(_ rule: Rule) throws {
        try repository.upsertRule(rule)
        try? repository.reclassifyObservationsForRule(rule)
        try repository.logEvent(
            kind: "rule_change",
            title: "Rule updated",
            detail: "\(rule.name) (\(rule.kind))",
            category: "rule"
        )
    }

    public func deleteRule(ruleId: String) throws {
        try repository.deleteRule(ruleId: ruleId)
        try repository.logEvent(
            kind: "rule_delete",
            title: "Rule deleted",
            detail: "ID: \(ruleId)",
            category: "rule"
        )
    }

    // MARK: - Schedule and execute active probes

    public func startManualProbe(hostname: String, port: Int = 443) async -> (success: Bool, message: String) {
        guard let normalized = DomainNormalizer.normalize(hostname: hostname) else {
            return (false, "The hostname is invalid or contains unsupported characters")
        }

        let isPrivate = DomainNormalizer.isPrivateOrReservedIP(normalized)
        if isPrivate {
            return (false, "Probing private or reserved addresses is disabled by default. Add an explicit private-network probe rule first.")
        }

        var canSchedule = await scheduler.canSchedule(target: "\(normalized):\(port)", isUserInitiated: true)
        if !canSchedule.allowed {
            for _ in 0..<4 {
                try? await Task.sleep(nanoseconds: 500_000_000)
                canSchedule = await scheduler.canSchedule(target: "\(normalized):\(port)", isUserInitiated: true)
                if canSchedule.allowed { break }
            }
        }
        guard canSchedule.allowed else {
            return (false, canSchedule.reason ?? "Probe scheduling limit exceeded")
        }

        _ = await scheduler.startProbe(target: "\(normalized):\(port)", isUserInitiated: true)

        let probeResult = await bridge.executeProbe(host: normalized, port: port)
        await scheduler.finishProbe(target: "\(normalized):\(port)")

        // Persist and classify the result.
        do {
            let currentEpochId = epochManager.currentEpochId
            try? repository.createEpoch(
                id: currentEpochId,
                name: epochManager.currentEpochName,
                routeDigest: "digest-live",
                startMs: Int64(Date().timeIntervalSince1970 * 1000)
            )

            let targetId = try repository.getOrCreateTarget(hostname: normalized, port: port)

            // Use the outbound interface observed by capture; leave it empty if unavailable instead of querying again.
            let resolvedEgressInterface: String? = capturedEgressInterface(host: normalized, port: port)

            // Persist each probe in one transaction to reduce WAL synchronization.
            let verdict: String = try repository.transaction {
                let obsRecord = StorageRepository.ObservationRecord(
                    sourceInstanceId: "manual_probe",
                    source: .nativeProbe,
                    objectKind: "probe",
                    generation: activeGeneration,
                    epochId: currentEpochId,
                    targetId: targetId,
                    observedAtMs: Int64(Date().timeIntervalSince1970 * 1000),
                    stage: probeResult.handshakeCompleted ? "completed" : "failed",
                    scopeJson: "{\"address_family\":\"ipv4\"}",
                    remoteIp: probeResult.remoteIp,
                    egressInterface: resolvedEgressInterface,
                    routeType: probeResult.routeType
                )
                try repository.saveObservation(obsRecord)

                // 1. Save the presented certificates, associations, and CA clusters.
                let caName = probeResult.caSubjects.count > 1 ? probeResult.caSubjects[1] : (probeResult.caSubjects.first ?? "")
                let extraAnchorSubject = probeResult.extraAnchorSubject ?? ""
                let effectiveCAName = !extraAnchorSubject.isEmpty ? extraAnchorSubject : caName
                let primarySPKI = probeResult.presentedSpkiIds.count > 1 ? probeResult.presentedSpkiIds[1] : (probeResult.presentedSpkiIds.first ?? "")

                // Aggregate certificate persistence failures into one log entry per probe.
                var chainPersistFailures = 0
                for (idx, certId) in probeResult.presentedCertIds.enumerated() {
                    let spki = (idx < probeResult.presentedSpkiIds.count) ? probeResult.presentedSpkiIds[idx] : certId
                    let der = (idx < probeResult.presentedDers.count) ? probeResult.presentedDers[idx] : Data([0x30, 0x82])
                    let subj = (idx < probeResult.caSubjects.count) ? probeResult.caSubjects[idx] : ""
                    let role = (idx == 0) ? "leaf" : "intermediate"
                    let issuerName = (idx < probeResult.issuers.count && !probeResult.issuers[idx].isEmpty)
                        ? probeResult.issuers[idx]
                        : ((idx == 0 && probeResult.caSubjects.count > 1) ? probeResult.caSubjects[1] : (idx > 0 ? subj : effectiveCAName))

                    let notBefore = (idx < probeResult.notBeforeMs.count && probeResult.notBeforeMs[idx] > 0)
                        ? probeResult.notBeforeMs[idx]
                        : (Int64(Date().timeIntervalSince1970 * 1000) - 86400000)
                    let notAfter = (idx < probeResult.notAfterMs.count && probeResult.notAfterMs[idx] > 0)
                        ? probeResult.notAfterMs[idx]
                        : (Int64(Date().timeIntervalSince1970 * 1000) + 31536000000)

                    var certPersistFailed = false
                    do {
                        try repository.saveCertificate(
                        certId: certId,
                        spkiId: spki,
                        derBytes: der,
                        subject: subj,
                        issuer: issuerName,
                        notBeforeMs: notBefore,
                        notAfterMs: notAfter,
                        isCa: idx > 0,
                        keyUsage: ["digitalSignature"],
                        sigAlg: "ECDSA-SHA384"
                        )
                    } catch {
                        certPersistFailed = true
                    }
                    do {
                        try repository.linkObservationCertificate(obsId: obsRecord.id, certId: certId, role: role, chainType: "presented", ordinal: idx)
                    } catch {
                        certPersistFailed = true
                    }
                    if certPersistFailed {
                        chainPersistFailures += 1
                    }

                    if idx > 0 && idx < probeResult.caSubjects.count {
                        let caNameEntry = probeResult.caSubjects[idx]
                        let isPublic = probeResult.publicPkixPassed || !probeResult.isExtraAnchor
                        let kind = isPublic ? "public" : (probeResult.nativeAccepted ? "suspected" : "unknown")
                        do {
                            _ = try repository.upsertCACluster(spkiSha256: spki, caName: caNameEntry, identityKind: kind, certId: certId)
                        } catch {
                            chainPersistFailures += 1
                        }
                    }
                }

                if chainPersistFailures > 0 {
                    AppLogger.shared.error("Storage", "Failed to persist \(chainPersistFailures) certificate chain entries for \(normalized):\(port); the target may not link to its CA")
                }

                // 2. Detect inspection patterns and apply automatic confirmation.
                // Condition 1: public validation fails but a locally added root is trusted.
                if probeResult.isExtraAnchor && !probeResult.publicPkixPassed && probeResult.nativeAccepted {
                    let domainStats = (try? repository.countDistinctDomainsForCA(spki: primarySPKI, caName: effectiveCAName)) ?? (total: 1, apex: 1)

                    // Condition 2: the same private root appears across more than 10 distinct domains.
                    if domainStats.total > 10 {
                        let ruleKey = !primarySPKI.isEmpty ? primarySPKI : effectiveCAName
                        let autoRule = Rule(
                            ruleId: "auto_rule_" + String(ruleKey.prefix(16)).replacingOccurrences(of: ":", with: "").lowercased(),
                            name: effectiveCAName.isEmpty ? "Enterprise inspection CA" : effectiveCAName,
                            kind: "inspection_ca",
                            matchType: !primarySPKI.isEmpty ? "ca_spki" : "ca_name",
                            matchValue: ruleKey,
                            domainScope: nil,
                            origin: "system_auto",
                            explanation: "Inspection criteria met: public validation failed, a locally trusted root was accepted, and more than 10 distinct domains were observed (\(domainStats.total) domains)",
                            expiresAtMs: nil,
                            revision: 1
                        )
                        do {
                            try repository.upsertRule(autoRule)
                            try repository.upgradeAllToConfirmedForCA(caName: effectiveCAName, spkiSha256: primarySPKI)
                        } catch {
                            AppLogger.shared.error("Classification", "Could not persist the automatic confirmation rule for CA \"\(effectiveCAName)\"; classification was not applied: \(error)")
                        }
                        AppLogger.shared.info("Classification", "Automatically confirmed private CA \"\(effectiveCAName)\": public validation failed, a local root was trusted, and \(domainStats.total) distinct domains were observed")
                    }
                }

                // 3. Apply the final classification.
                let recurrenceCount = max(1, (try? repository.countDomainsForCA(caName: effectiveCAName)) ?? 1)
                let rules = (try? repository.listRules()) ?? []

                let classification = classifier.classify(
                    hostname: normalized,
                    port: port,
                    isIpv4: true,
                    isHttps: true,
                    isOwnTraffic: false,
                    handshakeCompleted: probeResult.handshakeCompleted,
                    nativeAccepted: probeResult.nativeAccepted,
                    publicPkixPassed: probeResult.publicPkixPassed,
                    presentedCertIds: probeResult.presentedCertIds,
                    presentedSpkiIds: probeResult.presentedSpkiIds,
                    caSubjects: probeResult.caSubjects,
                    isExtraTrustAnchor: probeResult.isExtraAnchor,
                    extraAnchorSubject: probeResult.extraAnchorSubject,
                    caDomainRecurrenceCount: recurrenceCount,
                    rules: rules
                )

                try repository.saveClassification(
                    obsId: obsRecord.id,
                    revision: 1,
                    verdict: classification.verdict,
                    reason: classification.reason
                )

                // 4. Upgrade historical unknown verdicts to suspected when cross-domain recurrence reaches 2 through 10 targets.
                if recurrenceCount >= 2 && classification.verdict != .confirmedInspection {
                    try? repository.upgradeUnknownToSuspectedForCA(caName: effectiveCAName)
                }

                AppLogger.shared.info("Classification", "Classification host=\(normalized):\(port) -> \(classification.verdict.shortLabel) | reason: \(classification.reason) | CA: \"\(effectiveCAName)\" (associated domains: \(recurrenceCount))")
                return classification.verdict.shortLabel
            }

            return (true, "Probe complete: \(verdict)")
        } catch {
            AppLogger.shared.error("Probe", "Could not persist probe result host=\(normalized):\(port): \(error)")
            return (false, "Could not persist the result: \(error.localizedDescription)")
        }
    }

    // MARK: - Reevaluate historical private CA recurrence

    /// Evaluate historical observations on startup and confirm CAs meeting the inspection criteria.
    public func autoConfirmMultiTargetCAs() async {
        guard let clusters = try? repository.listCAClusters() else { return }
        for cluster in clusters {
            if cluster.identityKind == "public" { continue }

            let stats = (try? repository.countDistinctDomainsForCA(spki: cluster.spkiSha256, caName: cluster.caName)) ?? (total: 0, apex: 0)
            // Condition 2: one private root appears across more than 10 distinct domains.
            if stats.total > 10 {
                let ruleKey = !cluster.spkiSha256.isEmpty ? cluster.spkiSha256 : cluster.caName
                let autoRule = Rule(
                    ruleId: "auto_rule_" + String(ruleKey.prefix(16)).replacingOccurrences(of: ":", with: "").lowercased(),
                    name: cluster.caName.isEmpty ? "Enterprise inspection CA" : cluster.caName,
                    kind: "inspection_ca",
                    matchType: !cluster.spkiSha256.isEmpty ? "ca_spki" : "ca_name",
                    matchValue: ruleKey,
                    domainScope: nil,
                    origin: "system_auto",
                    explanation: "Inspection criteria met: public validation failed, a locally trusted root was accepted, and more than 10 distinct domains were observed (\(stats.total) domains)",
                    expiresAtMs: nil,
                    revision: 1
                )
                do {
                    try repository.upsertRule(autoRule)
                    try repository.upgradeAllToConfirmedForCA(caName: cluster.caName, spkiSha256: cluster.spkiSha256)
                } catch {
                    AppLogger.shared.error("Startup", "Startup confirmation failed for CA \"\(cluster.caName)\"; classification was not applied: \(error)")
                    continue
                }
                AppLogger.shared.info("Startup", "Startup check confirmed historical CA \"\(cluster.caName)\": inspection criteria met across \(stats.total) distinct domains")
            }
        }
    }

    // MARK: - Clear all data (data.clear)

}

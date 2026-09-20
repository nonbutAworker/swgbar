//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 本地协调服务 (MonitorAgent.swift)
// 遵循技术方案 v1.1 第 06, 26-28 章：单写者 actor、调度、不可变快照生成、RPC 路由器
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

    // MARK: - 启动时加载本机真实 Keychain CA 与活跃网络连接
    public func populateLiveSystemData(enableBatchFeeder: Bool = true) async {
        // 1. 初始化当前网络阶段
        try? repository.createEpoch(
            id: epochManager.currentEpochId,
            name: epochManager.currentEpochName,
            routeDigest: "digest-live",
            startMs: Int64(Date().timeIntervalSince1970 * 1000)
        )

        // 2. 加载本机 Keychain 中真实安装的额外信任根证书
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
            title: "已加载本机钥匙串额外信任证书",
            detail: "识别到 \(realCAs.count) 个用户/管理员额外信任根证书",
            category: "system"
        )

        // 3. 执行历史数据算法自检，自动确认具备多目标拦截特征的私有 CA
        await autoConfirmMultiTargetCAs()

        // 4. 仅首次启动扫描浏览器历史，建立基线目标与请求次数
        await importBrowserHistoryIfFirstLaunch()

        // 5. 启动类似 Golang channel 的并发工作池（4 个并发 worker 持续监听）
        startChannelWorkers(workerCount: 4)

        // 5. 启动系统网络层出站 HTTPS 实时嗅探器（自动捕获终端、客户端等所有进程流量）
        startSystemNetworkSniffer()

        // 6. 仅对首次导入的历史基线按每批 50 个探测一次；探完即停，新域名只靠嗅探
        if enableBatchFeeder && !repository.hasCompletedHistoricalBaselineProbe() {
            startPendingProbeFeeder()
        }
    }

    // MARK: - 网络层实时流量捕获与即时 TLS 握手响应

    /// 启动系统网络层出站 HTTPS 嗅探器（任意 TCP 端口的 TLS SNI / 复用，DNS 反查）
    public func startSystemNetworkSniffer() {
        let sniffer = SystemPacketSniffer.shared
        sniffer.onTargetCaptured = { [weak self] host, port, remoteIp, egressInterface in
            Task { [weak self] in
                await self?.handleLiveCapturedDomain(host: host, port: port, remoteIp: remoteIp, egressInterface: egressInterface)
            }
        }
        sniffer.start()
    }

    /// 处理网络层实时捕获的域名与端口
    public func handleLiveCapturedDomain(host: String, port: Int = 443, remoteIp: String, egressInterface: String = "") async {
        guard collectorState == .running else { return }
        guard let normalized = DomainNormalizer.normalize(hostname: host) else { return }
        if DomainNormalizer.isPrivateOrReservedIP(normalized) { return }

        let effectivePort = port > 0 ? port : 443
        do {
            // 1. 原子递增请求计数（单条 SQL，避免 SELECT + UPDATE 两次往返）
            let targetId = try repository.getOrCreateTarget(hostname: normalized, port: effectivePort)
            try repository.atomicIncrementRequestCount(targetId: targetId)

            // 2. 实时流式通知 UI 更新计数（节流至最多每 0.8 秒触发一次，杜绝通知风暴）
            postDataChangedNotificationThrottled(minInterval: 0.8)

            // 3. 记录该目标最近一次实际出站所用网卡，供探测落库时兜底使用
            if !egressInterface.isEmpty {
                rememberEgressInterface(host: normalized, port: effectivePort, interface: egressInterface)
            }

            // 4. 类似 Golang channel 的 ch <- target，瞬间放入通道，工作协程立刻消费并向该端口毫秒级发起探测
            await DomainProbeChannel.shared.send(host: normalized, port: effectivePort)
        } catch {
            AppLogger.shared.warn("Capture", "实时捕获目标落库失败 host=\(normalized):\(effectivePort): \(error)")
            return
        }
    }

    // MARK: - 出口网卡记录（来自网络层实时捕获）
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

    // MARK: - 实时变动通知节流器
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

    // MARK: - 从浏览器历史发现域名并更新数据库

    /// 仅在本机数据库首次启动时导入浏览器历史；后续启动跳过
    public func importBrowserHistoryIfFirstLaunch() async {
        if repository.hasCompletedBrowserHistoryImport() {
            AppLogger.shared.info("BrowserHistory", "跳过浏览器历史导入：仅首次启动执行一次")
            return
        }
        // 已有目标数据说明不是全新安装（例如升级前已经导入过），不再重复扫描历史
        if repository.hasAnyTargets() {
            try? repository.markBrowserHistoryImportCompleted()
            AppLogger.shared.info("BrowserHistory", "跳过浏览器历史导入：库中已有目标，视为非首次启动")
            return
        }
        await discoverDomainsFromBrowserHistory()
        try? repository.markBrowserHistoryImportCompleted()
    }

    /// 扫描浏览器历史记录，导入发现的 HTTPS 域名与真实请求次数
    public func discoverDomainsFromBrowserHistory() async {
        let scanner = BrowserHistoryScanner.shared
        let discovered = scanner.scanAllBrowserHistories()

        guard !discovered.isEmpty else { return }

        // 将发现的域名写入 targets 表，更新请求计数
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

        AppLogger.shared.info("BrowserHistory", "已从本机浏览器历史扫描导入 \(importedCount) 个出站访问基线目标")
        try? repository.logEvent(
            kind: "browser_discovery",
            title: "已加载浏览器出站访问基线",
            detail: "从本机 Chromium 浏览器导入 \(importedCount) 个目标",
            category: "system"
        )
    }

    // MARK: - 类似 Golang Channel 的并发工作协程池

    private var channelWorkerTasks: [Task<Void, Never>] = []

    /// 启动通道消费工作池 (类似 Go 的 4 个并发 goroutine 消费 channel: target := <-ch)
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
                        // 只要网络层捕获到域名与目标端口，立刻向对应端口发起纯 TLS 握手探测！
                        _ = await self.startManualProbe(hostname: target.host, port: target.port)
                        await self.postDataChangedNotificationThrottled(minInterval: 0.8)
                    }
                    await DomainProbeChannel.shared.markFinished()
                }
            }
            channelWorkerTasks.append(task)
        }
    }

    /// 停止工作池
    public func stopChannelWorkers() {
        for t in channelWorkerTasks {
            t.cancel()
        }
        channelWorkerTasks.removeAll()
        Task {
            await DomainProbeChannel.shared.closeOrReset()
        }
    }

    // MARK: - 首次历史基线分批探测（每批 50，探完即停，不再轮询新域名）

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
                    AppLogger.shared.info("ProbeFeeder", "历史基线目标已全部探测完毕，分批补探结束；后续新域名仅由网络嗅探触发")
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
                    "第 \(batchIndex) 批已入队 \(sentIds.count) 个历史基线目标（域名+端口去重，批量上限 \(Self.pendingProbeBatchSize)），当前仍有 \(remaining) 个尚未产生观测"
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

    /// 只等本批目标落库，避免被嗅探器持续入队挡住后续批次
    private func waitUntilBatchProbed(targetIds: [String], timeoutSeconds: TimeInterval = 180) async {
        guard !targetIds.isEmpty else { return }
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline, !Task.isCancelled {
            let leftover = (try? repository.countNeverProbed(amongTargetIds: targetIds)) ?? targetIds.count
            if leftover == 0 { return }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    // MARK: - 清空所有历史探测数据
    public func clearAllHistoricalData() {
        stopChannelWorkers()
        stopPendingProbeFeeder()
        Task {
            await DomainProbeChannel.shared.clearCooldowns()
        }
        try? repository.clearAllHistoricalData()
        startChannelWorkers(workerCount: 4)
    }

    // MARK: - 状态与配置管理

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
            title: state == .paused ? "监测已暂停" : "监测已恢复",
            detail: "状态切换为 \(state.rawValue)",
            category: "system"
        )
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: .swgBarDataChanged, object: nil)
        }
    }

    // MARK: - 快照与视图查询

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
            title: "规则更新",
            detail: "\(rule.name) (\(rule.kind))",
            category: "rule"
        )
    }

    public func deleteRule(ruleId: String) throws {
        try repository.deleteRule(ruleId: ruleId)
        try repository.logEvent(
            kind: "rule_delete",
            title: "规则已删除",
            detail: "ID: \(ruleId)",
            category: "rule"
        )
    }

    // MARK: - 主动探测触发与执行

    public func startManualProbe(hostname: String, port: Int = 443) async -> (success: Bool, message: String) {
        guard let normalized = DomainNormalizer.normalize(hostname: hostname) else {
            return (false, "域名格式非法或包含无效字符")
        }

        let isPrivate = DomainNormalizer.isPrivateOrReservedIP(normalized)
        if isPrivate {
            return (false, "目标为内网或私有保留地址，默认禁止探测；请先添加内网探测授权规则")
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
            return (false, canSchedule.reason ?? "超出调度限制")
        }

        _ = await scheduler.startProbe(target: "\(normalized):\(port)", isUserInitiated: true)

        let probeResult = await bridge.executeProbe(host: normalized, port: port)
        await scheduler.finishProbe(target: "\(normalized):\(port)")

        // 存储并分类
        do {
            let currentEpochId = epochManager.currentEpochId
            try? repository.createEpoch(
                id: currentEpochId,
                name: epochManager.currentEpochName,
                routeDigest: "digest-live",
                startMs: Int64(Date().timeIntervalSince1970 * 1000)
            )

            let targetId = try repository.getOrCreateTarget(hostname: normalized, port: port)

            // 出口网卡：仅取网络层抓包时已捕获到的真实出口，未捕获则留空，不额外发起任何查询
            let resolvedEgressInterface: String? = capturedEgressInterface(host: normalized, port: port)

            // 将所有探测结果写入包裹在单个事务中，减少 WAL 同步次数（~10+ → 1）
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

                // 1. 先保存对端呈现的证书、关联与 CA 聚类
                let caName = probeResult.caSubjects.count > 1 ? probeResult.caSubjects[1] : (probeResult.caSubjects.first ?? "")
                let extraAnchorSubject = probeResult.extraAnchorSubject ?? ""
                let effectiveCAName = !extraAnchorSubject.isEmpty ? extraAnchorSubject : caName
                let primarySPKI = probeResult.presentedSpkiIds.count > 1 ? probeResult.presentedSpkiIds[1] : (probeResult.presentedSpkiIds.first ?? "")

                // 证书链落库失败计数：逐条打印会随探测频次放大，按本次探测聚合为一条
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
                    AppLogger.shared.error("Storage", "证书链落库失败 \(chainPersistFailures) 处 host=\(normalized):\(port)，该域名可能无法关联到 CA")
                }

                // 2. 特征模式检测与自动确认 (Algorithmic SWG Auto-Confirmation)
                // 条件 1: 无法通过公网证书校验，且通过添加到本机的“受信任根证书”通过校验
                if probeResult.isExtraAnchor && !probeResult.publicPkixPassed && probeResult.nativeAccepted {
                    let domainStats = (try? repository.countDistinctDomainsForCA(spki: primarySPKI, caName: effectiveCAName)) ?? (total: 1, apex: 1)

                    // 条件 2: 多个不同的域名（超过10个）都是用该相同的私有根证书
                    if domainStats.total > 10 {
                        let ruleKey = !primarySPKI.isEmpty ? primarySPKI : effectiveCAName
                        let autoRule = Rule(
                            ruleId: "auto_rule_" + String(ruleKey.prefix(16)).replacingOccurrences(of: ":", with: "").lowercased(),
                            name: effectiveCAName.isEmpty ? "企业拦截代理 CA" : effectiveCAName,
                            kind: "inspection_ca",
                            matchType: !primarySPKI.isEmpty ? "ca_spki" : "ca_name",
                            matchValue: ruleKey,
                            domainScope: nil,
                            origin: "system_auto",
                            explanation: "满足SWG中间人特征: 无法通过公网校验、本机受信任根校验通过，且拦截超过10个不同域名 (\(domainStats.total) 个域名)",
                            expiresAtMs: nil,
                            revision: 1
                        )
                        do {
                            try repository.upsertRule(autoRule)
                            try repository.upgradeAllToConfirmedForCA(caName: effectiveCAName, spkiSha256: primarySPKI)
                        } catch {
                            AppLogger.shared.error("Classification", "自动确认规则落库失败，CA \"\(effectiveCAName)\" 判定未生效: \(error)")
                        }
                        AppLogger.shared.info("Classification", "⚡️ [自动确认] 私有 CA \"\(effectiveCAName)\" 命中了 SWG 中间人特征 (公网不通过 + 本机受信任根 + 超过10个不同域名: \(domainStats.total) 个)，已自动确认为【已确认】(Confirmed)")
                    }
                }

                // 3. 执行最终分类
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

                // 4. 当复现次数跨阈值 (2..10) 时，将历史未满足阈值的 unknown 自动升级为 suspected
                if recurrenceCount >= 2 && classification.verdict != .confirmedInspection {
                    try? repository.upgradeUnknownToSuspectedForCA(caName: effectiveCAName)
                }

                AppLogger.shared.info("Classification", "🎯 判定结果 host=\(normalized):\(port) -> 【\(classification.verdict.shortLabel)】 | 原因: \(classification.reason) | CA: \"\(effectiveCAName)\" (关联域名数: \(recurrenceCount))")
                return classification.verdict.shortLabel
            }

            return (true, "探测完成：判定为【\(verdict)】")
        } catch {
            AppLogger.shared.error("Probe", "探测结果落库失败 host=\(normalized):\(port): \(error)")
            return (false, "结果落库失败: \(error.localizedDescription)")
        }
    }

    // MARK: - 历史私有 CA 多目标特征算法自检

    /// 启动时根据历史观测数据，执行跨目标算法评估并自动确认已具备特征的 CA
    public func autoConfirmMultiTargetCAs() async {
        guard let clusters = try? repository.listCAClusters() else { return }
        for cluster in clusters {
            if cluster.identityKind == "public" { continue }

            let stats = (try? repository.countDistinctDomainsForCA(spki: cluster.spkiSha256, caName: cluster.caName)) ?? (total: 0, apex: 0)
            // 满足条件 2: 多个不同的域名（超过10个）都是用1个相同的私有根证书
            if stats.total > 10 {
                let ruleKey = !cluster.spkiSha256.isEmpty ? cluster.spkiSha256 : cluster.caName
                let autoRule = Rule(
                    ruleId: "auto_rule_" + String(ruleKey.prefix(16)).replacingOccurrences(of: ":", with: "").lowercased(),
                    name: cluster.caName.isEmpty ? "企业拦截代理 CA" : cluster.caName,
                    kind: "inspection_ca",
                    matchType: !cluster.spkiSha256.isEmpty ? "ca_spki" : "ca_name",
                    matchValue: ruleKey,
                    domainScope: nil,
                    origin: "system_auto",
                    explanation: "满足SWG中间人特征: 无法通过公网校验、本机受信任根校验通过，且拦截超过10个不同域名 (\(stats.total) 个域名)",
                    expiresAtMs: nil,
                    revision: 1
                )
                do {
                    try repository.upsertRule(autoRule)
                    try repository.upgradeAllToConfirmedForCA(caName: cluster.caName, spkiSha256: cluster.spkiSha256)
                } catch {
                    AppLogger.shared.error("Startup", "启动自检自动确认失败，CA \"\(cluster.caName)\" 判定未生效: \(error)")
                    continue
                }
                AppLogger.shared.info("Startup", "⚡️ 启动自检: 历史 CA \"\(cluster.caName)\" 满足 SWG 中间人特征 (拦截超过10个不同域名: \(stats.total) 个)，已自动确认为【已确认】")
            }
        }
    }

    // MARK: - 清理全部数据 (data.clear, 第 33.3 章)

}

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 界面视图模型 (AppViewModel.swift)
// 遵循技术方案 v1.1 第 15-28 章：版本化不可变快照消费、内联导航与各 Tab 交互
//

import SwiftUI
import Combine
import SWGBarContracts
import SWGBarAgent
import SWGBarStorage

@MainActor
public final class AppViewModel: ObservableObject {
    // MARK: - 导航与状态
    @Published public var selectedTab: Int = 0 // 0: 总览, 1: 域名, 2: 证书

    @Published public var showingOnboarding: Bool = false // 图 16-1 首次授权
    
    // 内联导航 (不创建第二窗口，第 15.1 章)
    @Published public var selectedDomainId: String? = nil // 进入域名详情 DD01-DD11
    @Published public var selectedCAClusterId: String? = nil // 进入 CA 详情 CD01-CD10
    
    // MARK: - 总览快照与状态
    @Published public var snapshot: OverviewSnapshot
    
    // 域名 Tab 状态
    @Published public var domainSearchText: String = "" // D01
    @Published public var domainStatusFilter: String = "ALL" // D02
    @Published public var domainCertFilter: String = "ALL" // 证书过滤器
    @Published public var availableCertOptions: [CertFilterOption] = []
    @Published public var domainSourceFilter: String = "ALL"
    @Published public var domainAppFilter: String = "ALL"
    @Published public var domainSortOption: String = "REQUEST_COUNT" // D03
    @Published public var domainRows: [DomainRow] = []
    private var cachedAllDomains: [DomainRow] = []
    
    // 分页机制（提升上千条域名的滚动与搜索渲染性能）
    public let domainPageSize: Int = 50
    @Published public var displayedDomainLimit: Int = 50
    @Published public var displayedDomainRows: [DomainRow] = []
    
    /// 同步复合过滤（按域名搜索 AND 按证书搜索，零延迟纯内存计算）
    public func applyCombinedDomainFilter(preserveLimit: Bool = false) {
        let domainQuery = domainSearchText.trimmingCharacters(in: .whitespaces).lowercased()
        let certFilter = domainCertFilter.trimmingCharacters(in: .whitespaces)
        
        var results = cachedAllDomains
        
        // 1. 域名搜索条件 (独立过滤)
        if !domainQuery.isEmpty {
            results = results.filter { row in
                row.hostname.lowercased().contains(domainQuery) ||
                "\(row.hostname):\(row.port)".lowercased().contains(domainQuery)
            }
        }
        
        // 2. 证书筛选条件 (独立过滤，与域名搜索是“并且”关系)
        if certFilter != "ALL" && !certFilter.isEmpty {
            results = results.filter { row in
                row.formattedCertSummary == certFilter ||
                (row.certificateSummary ?? "").localizedCaseInsensitiveContains(certFilter)
            }
        }
        
        self.domainRows = results
        if !preserveLimit {
            self.displayedDomainLimit = domainPageSize
        } else {
            self.displayedDomainLimit = max(domainPageSize, min(self.displayedDomainLimit, results.count))
        }
        self.displayedDomainRows = Array(results.prefix(self.displayedDomainLimit))
    }
    
    /// 触底自动追加下一页域名数据
    public func loadMoreDomainsIfNeeded() {
        guard displayedDomainLimit < domainRows.count else { return }
        displayedDomainLimit = min(displayedDomainLimit + domainPageSize, domainRows.count)
        displayedDomainRows = Array(domainRows.prefix(displayedDomainLimit))
    }
    
    /// 即时切换证书过滤项（独立触发，保持与当前域名搜索条件的“并且”组合）
    public func applyDomainCertFilter(_ filterValue: String) {
        self.domainCertFilter = filterValue
        applyCombinedDomainFilter()
    }
    
    /// 一键重置域名与证书全部筛选条件
    public func resetDomainFilters() {
        self.domainSearchText = ""
        self.domainCertFilter = "ALL"
        applyCombinedDomainFilter()
    }
    
    // 证书 Tab 状态
    @Published public var showAllCAs: Bool = true
    @Published public var caSearchText: String = "" // 按 CA 名称搜索
    @Published public var caStatusFilter: String = "ALL" // 按状态筛选：ALL / inspection / suspected / public
    @Published public var caClusters: [CADetail] = []
    @Published public var displayedCAClusters: [CADetail] = []
    @Published public var caStatusCounts: [String: Int] = [:]
    
    /// 同步复合过滤（按 CA 名称搜索 AND 按证书状态筛选，零延迟纯内存计算）
    public func applyCombinedCAFilter() {
        let nameQuery = caSearchText.trimmingCharacters(in: .whitespaces).lowercased()
        let statusFilter = caStatusFilter
        
        // 预先计算各类别的计数字典，供 popover O(1) 立即取用，消除视图帧重复遍历
        var counts: [String: Int] = ["ALL": caClusters.count]
        for ca in caClusters {
            counts[ca.identityKind, default: 0] += 1
        }
        self.caStatusCounts = counts
        
        var results = caClusters
        
        // 1. 仅按 CA 名称搜索 (独立过滤)
        if !nameQuery.isEmpty {
            results = results.filter { ca in
                ca.caName.lowercased().contains(nameQuery)
            }
        }
        
        // 2. 按状态搜索/筛选 (与 CA 名称搜索是“且”的关系)
        if statusFilter != "ALL" && !statusFilter.isEmpty {
            results = results.filter { ca in
                ca.identityKind == statusFilter
            }
        }
        
        // 3. 排序：先按 确认(inspection) -> 疑似(suspected) -> 公共(public)，内部再按关联域名数量降序
        func statusRank(_ kind: String) -> Int {
            switch kind {
            case "inspection": return 0
            case "suspected": return 1
            case "public": return 2
            default: return 3
            }
        }
        
        results.sort { (a, b) -> Bool in
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
        
        self.displayedCAClusters = results
    }

    /// 即时切换证书状态过滤项（零延迟，立即计算并展示）
    public func applyCAStatusFilter(_ filterValue: String) {
        self.caStatusFilter = filterValue
        applyCombinedCAFilter()
    }
    
    // 面板激活状态（感知窗口是否打开，面板关闭时仅运行轻量级菜单栏快照）
    @Published public var isPanelOpen: Bool = false {
        didSet {
            if isPanelOpen != oldValue {
                startPeriodicRefresh()
                if isPanelOpen {
                    refreshCurrentTabData()
                }
            }
        }
    }
    
    // 状态反馈与操作
    @Published public var configuration: Configuration = Configuration()
    @Published public var notificationToast: String? = nil
    @Published public var isProbing: Bool = false
    
    private var refreshTimer: Timer?
    private var cancellables = Set<AnyCancellable>()
    public let agent: MonitorAgent
    
    public init(agent: MonitorAgent = .shared) {
        self.agent = agent
        self.snapshot = agent.snapshotService.getOverviewSnapshot()
        
        // 订阅实时数据变动通知 (经 500ms 防抖合并高频网络并发，避免 UI 刷新风暴)
        NotificationCenter.default.publisher(for: .swgBarDataChanged)
            .receive(on: RunLoop.main)
            .debounce(for: .milliseconds(500), scheduler: RunLoop.main)
            .sink { [weak self] _ in
                guard let self = self else { return }
                if self.isPanelOpen {
                    self.refreshCurrentTabData()
                } else {
                    self.refreshMenuSnapshot()
                }
            }
            .store(in: &cancellables)
            
        Task {
            await agent.populateLiveSystemData()
            refreshCurrentTabData()
        }
        startPeriodicRefresh()
    }
    
    /// 自适应刷新定时器：面板关闭时 15 秒极低频快照；面板打开时 3 秒高频刷新
    private func startPeriodicRefresh() {
        refreshTimer?.invalidate()
        let interval: TimeInterval = isPanelOpen ? 3.0 : 15.0
        refreshTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                if self.isPanelOpen {
                    self.refreshCurrentTabData()
                } else {
                    self.refreshMenuSnapshot()
                }
            }
        }
    }
    
    /// 菜单栏极速快照刷新（<1ms，仅刷新顶栏 MITM XX% 与盾牌颜色，不加载大列表）
    public func refreshMenuSnapshot() {
        Task {
            self.snapshot = await agent.getOverviewSnapshot()
        }
    }
    
    /// 当前激活 Tab 的按需局部刷新
    public func refreshCurrentTabData() {
        Task {
            self.snapshot = await agent.getOverviewSnapshot()
            
            // 只有当面板处于展开状态时，才按需加载当前 Tab 所需的视图数据
            guard isPanelOpen else { return }
            
            switch selectedTab {
            case 0:
                // 总览 Tab：仅需要 snapshot，无需加载数千条域名明细
                break
                
            case 1:
                // 域名 Tab：按需加载全量域名至内存缓存，由客户端实现0延迟独立及复合过滤
                let allRows = await agent.listDomains(
                    search: "",
                    statusFilter: domainStatusFilter,
                    certFilter: "ALL",
                    sourceFilter: domainSourceFilter,
                    appFilter: domainAppFilter,
                    sort: domainSortOption
                )
                if self.cachedAllDomains != allRows {
                    self.cachedAllDomains = allRows
                    
                    var counts: [String: Int] = [:]
                    for r in allRows {
                        counts[r.formattedCertSummary, default: 0] += 1
                    }
                    let sortedOpts = counts.map { CertFilterOption(displayName: $0.key, filterValue: $0.key, count: $0.value) }
                        .sorted { $0.count > $1.count }
                    self.availableCertOptions = [CertFilterOption(displayName: "全部证书", filterValue: "ALL", count: allRows.count)] + sortedOpts
                    
                    // 统一应用复合过滤 (域名搜索 AND 证书过滤，保持当前已滚动的分页深度)
                    self.applyCombinedDomainFilter(preserveLimit: true)
                }
                
            case 2:
                // 证书 Tab：加载全量证书聚类（单页聚合，不再区分子 Tab）
                let clusters = await agent.listCAClusters(showAll: true)
                if self.caClusters != clusters || self.displayedCAClusters.isEmpty {
                    self.caClusters = clusters
                    self.applyCombinedCAFilter()
                }
                
            default:
                break
            }
        }
    }
    
    public func refreshAllData() {
        refreshCurrentTabData()
    }
    
    public func getDomainDetail(targetId: String) -> DomainDetail {
        return agent.snapshotService.getDomainDetail(targetId: targetId)
    }
    
    /// 跳转到指定证书的详情页：先确保证书列表已加载，避免因数据未就绪而回退到首条证书
    public func openCertificateDetail(clusterId: String) {
        selectedDomainId = nil
        selectedTab = 2
        if caClusters.contains(where: { $0.clusterId == clusterId }) {
            selectedCAClusterId = clusterId
            return
        }
        Task {
            let clusters = await agent.listCAClusters(showAll: true)
            await MainActor.run {
                self.caClusters = clusters
                self.applyCombinedCAFilter()
                self.selectedCAClusterId = clusterId
            }
        }
    }

    public func getAffectedDomains(for ca: CADetail) -> [String] {
        return agent.snapshotService.listHostnamesForCA(clusterId: ca.clusterId, spki: ca.spkiSha256, caName: ca.caName)
    }
    
    // MARK: - 交互操作映射 (G/O/D/DD/C/CD/H/S)
    
    // G04/G05/O10: 暂停与恢复监测
    public func togglePause() {
        let newState: CollectorState = (snapshot.collectorState == .running) ? .paused : .running
        self.snapshot.collectorState = newState
        NotificationCenter.default.post(name: .swgBarDataChanged, object: nil)
        Task {
            await agent.setCollectorState(newState)
            let updated = await agent.getOverviewSnapshot()
            await MainActor.run {
                self.snapshot = updated
                self.refreshCurrentTabData()
                NotificationCenter.default.post(name: .swgBarDataChanged, object: nil)
            }
        }
    }
    
    // 清空所有历史探测数据
    public func clearAllHistoricalData() {
        Task {
            NativeTrustEvaluator.shared.invalidateCACache()
            await agent.clearAllHistoricalData()
            refreshAllData()
            showToast("已清空所有历史探测数据")
        }
    }
    
    // CD09: 删除规则
    public func deleteRule(ruleId: String) {
        Task {
            try? await agent.deleteRule(ruleId: ruleId)
            refreshAllData()
            showToast("规则已删除")
        }
    }
    
    public func showToast(_ message: String) {
        withAnimation {
            self.notificationToast = message
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            withAnimation {
                if self.notificationToast == message {
                    self.notificationToast = nil
                }
            }
        }
    }
}

public struct CertFilterOption: Identifiable, Hashable, Sendable {
    public var id: String { filterValue }
    public let displayName: String
    public let filterValue: String
    public let count: Int
    
    public init(displayName: String, filterValue: String, count: Int) {
        self.displayName = displayName
        self.filterValue = filterValue
        self.count = count
    }
}

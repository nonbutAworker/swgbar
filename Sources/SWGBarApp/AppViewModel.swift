//
// SWGBar / macOS menu bar TLS inspection detector
// Application view model (AppViewModel.swift)
// Consume versioned snapshots and coordinate inline navigation and tab interactions.
//

import SwiftUI
import Combine
import SWGBarContracts
import SWGBarAgent
import SWGBarStorage

@MainActor
public final class AppViewModel: ObservableObject {
    // MARK: - Navigation and state
    @Published public var selectedTab: Int = 0 // 0: Overview, 1: Domains, 2: Certificates

    @Published public var showingOnboarding: Bool = false // Initial permission flow
    
    // Inline navigation without opening another window
    @Published public var selectedDomainId: String? = nil // Selected domain details (DD01-DD11)
    @Published public var selectedCAClusterId: String? = nil // Selected CA details (CD01-CD10)
    
    // MARK: - Overview snapshot and state
    @Published public var snapshot: OverviewSnapshot
    
    // Domains tab state
    @Published public var domainSearchText: String = "" // D01
    @Published public var domainStatusFilter: String = "ALL" // D02
    @Published public var domainCertFilter: String = "ALL" // Certificate filter
    @Published public var availableCertOptions: [CertFilterOption] = []
    @Published public var domainSourceFilter: String = "ALL"
    @Published public var domainAppFilter: String = "ALL"
    @Published public var domainSortOption: String = "REQUEST_COUNT" // D03
    @Published public var domainRows: [DomainRow] = []
    private var cachedAllDomains: [DomainRow] = []
    
    // Pagination keeps large domain lists responsive during scrolling and search.
    public let domainPageSize: Int = 50
    @Published public var displayedDomainLimit: Int = 50
    @Published public var displayedDomainRows: [DomainRow] = []
    
    /// Combine hostname search and certificate filtering synchronously in memory.
    public func applyCombinedDomainFilter(preserveLimit: Bool = false) {
        let domainQuery = domainSearchText.trimmingCharacters(in: .whitespaces).lowercased()
        let certFilter = domainCertFilter.trimmingCharacters(in: .whitespaces)
        
        var results = cachedAllDomains
        
        // 1. Apply the hostname search independently.
        if !domainQuery.isEmpty {
            results = results.filter { row in
                row.hostname.lowercased().contains(domainQuery) ||
                "\(row.hostname):\(row.port)".lowercased().contains(domainQuery)
            }
        }
        
        // 2. Combine the certificate filter with the hostname search using AND.
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
    
    /// Append the next page when scrolling reaches the end.
    public func loadMoreDomainsIfNeeded() {
        guard displayedDomainLimit < domainRows.count else { return }
        displayedDomainLimit = min(displayedDomainLimit + domainPageSize, domainRows.count)
        displayedDomainRows = Array(domainRows.prefix(displayedDomainLimit))
    }
    
    /// Apply a certificate filter immediately while preserving the hostname search.
    public func applyDomainCertFilter(_ filterValue: String) {
        self.domainCertFilter = filterValue
        applyCombinedDomainFilter()
    }
    
    /// Reset hostname and certificate filters together.
    public func resetDomainFilters() {
        self.domainSearchText = ""
        self.domainCertFilter = "ALL"
        applyCombinedDomainFilter()
    }
    
    // Certificates tab state
    @Published public var showAllCAs: Bool = true
    @Published public var caSearchText: String = "" // Search by CA name
    @Published public var caStatusFilter: String = "ALL" // Filter by status: ALL / inspection / suspected / public
    @Published public var caClusters: [CADetail] = []
    @Published public var displayedCAClusters: [CADetail] = []
    @Published public var caStatusCounts: [String: Int] = [:]
    
    /// Combine CA name search and status filtering synchronously in memory.
    public func applyCombinedCAFilter() {
        let nameQuery = caSearchText.trimmingCharacters(in: .whitespaces).lowercased()
        let statusFilter = caStatusFilter
        
        // Precompute counts by status so the popover can read them without repeatedly traversing the list.
        var counts: [String: Int] = ["ALL": caClusters.count]
        for ca in caClusters {
            counts[ca.identityKind, default: 0] += 1
        }
        self.caStatusCounts = counts
        
        var results = caClusters
        
        // 1. Search by CA name independently.
        if !nameQuery.isEmpty {
            results = results.filter { ca in
                ca.caName.lowercased().contains(nameQuery)
            }
        }
        
        // 2. Combine the status filter with the CA name search using AND.
        if statusFilter != "ALL" && !statusFilter.isEmpty {
            results = results.filter { ca in
                ca.identityKind == statusFilter
            }
        }
        
        // 3. Sort by inspection, suspected, then public status; break ties by descending domain count.
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

    /// Apply the certificate status filter and refresh its results immediately.
    public func applyCAStatusFilter(_ filterValue: String) {
        self.caStatusFilter = filterValue
        applyCombinedCAFilter()
    }
    
    // Track panel visibility; use lightweight menu bar snapshots when closed.
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
    
    // Operation feedback and notifications
    @Published public var configuration: Configuration = Configuration()
    @Published public var notificationToast: String? = nil
    @Published public var isProbing: Bool = false
    
    private var refreshTimer: Timer?
    private var cancellables = Set<AnyCancellable>()
    public let agent: MonitorAgent
    
    public init(agent: MonitorAgent = .shared) {
        self.agent = agent
        self.snapshot = agent.snapshotService.getOverviewSnapshot()
        
        // Debounce data-change notifications for 500 ms to coalesce concurrent network updates.
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
    
    /// Refresh every 15 seconds while closed, or every three seconds while the panel is open.
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
    
    /// Refresh only the menu bar percentage and status color without loading large lists.
    public func refreshMenuSnapshot() {
        Task {
            self.snapshot = await agent.getOverviewSnapshot()
        }
    }
    
    /// Refresh data for the active tab on demand.
    public func refreshCurrentTabData() {
        Task {
            self.snapshot = await agent.getOverviewSnapshot()
            
            // Load tab-specific data only while the panel is open.
            guard isPanelOpen else { return }
            
            switch selectedTab {
            case 0:
                // Overview needs only the snapshot, not the full domain list.
                break
                
            case 1:
                // Cache domain rows in memory for independent and combined filtering.
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
                    self.availableCertOptions = [CertFilterOption(displayName: "All certificates", filterValue: "ALL", count: allRows.count)] + sortedOpts
                    
                    // Combine hostname and certificate filters while preserving the current pagination depth.
                    self.applyCombinedDomainFilter(preserveLimit: true)
                }
                
            case 2:
                // Load the complete certificate cluster list for the certificates tab.
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
    
    /// Load the certificate list before navigating to a cluster, avoiding a fallback to the first row.
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
    
    // MARK: - UI operations (G/O/D/DD/C/CD/H/S)
    
    // G04/G05/O10: Pause and resume monitoring
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
    
    // Clear all historical probe data.
    public func clearAllHistoricalData() {
        Task {
            NativeTrustEvaluator.shared.invalidateCACache()
            await agent.clearAllHistoricalData()
            refreshAllData()
            showToast("All historical probe data has been cleared")
        }
    }
    
    // CD09: Delete a rule.
    public func deleteRule(ruleId: String) {
        Task {
            try? await agent.deleteRule(ruleId: ruleId)
            refreshAllData()
            showToast("Rule deleted")
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

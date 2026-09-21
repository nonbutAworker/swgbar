//
// SWGBar / macOS menu bar TLS inspection detector
// Tab 2: Domain list (DomainsTabView.swift)
// Domain list, combined filters, and inline details.
//

import SwiftUI
import SWGBarContracts

public struct DomainsTabView: View {
    // 订阅语言变更，切换后本视图立即重绘
    @ObservedObject private var l10n = LocalizationManager.shared
    @ObservedObject var vm: AppViewModel
    
    // Certificate filter popover state
    @State private var showingCertPopover: Bool = false
    @State private var certSearchText: String = ""
    @State private var hoveredCertOption: String? = nil
    @State private var hoveredDomainId: String? = nil
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        Group {
            if let domainId = vm.selectedDomainId {
                DomainDetailView(vm: vm, targetId: domainId)
            } else {
                domainsListContent
            }
        }
        .onAppear {
            vm.refreshAllData()
        }
        .onChange(of: vm.selectedTab) { _, _ in
            showingCertPopover = false
        }
    }
    
    private var domainsListContent: some View {
        ZStack(alignment: .top) {
            VStack(spacing: 8) {
                // Place hostname and certificate searches side by side and combine them using AND.
                HStack(spacing: 8) {
                    domainSearchField
                    certFilterDropdown
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
            
            // List header: match count and reset action
            HStack(spacing: 6) {
                Circle()
                    .fill(Color.green)
                    .frame(width: 6, height: 6)
                
                let isFiltered = (vm.domainCertFilter != "ALL" || !vm.domainSearchText.isEmpty)
                Text(isFiltered ? L(.matchingDomainsFormat, vm.domainRows.count) : L(.outboundDomainsCapturedFormat, vm.domainRows.count))
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
                
                Spacer()
                
                if isFiltered {
                    Button(action: {
                        vm.resetDomainFilters()
                    }) {
                        Text(L(.clearAllFilters))
                            .font(.system(size: 10))
                            .foregroundColor(.accentColor)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 16)
            
            // Domain list
            ScrollView(.vertical, showsIndicators: true) {
                if vm.domainRows.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .font(.system(size: 36))
                            .foregroundColor(.blue.opacity(0.8))
                            .padding(.top, 40)
                        Text(L(.discoveringOutboundConnections))
                            .font(UITheme.bodyBoldFont)
                            .foregroundColor(.primary)
                        Text(L(.swgbarIntro))
                            .font(UITheme.subFont)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, 20)
                } else {
                    LazyVStack(spacing: 6) {
                        ForEach(vm.displayedDomainRows) { row in
                            domainRowView(row: row)
                                .onAppear {
                                    if row.id == vm.displayedDomainRows.last?.id {
                                        vm.loadMoreDomainsIfNeeded()
                                    }
                                }
                        }
                        
                        // Load the next page when the end-of-list indicator appears.
                        if vm.displayedDomainRows.count < vm.domainRows.count {
                            HStack(spacing: 6) {
                                ProgressView()
                                    .controlSize(.small)
                                Text(L(.scrollForMoreFormat, vm.displayedDomainRows.count, vm.domainRows.count))
                                    .font(UITheme.subFont)
                                    .foregroundColor(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .onAppear {
                                vm.loadMoreDomainsIfNeeded()
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                }
            }
        }
            
            // Keep the certificate filter popover inside the 360-point panel width.
            if showingCertPopover {
                // Close the popover when its background is clicked.
                Color.black.opacity(0.001)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        withAnimation(.easeInOut(duration: 0.16)) {
                            showingCertPopover = false
                            hoveredCertOption = nil
                        }
                    }
                
                certPickerPopoverView
                    .padding(.top, 44)
                    .padding(.horizontal, 16)
                    .transition(.asymmetric(
                        insertion: .opacity.combined(with: .scale(scale: 0.98, anchor: .top)),
                        removal: .opacity
                    ))
                    .zIndex(100)
            }
        }
    }
    
    // MARK: - Domain row (D04)
    private func domainRowView(row: DomainRow) -> some View {
        let isHovered = (hoveredDomainId == row.targetId)
        return VStack(alignment: .leading, spacing: 5) {
            // First row: hostname and request count
            HStack {
                Text(row.port == 443 ? row.hostname : "\(row.hostname):\(row.port)")
                    .font(UITheme.bodyBoldFont)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                
                Spacer()
                
                if row.requestCount > 0 {
                    Text(L(.requestsCountFormat, row.requestCount))
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundColor(.secondary)
                        .padding(.trailing, 2)
                }
                
                Image(systemName: "chevron.right")
                    .font(.system(size: 10))
                    .foregroundColor(isHovered ? .accentColor : .secondary.opacity(0.5))
            }
            
            // Second row: certificate summary and status badge
            HStack(spacing: 6) {
                Text(row.certificateSummary ?? L(.awaitingProbe))
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                if let identityKind = row.certificateIdentityKind {
                    Text(UITheme.badgeText(for: identityKind))
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(UITheme.color(for: identityKind))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .liquidGlassPill(tintColor: UITheme.color(for: identityKind))
                }
                
                Spacer()
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .liquidGlassCard(cornerRadius: 10, isHovered: isHovered)
        .contentShape(Rectangle())
        .onHover { hovering in
            hoveredDomainId = hovering ? row.targetId : nil
        }
        .onTapGesture {
            vm.selectedDomainId = row.targetId
        }
        .accessibilityIdentifier("D04_domain_row_\(row.targetId)")
    }
    
    // MARK: - Hostname search
    private var domainSearchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
            
            TextField(L(.searchDomains), text: $vm.domainSearchText)
                .textFieldStyle(.plain)
                .font(UITheme.subFont)
                .accessibilityIdentifier("D01_search_field")
                .onChange(of: vm.domainSearchText) { _, _ in
                    vm.applyCombinedDomainFilter()
                }
            
            if !vm.domainSearchText.isEmpty {
                Button(action: {
                    vm.domainSearchText = ""
                    vm.applyCombinedDomainFilter()
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity)
        .liquidGlassInput(isFocusedOrActive: !vm.domainSearchText.isEmpty, cornerRadius: 8)
    }
    
    // MARK: - Certificate search and filter
    private var certFilterDropdown: some View {
        HStack(spacing: 4) {
            Button(action: {
                certSearchText = ""
                withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                    showingCertPopover.toggle()
                }
            }) {
                HStack(spacing: 5) {
                    Image(systemName: "doc.plaintext")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(vm.domainCertFilter == "ALL" ? .secondary : .accentColor)
                    
                    Text(vm.domainCertFilter == "ALL" ? L(.filterCertificates) : certificateFilterLabel(vm.domainCertFilter))
                        .font(UITheme.subFont)
                        .foregroundColor(vm.domainCertFilter == "ALL" ? .secondary : .primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    Image(systemName: showingCertPopover ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundColor(.secondary)
                }
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("D02_cert_filter_button")
            
            if vm.domainCertFilter != "ALL" {
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vm.applyDomainCertFilter("ALL")
                        showingCertPopover = false
                    }
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help(L(.clearCertificateFilter))
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity)
        .liquidGlassInput(isFocusedOrActive: vm.domainCertFilter != "ALL" || showingCertPopover, cornerRadius: 8)
    }
    
    private var filteredCertOptions: [CertFilterOption] {
        let query = certSearchText.trimmingCharacters(in: .whitespaces).lowercased()
        if query.isEmpty {
            return vm.availableCertOptions
        }
        return vm.availableCertOptions.filter { opt in
            opt.filterValue == "ALL" || certificateFilterLabel(opt.filterValue).lowercased().contains(query)
        }
    }
    
    // Keep filter values stable; resolve display-only labels at render time.
    private func certificateFilterLabel(_ value: String) -> String {
        if value == "ALL" { return L(.allCertificatesFilter) }
        if value == "Awaiting probe" { return L(.awaitingProbe) }
        return value
    }

    private func formatCount(_ count: Int) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return formatter.string(from: NSNumber(value: count)) ?? "\(count)"
    }
    
    private var certPickerPopoverView: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Search within the certificate choices.
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)
                
                TextField(L(.searchCertificates), text: $certSearchText)
                    .textFieldStyle(.plain)
                    .font(UITheme.subFont)
                    .accessibilityIdentifier("D02_cert_search_field")
                
                if !certSearchText.isEmpty {
                    Button(action: {
                        certSearchText = ""
                    }) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .liquidGlassInput(isFocusedOrActive: !certSearchText.isEmpty, cornerRadius: 6)
            
            Divider()
                .padding(.vertical, 2)
            
            // Show certificate choices with their associated domain counts.
            ScrollView(.vertical, showsIndicators: true) {
                if filteredCertOptions.isEmpty {
                    Text(L(.noMatchingCertificates))
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                        .padding(.vertical, 20)
                        .frame(maxWidth: .infinity)
                } else {
                    LazyVStack(alignment: .leading, spacing: 3) {
                        ForEach(filteredCertOptions) { opt in
                            certOptionRow(opt: opt)
                        }
                    }
                }
            }
            .frame(maxHeight: 240)
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(NSColor.windowBackgroundColor).opacity(0.92))
                .background(.ultraThickMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        )
        .overlay(UITheme.glassBorderStroke(cornerRadius: 12))
        .shadow(color: Color.black.opacity(0.28), radius: 18, x: 0, y: 10)
    }
    
    private func certOptionRow(opt: CertFilterOption) -> some View {
        let isSelected = (vm.domainCertFilter == opt.filterValue)
        let isHovered = (hoveredCertOption == opt.filterValue)
        
        return Button(action: {
            withAnimation(.easeInOut(duration: 0.16)) {
                vm.applyDomainCertFilter(opt.filterValue)
                showingCertPopover = false
                hoveredCertOption = nil
            }
        }) {
            HStack(spacing: 8) {
                if opt.filterValue == "ALL" {
                    Image(systemName: "line.3.horizontal.decrease.circle")
                        .font(.system(size: 10))
                        .foregroundColor(isSelected ? .accentColor : .secondary)
                } else {
                    Image(systemName: "doc.plaintext")
                        .font(.system(size: 10))
                        .foregroundColor(isSelected ? .accentColor : .secondary)
                }
                
                Text(certificateFilterLabel(opt.filterValue))
                    .font(UITheme.subFont)
                    .foregroundColor(isSelected ? .accentColor : .primary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                
                Spacer()
                
                Text(formatCount(opt.count))
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(isSelected ? .accentColor : .secondary)
                
                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.accentColor)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(
            RoundedRectangle(cornerRadius: 5)
                .fill(isSelected ? Color.accentColor.opacity(isHovered ? 0.16 : 0.12) : (isHovered ? Color.secondary.opacity(0.12) : Color.clear))
        )
        .onHover { hovering in
            hoveredCertOption = hovering ? opt.filterValue : nil
        }
        .accessibilityIdentifier("D02_cert_opt_\(opt.filterValue)")
    }
}


//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// Tab 3：证书与 CA 聚类 (CertificatesTabView.swift)
// 遵循技术方案 v1.1 第 20 章与图 20-1 视觉设计
//

import SwiftUI
import SWGBarContracts

public struct CertificatesTabView: View {
    @ObservedObject var vm: AppViewModel
    
    @State private var showingStatusPopover: Bool = false
    @State private var hoveredOptionId: String? = nil
    @State private var hoveredCAId: String? = nil
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        Group {
            if let caId = vm.selectedCAClusterId {
                CADetailView(vm: vm, clusterId: caId)
            } else {
                certificatesListContent
            }
        }
        .onAppear {
            vm.refreshAllData()
        }
        .onChange(of: vm.selectedTab) { _, _ in
            showingStatusPopover = false
        }
    }
    
    private var certificatesListContent: some View {
        ZStack(alignment: .top) {
            VStack(spacing: 8) {
                // 同级别、并列同行、独立搜索的双搜索栏（按 CA 名称搜索 AND 按状态筛选）
                HStack(spacing: 8) {
                    caSearchField
                    statusFilterDropdown
                }
                .padding(.horizontal, 16)
                .padding(.top, 10)
            
            // 状态栏：匹配数量与重置操作
            HStack(spacing: 6) {
                Circle()
                    .fill(Color.green)
                    .frame(width: 6, height: 6)
                
                let isFiltered = (vm.caStatusFilter != "ALL" || !vm.caSearchText.isEmpty)
                Text(isFiltered ? "匹配 \(vm.displayedCAClusters.count) 个证书簇" : "已识别 \(vm.displayedCAClusters.count) 个证书簇")
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
                
                Spacer()
            }
            .padding(.horizontal, 16)
            
            // CA 簇单页统一列表
            ScrollView(.vertical, showsIndicators: true) {
                if vm.displayedCAClusters.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.system(size: 32))
                            .foregroundColor(.secondary.opacity(0.7))
                            .padding(.top, 40)
                        Text("无匹配证书簇")
                            .font(UITheme.bodyBoldFont)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    LazyVStack(spacing: 6) {
                        ForEach(vm.displayedCAClusters, id: \.clusterId) { ca in
                            caRowView(ca: ca)
                        }
                    }
                    .padding(.horizontal, 16)
                }
            }
        }
            
            // 浮动在列表上方的状态筛选下拉卡片（严格受限于窗口内部，靠右对齐，绝不超出页面边缘）
            if showingStatusPopover {
                Color.black.opacity(0.001)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        withAnimation(.easeInOut(duration: 0.16)) {
                            showingStatusPopover = false
                            hoveredOptionId = nil
                        }
                    }
                
                HStack {
                    Spacer()
                    statusPickerPopoverView
                        .frame(width: 200)
                        .padding(.trailing, 16)
                }
                .padding(.top, 44)
                .transition(.asymmetric(
                    insertion: .opacity.combined(with: .scale(scale: 0.98, anchor: .topTrailing)),
                    removal: .opacity
                ))
                .zIndex(100)
            }
        }
    }
    
    // MARK: - 按证书名称搜索框（与状态筛选同级别并列同行）
    private var caSearchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
            
            TextField("按证书名称搜索...", text: $vm.caSearchText)
                .textFieldStyle(.plain)
                .font(UITheme.subFont)
                .accessibilityIdentifier("C02_search_ca")
                .onChange(of: vm.caSearchText) { _, _ in
                    vm.applyCombinedCAFilter()
                }
            
            if !vm.caSearchText.isEmpty {
                Button(action: {
                    vm.caSearchText = ""
                    vm.applyCombinedCAFilter()
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 8)
        .frame(maxWidth: .infinity)
        .frame(height: 28)
        .liquidGlassInput(isFocusedOrActive: !vm.caSearchText.isEmpty, cornerRadius: 8)
    }
    
    // MARK: - 按状态筛选框（与证书名称搜索同级别并列同行）
    private var statusFilterDropdown: some View {
        HStack(spacing: 4) {
            Button(action: {
                withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                    showingStatusPopover.toggle()
                }
            }) {
                HStack(spacing: 5) {
                    if vm.caStatusFilter == "ALL" {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.secondary)
                    } else {
                        Circle()
                            .fill(UITheme.color(for: vm.caStatusFilter))
                            .frame(width: 8, height: 8)
                    }
                    
                    Text(statusFilterDisplayText)
                        .font(UITheme.subFont)
                        .foregroundColor(vm.caStatusFilter == "ALL" ? .secondary : .primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    Image(systemName: showingStatusPopover ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundColor(.secondary)
                }
                .frame(maxHeight: .infinity)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("C03_status_filter_button")
            
            if vm.caStatusFilter != "ALL" {
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        vm.applyCAStatusFilter("ALL")
                        showingStatusPopover = false
                    }
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("清除状态过滤")
            }
        }
        .padding(.horizontal, 8)
        .frame(maxWidth: .infinity)
        .frame(height: 28)
        .liquidGlassInput(isFocusedOrActive: vm.caStatusFilter != "ALL" || showingStatusPopover, cornerRadius: 8)
    }
    
    private var statusFilterDisplayText: String {
        switch vm.caStatusFilter {
        case "inspection": return "确认"
        case "suspected": return "疑似"
        case "public": return "公共"
        default: return "按证书状态筛选..."
        }
    }
    
    private struct StatusOption: Identifiable {
        let id: String
        let name: String
        let kind: String
    }
    
    private let statusOptions: [StatusOption] = [
        StatusOption(id: "ALL", name: "全部状态", kind: "ALL"),
        StatusOption(id: "inspection", name: "确认", kind: "inspection"),
        StatusOption(id: "suspected", name: "疑似", kind: "suspected"),
        StatusOption(id: "public", name: "公共", kind: "public")
    ]
    
    private var statusPickerPopoverView: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("按证书状态筛选")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            
            Divider()
                .padding(.bottom, 2)
            
            ForEach(statusOptions) { opt in
                let isSelected = (vm.caStatusFilter == opt.id)
                let isHovered = (hoveredOptionId == opt.id)
                
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.16)) {
                        vm.applyCAStatusFilter(opt.id)
                        showingStatusPopover = false
                        hoveredOptionId = nil
                    }
                }) {
                    HStack(spacing: 8) {
                        if opt.kind != "ALL" {
                            Circle()
                                .fill(UITheme.color(for: opt.kind))
                                .frame(width: 8, height: 8)
                        } else {
                            Image(systemName: "line.3.horizontal.decrease.circle")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }
                        
                        Text(opt.name)
                            .font(UITheme.subFont)
                            .foregroundColor(isSelected ? .accentColor : .primary)
                        
                        Spacer()
                        
                        Text("\(vm.caStatusCounts[opt.kind, default: 0])")
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
                        .fill(isSelected ? Color.accentColor.opacity(0.12) : (isHovered ? Color.secondary.opacity(0.12) : Color.clear))
                )
                .onHover { hovering in
                    hoveredOptionId = hovering ? opt.id : nil
                }
                .accessibilityIdentifier("C03_status_opt_\(opt.id)")
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(NSColor.windowBackgroundColor).opacity(0.92))
                .background(.ultraThickMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        )
        .overlay(UITheme.glassBorderStroke(cornerRadius: 12))
        .shadow(color: Color.black.opacity(0.28), radius: 18, x: 0, y: 10)
    }
    
    // MARK: - 证书簇项 (C04: Liquid Glass 晶莹交互行卡片)
    private func caRowView(ca: CADetail) -> some View {
        let isHovered = (hoveredCAId == ca.clusterId)
        return HStack(spacing: 8) {
            Image(systemName: "doc.plaintext")
                .font(.system(size: 14))
                .foregroundColor(isHovered ? .accentColor : .secondary)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(ca.caName)
                    .font(UITheme.bodyBoldFont)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                
                Text(String(ca.spkiSha256.prefix(11)))
                    .font(UITheme.fingerprintFont)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text("\(ca.affectedDomainsCount) 个域名")
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
            
            Text(UITheme.badgeText(for: ca.identityKind))
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(UITheme.color(for: ca.identityKind))
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .liquidGlassPill(tintColor: UITheme.color(for: ca.identityKind))
            
            Image(systemName: "chevron.right")
                .font(.system(size: 10))
                .foregroundColor(isHovered ? .accentColor : .secondary)
        }
        .padding(10)
        .liquidGlassCard(cornerRadius: 10, isHovered: isHovered)
        .contentShape(Rectangle())
        .onHover { hovering in
            hoveredCAId = hovering ? ca.clusterId : nil
        }
        .onTapGesture {
            vm.selectedCAClusterId = ca.clusterId
        }
        .accessibilityIdentifier("C04_ca_row_\(ca.clusterId)")
    }
}

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// Tab 1：总览 (OverviewTabView.swift)
// 遵循技术方案 v1.1 第 17 章与图 17-1 视觉设计
//

import SwiftUI
import SWGBarContracts

public struct OverviewTabView: View {
    @ObservedObject var vm: AppViewModel
    @State private var hoveredClusterId: String? = nil
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        GeometryReader { proxy in
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: 12) {
                    // 主指标占比卡片 (O04) - 占据上半部剩余空间
                    mainMetricCard
                    
                    // 证书列表 (O07) - 保持在底部
                    topCAsSection
                }
                .padding(.horizontal, 14)
                .padding(.top, 8)
                .padding(.bottom, 10)
                .frame(minHeight: proxy.size.height)
            }
        }
        .onAppear {
            vm.refreshAllData()
        }
    }
    
    // MARK: - 主卡片 (O04: Liquid Glass 晶莹悬浮卡片)
    private var mainMetricCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("域名劫持占比")
                    .font(UITheme.bodyFont)
                    .foregroundColor(.secondary)
                
                Spacer()
                
                if vm.snapshot.userAssertedConfirmed > 0 {
                    Text("含用户标注")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.orange)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2.5)
                        .liquidGlassPill(tintColor: .orange)
                }
            }
            
            Spacer(minLength: 6)
            
            HStack(alignment: .firstTextBaseline) {
                Text(vm.snapshot.mitmPercentageString)
                    .font(UITheme.heroPercentageFont)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
                    .accessibilityIdentifier("O04_main_percentage")
            }
            
            Spacer(minLength: 8)
            
            let total = vm.snapshot.mitmTotalCount
            HStack(spacing: 10) {
                statusMetricItem(color: UITheme.colorConfirmed, label: "确认", count: vm.snapshot.counts.confirmed, total: total)
                    .accessibilityIdentifier("O04_metric_confirmed")
                statusMetricItem(color: UITheme.colorSuspected, label: "疑似", count: vm.snapshot.counts.suspected, total: total)
                    .accessibilityIdentifier("O04_metric_suspected")
                statusMetricItem(color: UITheme.colorPublicPath, label: "公共", count: vm.snapshot.counts.publicPath, total: total)
                    .accessibilityIdentifier("O04_metric_public")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(maxHeight: .infinity)
        .liquidGlassCard(cornerRadius: 14)
    }
    
    // MARK: - 证书 (O07: Liquid Glass 容器)
    private var topCAsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("中间人证书")
                    .font(UITheme.bodyBoldFont)
                Spacer()
                Button("查看全部 >") {
                    vm.selectedTab = 2 // 跳转至证书 Tab
                }
                .font(UITheme.subFont)
                .foregroundColor(.accentColor)
                .buttonStyle(.plain)
            }
            
            VStack(spacing: 3) {
                if vm.snapshot.topClusters.isEmpty {
                    Text("尚未发现拦截或自签名证书")
                        .font(UITheme.subFont)
                        .foregroundColor(.secondary)
                        .padding(.vertical, 8)
                } else {
                    ForEach(vm.snapshot.topClusters.prefix(5)) { cluster in
                        let isHovered = (hoveredClusterId == cluster.clusterId)
                        HStack {
                            Image(systemName: "doc.plaintext")
                                .font(.system(size: 12))
                                .foregroundColor(isHovered ? .accentColor : .secondary)
                            
                            Text(cluster.caName)
                                .font(.system(size: 12))
                                .lineLimit(1)
                            
                            Spacer()
                            
                            Text("\(cluster.affectedDomainsCount) 域名")
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                            
                            Text(UITheme.badgeText(for: cluster.identityKind))
                                .font(.system(size: 10, weight: .medium))
                                .foregroundColor(UITheme.color(for: cluster.identityKind))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .liquidGlassPill(tintColor: UITheme.color(for: cluster.identityKind))
                        }
                        .padding(.horizontal, 6)
                        .padding(.vertical, 4)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(isHovered ? Color(NSColor.controlBackgroundColor).opacity(0.5) : Color.clear)
                        )
                        .contentShape(Rectangle())
                        .onHover { hovering in
                            hoveredClusterId = hovering ? cluster.clusterId : nil
                        }
                        .onTapGesture {
                            vm.selectedTab = 2
                            vm.selectedCAClusterId = cluster.clusterId
                        }
                        .accessibilityIdentifier("O07_ca_\(cluster.clusterId)")
                    }
                }
            }
        }
        .padding(12)
        .liquidGlassCard(cornerRadius: 14)
    }
    
    // MARK: - 状态数量指标项
    private func statusMetricItem(color: Color, label: String, count: Int64, total: Int64) -> some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
                .shadow(color: color.opacity(0.5), radius: 2, x: 0, y: 0)
            Text("\(label) \(count) / \(total)")
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 5)
        .padding(.vertical, 2.5)
        .background(
            RoundedRectangle(cornerRadius: 5, style: .continuous)
                .fill(Color(NSColor.controlBackgroundColor).opacity(0.35))
        )
    }
}


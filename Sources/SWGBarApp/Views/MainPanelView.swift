//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 菜单栏紧凑面板主容器 (MainPanelView.swift)
// 遵循技术方案 v1.1 第 15 章与图 15-1：420×640 pt，五 Tab，无第二独立窗口
//

import SwiftUI
import SWGBarContracts

public struct MainPanelView: View {
    @StateObject var vm: AppViewModel
    
    public init(viewModel: AppViewModel? = nil) {
        _vm = StateObject(wrappedValue: viewModel ?? AppViewModel())
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            // 吐司提示 (如操作反馈)
            if let toast = vm.notificationToast {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text(toast)
                        .font(UITheme.subFont)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 6)
                .background(Color.accentColor.opacity(0.12))
                .transition(.move(edge: .top).combined(with: .opacity))
            }
            
            // 2. 三 Tab 选择栏 (32 pt, G03)
            tabBar
            
            Divider()
            
            // 3. 主内容区 (各 Tab 内容常驻，利用 LazyVStack 消除反复销毁创建的重绘卡顿)
            ZStack {
                if vm.showingOnboarding {
                    OnboardingView(vm: vm)
                } else {
                    OverviewTabView(vm: vm)
                        .opacity(vm.selectedTab == 0 ? 1 : 0)
                        .allowsHitTesting(vm.selectedTab == 0)
                    
                    DomainsTabView(vm: vm)
                        .opacity(vm.selectedTab == 1 ? 1 : 0)
                        .allowsHitTesting(vm.selectedTab == 1)
                    
                    CertificatesTabView(vm: vm)
                        .opacity(vm.selectedTab == 2 ? 1 : 0)
                        .allowsHitTesting(vm.selectedTab == 2)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            
            Divider()
            
            // 4. 固定底栏 (28 pt)
            FooterView(vm: vm)
        }
        .frame(width: UITheme.panelWidth, height: UITheme.panelStandardHeight)
        .background(
            ZStack {
                // 1. 系统底层超清超细毛玻璃材质（半透穿透桌面）
                Rectangle()
                    .fill(.ultraThinMaterial)
                
                // 2. 弱微光环境漫反射渐变，营造晶莹深度
                LinearGradient(
                    colors: [
                        Color.white.opacity(0.06),
                        Color.clear,
                        Color.black.opacity(0.04)
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
        )
    }
    
    // MARK: - 三 Tab 栏 (G03, 快捷键 Cmd+1...3, Liquid Glass 浮动晶莹胶囊切换器)
    private var tabBar: some View {
        HStack(spacing: 4) {
            tabButton(title: "总览", icon: "house", index: 0)
            tabButton(title: "域名", icon: "globe", index: 1)
            tabButton(title: "证书", icon: "doc.plaintext", index: 2)
        }
        .padding(3)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(NSColor.controlBackgroundColor).opacity(0.4))
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(
                            LinearGradient(
                                colors: [Color.white.opacity(0.25), Color.white.opacity(0.05)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 0.6
                        )
                )
        )
        .padding(.horizontal, 14)
        .padding(.vertical, 4)
        .accessibilityIdentifier("G03_tab_bar")
    }
    
    private func tabButton(title: String, icon: String, index: Int) -> some View {
        let isSelected = (vm.selectedTab == index && !vm.showingOnboarding)
        return Button(action: {
            vm.showingOnboarding = false
            vm.selectedTab = index
            vm.refreshCurrentTabData()
        }) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 11, weight: isSelected ? .semibold : .medium))
                Text(title)
                    .font(UITheme.subBoldFont)
            }
            .foregroundColor(isSelected ? .primary : .secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .frame(maxWidth: .infinity)
            .background(
                ZStack {
                    if isSelected {
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(Color(NSColor.controlBackgroundColor).opacity(0.85))
                            .shadow(color: Color.black.opacity(0.08), radius: 3, x: 0, y: 1.5)
                            .overlay(
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .strokeBorder(
                                        LinearGradient(
                                            colors: [Color.white.opacity(0.6), Color.white.opacity(0.15)],
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        ),
                                        lineWidth: 0.75
                                    )
                            )
                    }
                }
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("G03_tab_\(index)")
    }
}

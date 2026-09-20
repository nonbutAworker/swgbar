//
// SWGBar / macOS menu bar TLS inspection detector
// Compact menu bar panel container (MainPanelView.swift)
// A single compact panel with three tabs and inline navigation.
//

import SwiftUI
import SWGBarContracts

public struct MainPanelView: View {
    // 订阅语言变更，切换后本视图立即重绘
    @ObservedObject private var l10n = LocalizationManager.shared
    @StateObject var vm: AppViewModel
    
    public init(viewModel: AppViewModel? = nil) {
        _vm = StateObject(wrappedValue: viewModel ?? AppViewModel())
    }
    
    public var body: some View {
        VStack(spacing: 0) {
            // Transient operation feedback
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
            
            // 2. Three-tab selector (G03)
            tabBar
            
            Divider()
            
            // 3. Keep tab contents mounted and use lazy stacks to reduce view recreation.
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
            
            // 4. Fixed footer (28 points)
            FooterView(vm: vm)
        }
        .frame(width: UITheme.panelWidth, height: UITheme.panelStandardHeight)
        .background(
            ZStack {
                // 1. Translucent system material
                Rectangle()
                    .fill(.ultraThinMaterial)
                
                // 2. A subtle gradient adds depth.
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
    
    // MARK: - Three-tab selector (G03)
    private var tabBar: some View {
        HStack(spacing: 4) {
            tabButton(title: L(.overview), icon: "house", index: 0)
            tabButton(title: L(.domains), icon: "globe", index: 1)
            tabButton(title: L(.certificates), icon: "doc.plaintext", index: 2)
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

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 底部状态栏：本地处理说明与监测状态圆点
//

import SwiftUI
import SWGBarContracts

public struct FooterView: View {
    @ObservedObject var vm: AppViewModel
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        HStack(spacing: 8) {
            Text("v\(InstallationManager.currentVersion)")
                .font(.system(size: 10))
                .foregroundColor(.secondary.opacity(0.7))

            Spacer()

            Text("所有数据均在本地完成处理")
                .font(.system(size: 10))
                .foregroundColor(.secondary)

            // 状态点即暂停/恢复开关：绿色跳动表示监测中，点击后转为灰色静止
            Button(action: {
                vm.togglePause()
            }) {
                Group {
                    if vm.snapshot.collectorState == .running {
                        statusDot
                            .phaseAnimator([false, true]) { dot, pulse in
                                dot
                                    .opacity(pulse ? 1 : 0.55)
                                    .shadow(color: .green.opacity(pulse ? 0.6 : 0.15), radius: pulse ? 3 : 1)
                            } animation: { _ in
                                .easeInOut(duration: 1.2)
                            }
                    } else {
                        statusDot
                    }
                }
                // 放大命中区域，6pt 的圆点本身过小不易点中
                .frame(width: 20, height: 20)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(toggleHint)
            .accessibilityLabel("监测状态")
            .accessibilityValue(statusText)
            .accessibilityHint(toggleHint)
        }
        .frame(height: 28)
        .padding(.horizontal, 16)
        .background(
            ZStack(alignment: .top) {
                Rectangle()
                    .fill(.ultraThinMaterial.opacity(0.5))
                Rectangle()
                    .fill(
                        LinearGradient(
                            colors: [Color.white.opacity(0.25), Color.white.opacity(0.06), Color.clear],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    .frame(height: 0.75)
            }
        )
    }

    private var statusDot: some View {
        Circle()
            .fill(statusColor)
            .frame(width: 6, height: 6)
    }

    /// 悬停与辅助功能提示：同时说明当前状态与点击后的行为
    private var toggleHint: String {
        vm.snapshot.collectorState == .running ? "正在监测 · 点击暂停" : "\(statusText) · 点击恢复监测"
    }

    private var statusText: String {
        switch vm.snapshot.collectorState {
        case .running: return "正在监测"
        case .paused: return "已暂停"
        case .authorizing, .unconfigured: return "等待授权"
        case .degraded: return "降级运行"
        }
    }

    private var statusColor: Color {
        switch vm.snapshot.collectorState {
        case .running: return .green
        case .paused: return .gray
        case .authorizing, .unconfigured: return .blue
        case .degraded: return .yellow
        }
    }
}

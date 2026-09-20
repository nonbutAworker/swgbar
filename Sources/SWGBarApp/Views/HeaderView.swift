//
// SWGBar / macOS menu bar TLS inspection detector
// Footer: local processing notice and monitoring status control
//

import SwiftUI
import SWGBarContracts

public struct FooterView: View {
    // 订阅语言变更，切换后本视图立即重绘
    @ObservedObject private var l10n = LocalizationManager.shared
    @ObservedObject var vm: AppViewModel
    @ObservedObject private var appearance = AppearanceManager.shared
    
    public init(vm: AppViewModel) {
        self.vm = vm
    }
    
    public var body: some View {
        HStack(spacing: 8) {
            // Cycles System -> Dark -> Light; same small type as the version label.
            Button(action: {
                appearance.cycle()
            }) {
                HStack(spacing: 3) {
                    Image(systemName: appearance.mode.symbolName)
                        .font(.system(size: 9))
                    Text(appearance.mode.label)
                        .font(.system(size: 10))
                }
                .foregroundColor(.secondary.opacity(0.7))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(L(.appearanceHintFormat, appearance.mode.label))
            .accessibilityLabel(L(.appearance))
            .accessibilityValue(appearance.mode.label)
            .accessibilityHint(L(.appearanceCycleHint))

            Text("v\(InstallationManager.currentVersion)")
                .font(.system(size: 10))
                .foregroundColor(.secondary.opacity(0.7))

            Spacer()

            Text(L(.processedOnThisMac))
                .font(.system(size: 10))
                .foregroundColor(.secondary)

            // The green pulsing dot pauses monitoring; the paused state uses a static gray dot.
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
                // Enlarge the hit area around the six-point status dot.
                .frame(width: 20, height: 20)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(toggleHint)
            .accessibilityLabel(L(.monitoringStatus))
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

    /// Explain both the current state and the click action in hover and accessibility hints.
    private var toggleHint: String {
        vm.snapshot.collectorState == .running ? "Monitoring - click to pause" : "\(statusText) · click to resume monitoring"
    }

    private var statusText: String {
        switch vm.snapshot.collectorState {
        case .running: return "Monitoring"
        case .paused: return "Paused"
        case .authorizing, .unconfigured: return "Awaiting permission"
        case .degraded: return "Limited monitoring"
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

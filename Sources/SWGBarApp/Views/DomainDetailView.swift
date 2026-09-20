//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 域名详情：证据、只读展示与溯源 (DomainDetailView.swift)
// 遵循技术方案 v1.1 第 19 章与现代化 macOS 卡片化视觉设计
//

import SwiftUI
import SWGBarContracts

public struct DomainDetailView: View {
    @ObservedObject var vm: AppViewModel
    let targetId: String

    public init(vm: AppViewModel, targetId: String) {
        self.vm = vm
        self.targetId = targetId
    }

    public var body: some View {
        let detail = vm.getDomainDetail(targetId: targetId)
        let listRow = vm.domainRows.first(where: { $0.targetId == targetId })
        let certificateIdentityKind = listRow?.certificateIdentityKind
        let statusLabel = certificateIdentityKind.map { UITheme.badgeText(for: $0) } ?? detail.verdict.shortLabel
        let statusColor = certificateIdentityKind.map { UITheme.color(for: $0) } ?? UITheme.color(for: detail.verdict)
        let endpointParts = detail.endpointAddress.components(separatedBy: " : ")
        let ipAddress = endpointParts.count > 1 ? endpointParts[0] : "—"
        let targetAddress = ipAddress == "—" ? "—" : "\(ipAddress):\(detail.port)"

        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 12) {
                // 顶部返回导航 (DD01)
                HStack {
                    Button(action: {
                        vm.selectedDomainId = nil
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.backward")
                                .font(.system(size: 11, weight: .medium))
                            Text("返回域名列表")
                                .font(UITheme.subFont)
                        }
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.08))
                        .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("DD01_back_button")

                    Spacer()
                }
                .padding(.top, 2)

                // 域名核心信息与状态看板 (Hero Banner)
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: verdictIconName(for: detail.verdict))
                        .font(.system(size: 22))
                        .foregroundColor(UITheme.color(for: detail.verdict))
                        .frame(width: 36, height: 36)
                        .background(UITheme.color(for: detail.verdict).opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8))

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text(detail.hostname)
                                .font(.system(size: 15, weight: .bold))
                                .foregroundColor(.primary)
                                .lineLimit(1)
                                .truncationMode(.middle)

                            CopyButton(text: detail.hostname, tooltip: "复制域名", size: 9, padding: 3)
                        }

                        Text(ipAddress)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    Text(statusLabel)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(statusColor)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .liquidGlassPill(tintColor: statusColor)
                }
                .padding(12)
                .liquidGlassCard(cornerRadius: 12)

                // 卡片 1: 网络信息
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "network", title: "网络信息")

                    VStack(spacing: 8) {
                        cardRow(label: "目标地址", value: targetAddress, isMonospaced: true)
                        Divider().opacity(0.4)

                        cardRow(label: "出口网卡", value: detail.egressInterface, isMonospaced: true)
                        Divider().opacity(0.4)

                        cardRow(label: "连接方式", value: detail.routingSummary)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }

                // 卡片 2: 访问统计
                if detail.requestCount > 0 {
                    VStack(alignment: .leading, spacing: 8) {
                        sectionHeader(icon: "chart.bar", title: "访问统计")

                        VStack(spacing: 8) {
                            cardRow(label: "请求频次", value: "\(detail.requestCount) 次", highlightValue: true)
                            Divider().opacity(0.4)
                            cardRow(label: "最近观察", value: detail.lastObservedFormatted, isMonospaced: true)
                        }
                        .padding(12)
                        .liquidGlassCard(cornerRadius: 12)
                    }
                }

                // 卡片 3: 证书与信任
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "lock.shield", title: "证书与信任")

                    VStack(alignment: .leading, spacing: 10) {
                        let isPublicPassed = (detail.verdict == .publicPath || detail.baselineVerdict.contains("已建立"))
                        let isSystemTrustPassed = (detail.verdict != .unknown && detail.handshakeStatus != "未探测或等待中")

                        HStack {
                            Text("本机系统验证")
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 88, alignment: .leading)

                            HStack(spacing: 5) {
                                Image(systemName: isSystemTrustPassed ? "checkmark.seal.fill" : "xmark.seal.fill")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(isSystemTrustPassed ? .accentColor : .red)
                                Text("macOS System Trust")
                                    .font(UITheme.subFont)
                                    .foregroundColor(.primary)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(Color.secondary.opacity(0.08))
                            .cornerRadius(6)

                            Spacer()
                        }

                        Divider().opacity(0.4)

                        HStack {
                            Text("公网权威验证")
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 88, alignment: .leading)

                            HStack(spacing: 5) {
                                Image(systemName: isPublicPassed ? "checkmark.seal.fill" : "xmark.seal.fill")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(isPublicPassed ? .accentColor : .red)
                                Text("Mozilla Root Store")
                                    .font(UITheme.subFont)
                                    .foregroundColor(.primary)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(Color.secondary.opacity(0.08))
                            .cornerRadius(6)

                            Spacer()
                        }

                        // 关联证书 (DD04: 与域名列表同名同源，点击跳转对应证书详情)
                        if let certificateName = listRow?.certificateSummary ?? detail.caClusterName {
                            Divider().opacity(0.4)

                            let certificateClusterId = listRow?.certificateClusterId ?? detail.caClusterId

                            HStack {
                                Text("关联证书")
                                    .font(UITheme.subFont)
                                    .foregroundColor(.secondary)
                                    .frame(width: 88, alignment: .leading)

                                Button(action: {
                                    guard let clusterId = certificateClusterId else { return }
                                    vm.openCertificateDetail(clusterId: clusterId)
                                }) {
                                    HStack(spacing: 6) {
                                        Text(certificateName)
                                            .font(UITheme.subFont)
                                            .foregroundColor(.primary)
                                            .lineLimit(1)
                                            .truncationMode(.middle)

                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 10, weight: .semibold))
                                            .foregroundColor(.secondary)
                                    }
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .disabled(certificateClusterId == nil)
                                .accessibilityIdentifier("DD04_cert_chain_node")

                                Spacer()
                            }
                        }
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }

                // 只读底部提示
                HStack {
                    Spacer()
                    Text("所有探测数据均保留于本地证据库 · 仅供只读分析")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary.opacity(0.6))
                    Spacer()
                }
                .padding(.top, 4)
                .padding(.bottom, 16)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
    }

    // MARK: - 辅助子视图组件

    private func sectionHeader(icon: String, title: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.secondary)
            Text(title)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(.secondary)
            Spacer()
        }
        .padding(.horizontal, 2)
    }

    private func cardRow(label: String, value: String, isMonospaced: Bool = false, highlightValue: Bool = false) -> some View {
        HStack(alignment: .top) {
            Text(label)
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .frame(width: 88, alignment: .leading)

            if highlightValue {
                Text(value)
                    .font(UITheme.subBoldFont)
                    .foregroundColor(.accentColor)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(Color.accentColor.opacity(0.08))
                    .cornerRadius(4)
            } else {
                Text(value)
                    .font(isMonospaced ? .system(size: 11, design: .monospaced) : UITheme.subFont)
                    .foregroundColor(.primary)
                    .lineLimit(2)
            }

            Spacer()
        }
    }

    private func verdictIconName(for verdict: Verdict) -> String {
        switch verdict {
        case .confirmedInspection: return "exclamationmark.shield.fill"
        case .suspectedInspection: return "exclamationmark.triangle.fill"
        case .publicPath: return "checkmark.shield.fill"
        case .unknown, .expectedPrivate: return "questionmark.circle.fill"
        case .excluded: return "slash.circle.fill"
        }
    }

}


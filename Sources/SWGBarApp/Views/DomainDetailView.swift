//
// SWGBar / macOS menu bar TLS inspection detector
// Domain details: evidence, read-only fields, and provenance (DomainDetailView.swift)
// Display domain evidence in native macOS cards.
//

import SwiftUI
import SWGBarContracts

public struct DomainDetailView: View {
    // 订阅语言变更，切换后本视图立即重绘
    @ObservedObject private var l10n = LocalizationManager.shared
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
        let statusLabel = certificateIdentityKind.map { UITheme.badgeText(for: $0) } ?? detail.verdict.localizedLabel
        let statusColor = certificateIdentityKind.map { UITheme.color(for: $0) } ?? UITheme.color(for: detail.verdict)
        let endpointParts = detail.endpointAddress.components(separatedBy: " : ")
        let ipAddress = endpointParts.count > 1 ? endpointParts[0] : "—"
        let targetAddress = ipAddress == "—" ? "—" : "\(ipAddress):\(detail.port)"

        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 12) {
                // Back navigation (DD01)
                HStack {
                    Button(action: {
                        vm.selectedDomainId = nil
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.backward")
                                .font(.system(size: 11, weight: .medium))
                            Text(L(.backToDomains))
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

                // Domain identity and verdict summary
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

                            CopyButton(text: detail.hostname, tooltip: L(.copyHostname), size: 9, padding: 3)
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

                // Card 1: Network details
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "network", title: L(.networkDetails))

                    VStack(spacing: 8) {
                        cardRow(label: L(.endpoint), value: targetAddress, isMonospaced: true)
                        Divider().opacity(0.4)

                        cardRow(label: L(.interfaceLabel), value: detail.egressInterface, isMonospaced: true)
                        Divider().opacity(0.4)

                        cardRow(label: L(.connection), value: detail.routingSummary)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }

                // Card 2: Activity
                if detail.requestCount > 0 {
                    VStack(alignment: .leading, spacing: 8) {
                        sectionHeader(icon: "chart.bar", title: L(.activity))

                        VStack(spacing: 8) {
                            cardRow(label: L(.requests), value: L(.requestsCountFormat, detail.requestCount), highlightValue: true)
                            Divider().opacity(0.4)
                            cardRow(label: L(.lastObserved), value: detail.lastObservedFormatted, isMonospaced: true)
                        }
                        .padding(12)
                        .liquidGlassCard(cornerRadius: 12)
                    }
                }

                // Card 3: Certificate and trust
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "lock.shield", title: L(.certificateAndTrust))

                    VStack(alignment: .leading, spacing: 10) {
                        let isPublicPassed = (detail.verdict == .publicPath || detail.baselineVerdict == L(.publicPathEstablished))
                        let isSystemTrustPassed = (detail.verdict != .unknown && detail.handshakeStatus != L(.notProbedOrPending))

                        HStack {
                            Text(L(.systemTrust))
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 88, alignment: .leading)

                            HStack(spacing: 5) {
                                Image(systemName: isSystemTrustPassed ? "checkmark.seal.fill" : "xmark.seal.fill")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(isSystemTrustPassed ? .accentColor : .red)
                                Text(L(.macosSystemTrust))
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
                            Text(L(.publicPKI))
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 88, alignment: .leading)

                            HStack(spacing: 5) {
                                Image(systemName: isPublicPassed ? "checkmark.seal.fill" : "xmark.seal.fill")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(isPublicPassed ? .accentColor : .red)
                                Text(L(.mozillaRootStore))
                                    .font(UITheme.subFont)
                                    .foregroundColor(.primary)
                            }
                            .padding(.horizontal, 7)
                            .padding(.vertical, 4)
                            .background(Color.secondary.opacity(0.08))
                            .cornerRadius(6)

                            Spacer()
                        }

                        // Associated certificate (DD04): reuse the list's identity and open its matching details.
                        if let certificateName = listRow?.certificateSummary ?? detail.caClusterName {
                            Divider().opacity(0.4)

                            let certificateClusterId = listRow?.certificateClusterId ?? detail.caClusterId

                            HStack {
                                Text(L(.associatedCertificate))
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

                // Read-only notice
                HStack {
                    Spacer()
                    Text(L(.probeEvidenceStaysLocal))
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

    // MARK: - Supporting view components

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

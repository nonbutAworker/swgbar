//
// SWGBar / macOS menu bar TLS inspection detector
// CA details: certificate identity, trust paths, and affected domains (CADetailView.swift)
// Present certificate fields in a familiar browser-style layout with native macOS cards.
//

import SwiftUI
import SWGBarContracts

public struct CADetailView: View {
    // 订阅语言变更，切换后本视图立即重绘
    @ObservedObject private var l10n = LocalizationManager.shared
    @ObservedObject var vm: AppViewModel
    let clusterId: String
    @State private var isDomainListExpanded: Bool = false
    
    public init(vm: AppViewModel, clusterId: String) {
        self.vm = vm
        self.clusterId = clusterId
    }
    
    public var body: some View {
        if let ca = vm.caClusters.first(where: { $0.clusterId == clusterId }) ?? vm.caClusters.first {
            caContent(ca: ca)
        } else {
            VStack(spacing: 12) {
                Button(action: {
                    vm.selectedCAClusterId = nil
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.backward")
                        Text(L(.backToCertificates))
                    }
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                
                Spacer()
                Text(L(.certificateClusterNotFound))
                    .font(UITheme.bodyFont)
                    .foregroundColor(.secondary)
                Spacer()
            }
            .padding(16)
        }
    }
    
    private func caContent(ca: CADetail) -> some View {
        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 12) {
                // Back navigation
                HStack {
                    Button(action: {
                        vm.selectedCAClusterId = nil
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.backward")
                                .font(.system(size: 11, weight: .medium))
                            Text(L(.backToCertificates))
                                .font(UITheme.subFont)
                        }
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.08))
                        .cornerRadius(6)
                    }
                    .buttonStyle(.plain)
                    
                    Spacer()
                }
                .padding(.top, 2)
                
                // CA identity summary
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: caIconName(for: ca.identityKind))
                        .font(.system(size: 22))
                        .foregroundColor(UITheme.color(for: ca.identityKind))
                        .frame(width: 36, height: 36)
                        .background(UITheme.color(for: ca.identityKind).opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    
                    VStack(alignment: .leading, spacing: 3) {
                        Text(ca.subjectElements.cn != "<Not present in certificate>" ? ca.subjectElements.cn : ca.caName)
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        
                        HStack(spacing: 6) {
                            Text(L(.associatedDomainsCountFormat, ca.affectedDomainsCount))
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                        }
                    }
                    
                    Spacer()
                    
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(caStatusTitle(for: ca.identityKind))
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(UITheme.color(for: ca.identityKind))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .liquidGlassPill(tintColor: UITheme.color(for: ca.identityKind))
                        
                        if ca.hasUserAssertion {
                            Text(L(.includesUserLabels))
                                .font(.system(size: 9, weight: .medium))
                                .foregroundColor(.orange)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Color.orange.opacity(0.1))
                                .cornerRadius(4)
                        }
                    }
                }
                .padding(12)
                .liquidGlassCard(cornerRadius: 12)
                
                // Section 1: Issued to
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "person.crop.square", title: L(.issuedTo))
                    
                    VStack(spacing: 8) {
                        let sub = ca.subjectElements
                        chromeRow(label: L(.commonName), value: sub.cn, canCopy: true)
                        Divider().opacity(0.4)
                        chromeRow(label: L(.organization), value: sub.o)
                        Divider().opacity(0.4)
                        chromeRow(label: L(.organizationalUnit), value: sub.ou)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Section 2: Issued by
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "building.2", title: L(.issuedBy))
                    
                    VStack(spacing: 8) {
                        let iss = ca.issuerElements
                        chromeRow(label: L(.commonName), value: iss.cn, canCopy: true)
                        Divider().opacity(0.4)
                        chromeRow(label: L(.organization), value: iss.o)
                        Divider().opacity(0.4)
                        chromeRow(label: L(.organizationalUnit), value: iss.ou)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Section 3: Validity
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "calendar", title: L(.validity))
                    
                    VStack(spacing: 8) {
                        chromeRow(label: L(.validFrom), value: ca.notBeforeFormatted)
                        Divider().opacity(0.4)
                        chromeRow(label: L(.validUntil), value: ca.notAfterFormatted)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Section 4: SHA-256 fingerprints
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "key", title: L(.sha256Fingerprints))
                    
                    VStack(spacing: 8) {
                        fingerprintRow(label: L(.certificateShort), value: ca.certSha256)
                        Divider().opacity(0.4)
                        fingerprintRow(label: L(.publicKey), value: ca.spkiSha256)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Section 5: Certificate and trust, using the same terminology as domain details
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "lock.shield", title: L(.certificateAndTrust))
                    
                    VStack(alignment: .leading, spacing: 10) {
                        let isPublicPassed: Bool = {
                            if ca.identityKind == "public" { return true }
                            if ca.identityKind == "inspection" || ca.identityKind == "suspected" { return false }
                            return ca.baselineStatus.contains("Public") && !ca.baselineStatus.contains("not established")
                        }()
                        let isSystemTrustPassed: Bool = (ca.identityKind != "unknown")
                        
                        HStack {
                            Text(L(.systemTrust))
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 105, alignment: .leading)
                            
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
                                .frame(width: 105, alignment: .leading)
                            
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
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Section 6: Affected domains
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "globe", title: L(.affectedDomains))
                    
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text(L(.associatedDomains))
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 105, alignment: .leading)
                            
                            Text(L(.domainsCountFormat, ca.affectedDomainsCount))
                                .font(UITheme.subBoldFont)
                                .foregroundColor(.primary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.secondary.opacity(0.08))
                                .cornerRadius(4)
                            
                            Spacer()
                        }
                        .frame(height: 24)
                        
                        let domains = vm.getAffectedDomains(for: ca)
                        if !domains.isEmpty {
                            Divider().opacity(0.4)
                            
                            Button(action: {
                                isDomainListExpanded.toggle()
                            }) {
                                HStack(spacing: 6) {
                                    Text(L(.domainDetailsCountFormat, domains.count))
                                        .font(UITheme.subFont)
                                        .foregroundColor(.secondary)
                                    
                                    Image(systemName: isDomainListExpanded ? "chevron.down" : "chevron.right")
                                        .font(.system(size: 9, weight: .semibold))
                                        .foregroundColor(.secondary)
                                    
                                    Spacer()
                                }
                                .frame(height: 24)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .help(isDomainListExpanded ? "Hide domain details" : "Show domain details")
                            
                            if isDomainListExpanded {
                                ScrollView(.vertical, showsIndicators: true) {
                                    VStack(alignment: .leading, spacing: 5) {
                                        ForEach(domains, id: \.self) { domain in
                                            HStack(spacing: 6) {
                                                Image(systemName: "link")
                                                    .font(.system(size: 9))
                                                    .foregroundColor(.secondary)
                                                Text(domain)
                                                    .font(.system(size: 11, design: .monospaced))
                                                    .foregroundColor(.primary)
                                                    .lineLimit(1)
                                                
                                                Spacer()
                                                
                                                CopyButton(text: domain, tooltip: "Copy hostname", size: 9, padding: 3)
                                            }
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .background(Color.secondary.opacity(0.06))
                                            .cornerRadius(6)
                                        }
                                    }
                                }
                                .frame(maxHeight: 140)
                            }
                        }
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // Read-only notice
                HStack {
                    Spacer()
                    Text(L(.certificateDataLocalOnly))
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
    
    private func chromeRow(label: String, value: String, canCopy: Bool = false) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(label)
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .frame(width: 105, alignment: .leading)
            
            let isMissing = value == "<Not present in certificate>" || value.isEmpty
            Text(isMissing ? "<Not present in certificate>" : value)
                .font(UITheme.subFont)
                .foregroundColor(isMissing ? .secondary.opacity(0.8) : .primary)
                .lineLimit(3)
            
            Spacer()
            
            if canCopy && !isMissing {
                CopyButton(text: value, tooltip: "Copy \(label)")
            }
        }
    }
    
    private func fingerprintRow(label: String, value: String) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(label)
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .frame(width: 105, alignment: .leading)
            
            let isMissing = value.isEmpty || value == "<Not present in certificate>"
            if isMissing {
                Text(L(.notPresentInCertificate))
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary.opacity(0.8))
            } else {
                Text(value)
                    .font(UITheme.fingerprintFont)
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            
            Spacer()
            
            if !isMissing {
                CopyButton(text: value, tooltip: "Copy full fingerprint")
            }
        }
    }
    
    private func caStatusTitle(for kind: String) -> String {
        switch kind {
        case "inspection": return "Confirmed"
        case "suspected": return "Suspected"
        case "public": return "Public"
        default: return "Unknown"
        }
    }
    
    private func caIconName(for kind: String) -> String {
        switch kind {
        case "inspection": return "exclamationmark.shield.fill"
        case "suspected": return "exclamationmark.triangle.fill"
        case "public": return "checkmark.seal.fill"
        default: return "doc.plaintext.fill"
        }
    }
}

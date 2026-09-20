//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// CA 详情：证书信息、信任路径与影响域展示 (CADetailView.swift)
// 严格对齐 Chrome 证书查看器基本信息规范与现代化 macOS 卡片化视觉设计
//

import SwiftUI
import SWGBarContracts

public struct CADetailView: View {
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
                        Text("返回证书列表")
                    }
                    .font(UITheme.subFont)
                    .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                
                Spacer()
                Text("未找到该证书簇信息")
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
                // 顶部返回导航
                HStack {
                    Button(action: {
                        vm.selectedCAClusterId = nil
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.backward")
                                .font(.system(size: 11, weight: .medium))
                            Text("返回证书列表")
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
                
                // CA 核心信息看板 (Hero Banner)
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: caIconName(for: ca.identityKind))
                        .font(.system(size: 22))
                        .foregroundColor(UITheme.color(for: ca.identityKind))
                        .frame(width: 36, height: 36)
                        .background(UITheme.color(for: ca.identityKind).opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    
                    VStack(alignment: .leading, spacing: 3) {
                        Text(ca.subjectElements.cn != "<未包含在证书中>" ? ca.subjectElements.cn : ca.caName)
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        
                        HStack(spacing: 6) {
                            Text("已关联 \(ca.affectedDomainsCount) 个域名")
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
                            Text("含用户标注")
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
                
                // 分类 1: 颁发对象 (Chrome 标准)
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "person.crop.square", title: "颁发对象")
                    
                    VStack(spacing: 8) {
                        let sub = ca.subjectElements
                        chromeRow(label: "公用名 (CN)", value: sub.cn, canCopy: true)
                        Divider().opacity(0.4)
                        chromeRow(label: "组织 (O)", value: sub.o)
                        Divider().opacity(0.4)
                        chromeRow(label: "组织单位 (OU)", value: sub.ou)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // 分类 2: 颁发者 (Chrome 标准)
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "building.2", title: "颁发者")
                    
                    VStack(spacing: 8) {
                        let iss = ca.issuerElements
                        chromeRow(label: "公用名 (CN)", value: iss.cn, canCopy: true)
                        Divider().opacity(0.4)
                        chromeRow(label: "组织 (O)", value: iss.o)
                        Divider().opacity(0.4)
                        chromeRow(label: "组织单位 (OU)", value: iss.ou)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // 分类 3: 有效期 (Chrome 标准)
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "calendar", title: "有效期")
                    
                    VStack(spacing: 8) {
                        chromeRow(label: "颁发日期", value: ca.notBeforeFormatted)
                        Divider().opacity(0.4)
                        chromeRow(label: "截止日期", value: ca.notAfterFormatted)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // 分类 4: SHA-256 指纹 (Chrome 标准)
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "key", title: "SHA-256 指纹")
                    
                    VStack(spacing: 8) {
                        fingerprintRow(label: "证书", value: ca.certSha256)
                        Divider().opacity(0.4)
                        fingerprintRow(label: "公钥", value: ca.spkiSha256)
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // 分类 5: 证书与信任（与域名详情保持一致的文案）
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "lock.shield", title: "证书与信任")
                    
                    VStack(alignment: .leading, spacing: 10) {
                        let isPublicPassed: Bool = {
                            if ca.identityKind == "public" { return true }
                            if ca.identityKind == "inspection" || ca.identityKind == "suspected" { return false }
                            return ca.baselineStatus.contains("公共") && !ca.baselineStatus.contains("未建立")
                        }()
                        let isSystemTrustPassed: Bool = (ca.identityKind != "unknown")
                        
                        HStack {
                            Text("本机系统验证")
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 105, alignment: .leading)
                            
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
                                .frame(width: 105, alignment: .leading)
                            
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
                    }
                    .padding(12)
                    .liquidGlassCard(cornerRadius: 12)
                }
                
                // 分类 6: 影响域 (独立分类)
                VStack(alignment: .leading, spacing: 8) {
                    sectionHeader(icon: "globe", title: "影响域")
                    
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("关联域名")
                                .font(UITheme.subFont)
                                .foregroundColor(.secondary)
                                .frame(width: 105, alignment: .leading)
                            
                            Text("\(ca.affectedDomainsCount) 个域名")
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
                                    Text("详细域名 (\(domains.count))")
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
                            .help(isDomainListExpanded ? "收起详细域名" : "展开详细域名")
                            
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
                                                
                                                CopyButton(text: domain, tooltip: "复制域名", size: 9, padding: 3)
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
                
                // 只读底部提示
                HStack {
                    Spacer()
                    Text("所有证书数据均提取自本地钥匙串与网络证据流 · 仅供只读分析")
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
    
    private func chromeRow(label: String, value: String, canCopy: Bool = false) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(label)
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .frame(width: 105, alignment: .leading)
            
            let isMissing = value == "<未包含在证书中>" || value.isEmpty
            Text(isMissing ? "<未包含在证书中>" : value)
                .font(UITheme.subFont)
                .foregroundColor(isMissing ? .secondary.opacity(0.8) : .primary)
                .lineLimit(3)
            
            Spacer()
            
            if canCopy && !isMissing {
                CopyButton(text: value, tooltip: "复制 \(label)")
            }
        }
    }
    
    private func fingerprintRow(label: String, value: String) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(label)
                .font(UITheme.subFont)
                .foregroundColor(.secondary)
                .frame(width: 105, alignment: .leading)
            
            let isMissing = value.isEmpty || value == "<未包含在证书中>"
            if isMissing {
                Text("<未包含在证书中>")
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
                CopyButton(text: value, tooltip: "复制完整指纹")
            }
        }
    }
    
    private func caStatusTitle(for kind: String) -> String {
        switch kind {
        case "inspection": return "确认"
        case "suspected": return "疑似"
        case "public": return "公共"
        default: return "未知"
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

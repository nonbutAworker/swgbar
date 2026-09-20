//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 分类判定与 CA 聚类引擎 (ClassificationEngine.swift)
// 遵循技术方案 v1.1 第 12 章：严格按证据强度执行，互斥分类，冲突检测
//

import Foundation
import SWGBarContracts

public struct ClassificationResult: Sendable {
    public let verdict: Verdict
    public let reason: String
    public let primaryCAClusterKey: String? // SPKI SHA256
    public let primaryCAName: String?
    public let hasUserAssertion: Bool
    
    public init(
        verdict: Verdict,
        reason: String,
        primaryCAClusterKey: String? = nil,
        primaryCAName: String? = nil,
        hasUserAssertion: Bool = false
    ) {
        self.verdict = verdict
        self.reason = reason
        self.primaryCAClusterKey = primaryCAClusterKey
        self.primaryCAName = primaryCAName
        self.hasUserAssertion = hasUserAssertion
    }
}

public final class ClassificationEngine: @unchecked Sendable {
    public static let shared = ClassificationEngine()
    
    public init() {}
    
    /// 执行证据分类判定
    public func classify(
        hostname: String,
        port: Int,
        isIpv4: Bool,
        isHttps: Bool,
        isOwnTraffic: Bool,
        handshakeCompleted: Bool,
        nativeAccepted: Bool,
        publicPkixPassed: Bool,
        presentedCertIds: [String],
        presentedSpkiIds: [String],
        caSubjects: [String],
        isExtraTrustAnchor: Bool,
        extraAnchorSubject: String? = nil,
        caDomainRecurrenceCount: Int, // 同一 CA 在不同公共域名出现的次数
        rules: [Rule]
    ) -> ClassificationResult {
        // 1. 范围排除 (X)
        if !isIpv4 || !isHttps || isOwnTraffic {
            return ClassificationResult(
                verdict: .excluded,
                reason: !isIpv4 ? "IPv6_OUT_OF_SCOPE" : (!isHttps ? "NON_HTTPS" : "OWN_TRAFFIC")
            )
        }
        
        // 2. 证据完整性 (U)
        if !handshakeCompleted || presentedCertIds.isEmpty {
            return ClassificationResult(
                verdict: .unknown,
                reason: "HANDSHAKE_INCOMPLETE_OR_NO_CERTS"
            )
        }
        
        // 提取主要 CA 指纹与名称 (最接近叶子的中间证书或根证书)
        let primarySPKI = presentedSpkiIds.count > 1 ? presentedSpkiIds[1] : presentedSpkiIds.first
        let primaryName = caSubjects.count > 1 ? caSubjects[1] : (caSubjects.first ?? "Unknown CA")
        
        // 3. 检查规则匹配与冲突检测
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let activeRules = rules.filter { rule in
            if let exp = rule.expiresAtMs, exp < now { return false }
            return true
        }
        
        var matchedInspectionRule: Rule? = nil
        
        for rule in activeRules {
            let normMatch = rule.matchValue.replacingOccurrences(of: ":", with: "").lowercased()
            let matchesFingerprint = presentedCertIds.map { $0.replacingOccurrences(of: ":", with: "").lowercased() }.contains(normMatch)
            let matchesSPKI = presentedSpkiIds.map { $0.replacingOccurrences(of: ":", with: "").lowercased() }.contains(normMatch)
            
            let matchesName = (rule.matchType == "ca_name") && (
                caSubjects.contains { $0.localizedCaseInsensitiveContains(rule.matchValue) } ||
                (extraAnchorSubject != nil && extraAnchorSubject!.localizedCaseInsensitiveContains(rule.matchValue))
            )
            
            // 如果规则名称匹配当前连接的 extraAnchorSubject 或任一证书 Subject
            let matchesAnchorSubject = (extraAnchorSubject != nil && !rule.name.isEmpty && (
                extraAnchorSubject!.localizedCaseInsensitiveContains(rule.name) ||
                rule.name.localizedCaseInsensitiveContains(extraAnchorSubject!)
            ))
            
            let matchesCA = matchesFingerprint || matchesSPKI || matchesName || matchesAnchorSubject
            
            let matchesDomain: Bool
            if let scope = rule.domainScope, !scope.isEmpty {
                if rule.matchType == "domain_suffix" {
                    matchesDomain = hostname.hasSuffix(scope)
                } else {
                    matchesDomain = (hostname == scope)
                }
            } else {
                matchesDomain = true
            }
            
            if rule.kind == "inspection_ca" && (matchesCA || (rule.matchType.hasPrefix("domain") && matchesDomain)) {
                matchedInspectionRule = rule
            }
        }
        
        // 4. 明确检查身份规则 (C)
        if let inspRule = matchedInspectionRule {
            // 条件 1 约束：必须无法通过公网校验，才允许确认为中间人检查身份
            if !publicPkixPassed {
                return ClassificationResult(
                    verdict: .confirmedInspection,
                    reason: "RULE_MATCH: \(inspRule.explanation)",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName,
                    hasUserAssertion: (inspRule.origin == "user")
                )
            }
        }
        
        // 6. 公共基线验证通过 或 根证书为系统原生公共根（非额外私有信任根）(P)
        if nativeAccepted && (publicPkixPassed || !isExtraTrustAnchor) {
            return ClassificationResult(
                verdict: .publicPath,
                reason: "BASIC_PKIX_PUBLIC_PATH_VALID",
                primaryCAClusterKey: primarySPKI,
                primaryCAName: primaryName
            )
        }
        
        // 7. 原生信任接受且属于用户/管理员额外安装的私有根证书 (isExtraTrustAnchor == true)
        // 此时已满足条件 1 (无法通过公网证书校验，通过添加到本机的受信任根证书校验)
        if nativeAccepted && isExtraTrustAnchor {
            if caDomainRecurrenceCount > 10 {
                // 条件 2: 多个不同的域名（超过10个）都是用 1 个相同的证书 -> 确认状态 (C)
                return ClassificationResult(
                    verdict: .confirmedInspection,
                    reason: "SWG_INTERCEPTION_CONFIRMED: Exceeds 10 distinct domains (count=\(caDomainRecurrenceCount))",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            } else if caDomainRecurrenceCount >= 2 {
                // 尚未达到超过10个不同域名的确认阈值，但已跨域名复现 -> 疑似状态 (S)
                return ClassificationResult(
                    verdict: .suspectedInspection,
                    reason: "EXTRA_TRUST_RECURRENCE_ACROSS_PUBLIC_DOMAINS (count=\(caDomainRecurrenceCount))",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            } else {
                // 单个域名私有信任，尚未跨域名复现 -> 未知 (U)
                return ClassificationResult(
                    verdict: .unknown,
                    reason: "EXTRA_PRIVATE_TRUST_NO_RECURRENCE",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            }
        }
        
        // 8. 默认未知 (U)
        return ClassificationResult(
            verdict: .unknown,
            reason: "CERT_VERIFICATION_FAILED_OR_REJECTED",
            primaryCAClusterKey: primarySPKI,
            primaryCAName: primaryName
        )
    }
}

//
// SWGBar / macOS menu bar TLS inspection detector
// Classification and CA clustering engine (ClassificationEngine.swift)
// Classify by evidence strength with mutually exclusive verdicts and rule conflict detection.
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
    
    /// Classify the available evidence.
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
        caDomainRecurrenceCount: Int, // Number of distinct public domains where this CA has appeared
        rules: [Rule]
    ) -> ClassificationResult {
        // 1. Scope exclusions (X)
        if !isIpv4 || !isHttps || isOwnTraffic {
            return ClassificationResult(
                verdict: .excluded,
                reason: !isIpv4 ? "IPv6_OUT_OF_SCOPE" : (!isHttps ? "NON_HTTPS" : "OWN_TRAFFIC")
            )
        }
        
        // 2. Evidence completeness (U)
        if !handshakeCompleted || presentedCertIds.isEmpty {
            return ClassificationResult(
                verdict: .unknown,
                reason: "HANDSHAKE_INCOMPLETE_OR_NO_CERTS"
            )
        }
        
        // Extract the primary CA fingerprint and name, using the intermediate nearest the leaf or the root.
        let primarySPKI = presentedSpkiIds.count > 1 ? presentedSpkiIds[1] : presentedSpkiIds.first
        let primaryName = caSubjects.count > 1 ? caSubjects[1] : (caSubjects.first ?? "Unknown CA")
        
        // 3. Match rules and detect conflicts.
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
            
            // Match the rule name against extraAnchorSubject or a presented certificate subject.
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
        
        // 4. Explicit inspection identity rules (C)
        if let inspRule = matchedInspectionRule {
            // Condition 1: public validation must fail before confirming inspection.
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
        
        // 6. Public baseline validation passed, or the root is a built-in public trust anchor (P).
        if nativeAccepted && (publicPkixPassed || !isExtraTrustAnchor) {
            return ClassificationResult(
                verdict: .publicPath,
                reason: "BASIC_PKIX_PUBLIC_PATH_VALID",
                primaryCAClusterKey: primarySPKI,
                primaryCAName: primaryName
            )
        }
        
        // 7. Native trust accepted an additional user or administrator root (isExtraTrustAnchor == true).
        // Condition 1 is met: public validation failed and a locally added root was trusted.
        if nativeAccepted && isExtraTrustAnchor {
            if caDomainRecurrenceCount > 10 {
                // Condition 2: one private CA appears across more than 10 distinct domains, confirming inspection (C).
                return ClassificationResult(
                    verdict: .confirmedInspection,
                    reason: "SWG_INTERCEPTION_CONFIRMED: Exceeds 10 distinct domains (count=\(caDomainRecurrenceCount))",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            } else if caDomainRecurrenceCount >= 2 {
                // Cross-domain recurrence below the confirmation threshold remains suspected (S).
                return ClassificationResult(
                    verdict: .suspectedInspection,
                    reason: "EXTRA_TRUST_RECURRENCE_ACROSS_PUBLIC_DOMAINS (count=\(caDomainRecurrenceCount))",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            } else {
                // Private trust on a single domain remains unknown (U).
                return ClassificationResult(
                    verdict: .unknown,
                    reason: "EXTRA_PRIVATE_TRUST_NO_RECURRENCE",
                    primaryCAClusterKey: primarySPKI,
                    primaryCAName: primaryName
                )
            }
        }
        
        // 8. Default to unknown (U).
        return ClassificationResult(
            verdict: .unknown,
            reason: "CERT_VERIFICATION_FAILED_OR_REJECTED",
            primaryCAClusterKey: primarySPKI,
            primaryCAName: primaryName
        )
    }
}

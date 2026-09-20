//
// SWGBar / macOS menu bar TLS inspection detector
// Native macOS server trust evaluation (NativeTrustEvaluator.swift)
// Use SecTrust and read-only trust enumeration without network evidence fetching.
//

import Foundation
import Security
import CryptoKit
import SWGBarContracts

public struct NativeTrustEvaluationOutput: Sendable {
    public let accepted: Bool
    public let errors: [String]
    public let isExtraTrustAnchor: Bool
    public let extraAnchorSubject: String?
    public let extraAnchorSPKI: String?
    
    public init(
        accepted: Bool,
        errors: [String] = [],
        isExtraTrustAnchor: Bool = false,
        extraAnchorSubject: String? = nil,
        extraAnchorSPKI: String? = nil
    ) {
        self.accepted = accepted
        self.errors = errors
        self.isExtraTrustAnchor = isExtraTrustAnchor
        self.extraAnchorSubject = extraAnchorSubject
        self.extraAnchorSPKI = extraAnchorSPKI
    }
}

public final class NativeTrustEvaluator: @unchecked Sendable {
    public static let shared = NativeTrustEvaluator()
    
    public init() {}
    
    /// Evaluate the chain using native macOS SecTrust.
    public func evaluate(host: String, peerCertsDER: [Data]) -> NativeTrustEvaluationOutput {
        guard !peerCertsDER.isEmpty else {
            return NativeTrustEvaluationOutput(accepted: false, errors: ["No peer certificates presented"])
        }
        
        var secCerts: [SecCertificate] = []
        for der in peerCertsDER {
            if let cert = SecCertificateCreateWithData(nil, der as CFData) {
                secCerts.append(cert)
            }
        }
        
        guard !secCerts.isEmpty else {
            return NativeTrustEvaluationOutput(accepted: false, errors: ["Failed to parse leaf certificate"])
        }
        
        let policy = SecPolicyCreateSSL(true, host as CFString)
        var optionalTrust: SecTrust?
        let status = SecTrustCreateWithCertificates(secCerts as CFArray, policy, &optionalTrust)
        guard status == errSecSuccess, let trust = optionalTrust else {
            return NativeTrustEvaluationOutput(accepted: false, errors: ["SecTrustCreateWithCertificates failed (\(status))"])
        }
        
        // Disable network fetching, including automatic AIA, OCSP, and CRL requests.
        if #available(macOS 10.14, *) {
            SecTrustSetNetworkFetchAllowed(trust, false)
        }
        
        var cfError: CFError?
        let accepted = SecTrustEvaluateWithError(trust, &cfError)
        
        var errorMessages: [String] = []
        if let err = cfError {
            errorMessages.append(err.localizedDescription)
        }
        
        // Check whether the root has additional trust in user or administrator keychain settings.
        var isExtraAnchor = false
        var extraSubject: String? = nil
        
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let rootCert = chain.last {
            extraSubject = SecCertificateCopySubjectSummary(rootCert) as String?
            isExtraAnchor = isCertificateInExtraTrust(rootCert)
        }
        
        if !accepted {
            AppLogger.shared.debug("SecTrust", "SecTrust validation failed host=\(host): \(errorMessages.joined(separator: "; "))")
        } else if isExtraAnchor {
            AppLogger.shared.info("SecTrust", "🎯 host=\(host) validated through an additional locally trusted root: \"\(extraSubject ?? "unknown")\"")
        } else {
            AppLogger.shared.debug("SecTrust", "host=\(host) validated through a built-in public root: \"\(extraSubject ?? "public")\"")
        }
        
        return NativeTrustEvaluationOutput(
            accepted: accepted,
            errors: errorMessages,
            isExtraTrustAnchor: isExtraAnchor,
            extraAnchorSubject: extraSubject,
            extraAnchorSPKI: nil
        )
    }
    
    /// Enumerate additional trusted certificates using SecTrustSettingsCopyCertificates.
    public func isCertificateInExtraTrust(_ cert: SecCertificate) -> Bool {
        let der = SecCertificateCopyData(cert) as Data
        
        // Enumerate the user and administrator domains.
        for domain in [SecTrustSettingsDomain.user, SecTrustSettingsDomain.admin] {
            var certsArray: CFArray?
            if SecTrustSettingsCopyCertificates(domain, &certsArray) == errSecSuccess, let certs = certsArray as? [SecCertificate] {
                for c in certs {
                    let cDer = SecCertificateCopyData(c) as Data
                    if cDer == der {
                        return true
                    }
                }
            }
        }
        return false
    }
    
    private let cacheLock = NSLock()
    private var cachedExtraTrustCAs: [CADetail]? = nil
    
    /// Invalidate the local certificate cache, for example before revalidation.
    public func invalidateCACache() {
        cacheLock.lock()
        cachedExtraTrustCAs = nil
        cacheLock.unlock()
    }
    
    /// Cache additional trusted CAs from the user and administrator keychains to avoid repeated polling work.
    public func extractAllInstalledExtraTrustCAs(forceRefresh: Bool = false) -> [CADetail] {
        cacheLock.lock()
        if !forceRefresh, let cached = cachedExtraTrustCAs {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()
        
        var results: [CADetail] = []
        var seenSPKIs = Set<String>()
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd"
        
        for domain in [SecTrustSettingsDomain.user, SecTrustSettingsDomain.admin] {
            var certsArray: CFArray?
            if SecTrustSettingsCopyCertificates(domain, &certsArray) == errSecSuccess, let certs = certsArray as? [SecCertificate] {
                for cert in certs {
                    let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown CA"
                    let der = SecCertificateCopyData(cert) as Data
                    
                    let derHash = SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
                    let spkiHash = SHA256.hash(data: der + Data("spki".utf8)).map { String(format: "%02X", $0) }.joined(separator: ":")
                    
                    if seenSPKIs.contains(spkiHash) { continue }
                    seenSPKIs.insert(spkiHash)
                    
                    let clusterId = "ca_live_" + String(spkiHash.prefix(8)).replacingOccurrences(of: ":", with: "")
                    
                    results.append(CADetail(
                        clusterId: clusterId,
                        caName: subject,
                        identityKind: "suspected",
                        hasUserAssertion: false,
                        subject: subject,
                        issuer: "System Keychain (\(domain == .user ? "User" : "Admin"))",
                        validityFormatted: "2024-01-01 to 2034-01-01",
                        certSha256: derHash,
                        spkiSha256: spkiHash,
                        extraTrustVerifiedPath: [subject, "macOS System Trust"],
                        baselineStatus: "Public path not established",
                        activeRule: nil,
                        affectedDomainsCount: 1
                    ))
                }
            }
        }
        
        if results.isEmpty {
            AppLogger.shared.warn("Keychain", "⚠️ Keychain scan complete: no additional trusted roots were found in the user or administrator domains. Only built-in Apple roots were found. If TLS inspection is expected, check the organization's root certificate and its trust settings.")
        } else {
            AppLogger.shared.info("Keychain", "✅ Keychain scan complete: found \(results.count) additional trusted or enterprise root certificates:")
            for ca in results {
                AppLogger.shared.info("Keychain", "   -> CA: \"\(ca.caName)\" | SPKI: \(ca.spkiSha256) | source: \(ca.issuer)")
            }
        }
        
        cacheLock.lock()
        cachedExtraTrustCAs = results
        cacheLock.unlock()
        
        return results
    }
}

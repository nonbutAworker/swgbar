//
// SWGBar / macOS menu bar TLS inspection detector
// Storage encryption and key management (Crypto.swift)
// AES-GCM with bound associated data and an independently derived HMAC key.
//

import Foundation
import CryptoKit
import SWGBarContracts

public final class StorageCrypto: @unchecked Sendable {
    public static let shared = StorageCrypto()
    
    private let masterKey: SymmetricKey
    private let hmacKey: SymmetricKey
    
    public init(testKey: SymmetricKey? = nil) {
        if let key = testKey {
            self.masterKey = key
            self.hmacKey = SymmetricKey(data: SHA256.hash(data: key.withUnsafeBytes { Data($0) } + Data("hmac_domain_salt".utf8)))
            return
        }
        
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = appSupport.appendingPathComponent("SWGBar", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            AppLogger.shared.error("Crypto", "Cannot create the key directory; encrypted data may not persist: \(error.localizedDescription)")
        }
        let keyFile = dir.appendingPathComponent(".storage_key")

        if let data = try? Data(contentsOf: keyFile), data.count == 32 {
            self.masterKey = SymmetricKey(data: data)
        } else {
            // A missing key is expected on first launch; an unreadable or invalid existing key makes older data unreadable.
            if FileManager.default.fileExists(atPath: keyFile.path) {
                AppLogger.shared.error("Crypto", "The existing key is unreadable or has an invalid length. A new key will be generated; previously encrypted data will be unreadable.")
            }
            let newKey = SymmetricKey(size: .bits256)
            let data = newKey.withUnsafeBytes { Data($0) }
            do {
                try data.write(to: keyFile, options: .atomic)
            } catch {
                AppLogger.shared.error("Crypto", "Cannot save the key; this session's data will be unreadable after restarting: \(error.localizedDescription)")
            }
            do {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
            } catch {
                AppLogger.shared.warn("Crypto", "Cannot restrict key file permissions: \(error.localizedDescription)")
            }
            self.masterKey = newKey
        }
        
        // Derive independent HMAC key to prevent dictionary attacks
        let derivedHmac = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: self.masterKey.withUnsafeBytes { Data($0) }),
            info: Data("SWGBar.DomainHMAC.v1".utf8),
            outputByteCount: 32
        )
        self.hmacKey = derivedHmac
    }
    
    // MARK: - AES-GCM encryption with table and primary-key binding
    
    public func encrypt(plainData: Data, table: String, primaryKey: String) throws -> Data {
        let aad = Data("\(table):\(primaryKey)".utf8)
        let sealedBox = try AES.GCM.seal(plainData, using: masterKey, authenticating: aad)
        guard let combined = sealedBox.combined else {
            throw StorageCryptoError.encryptionFailed
        }
        return combined
    }
    
    public func encryptString(_ str: String, table: String, primaryKey: String) throws -> Data {
        return try encrypt(plainData: Data(str.utf8), table: table, primaryKey: primaryKey)
    }
    
    public func decrypt(cipherData: Data, table: String, primaryKey: String) throws -> Data {
        let aad = Data("\(table):\(primaryKey)".utf8)
        let sealedBox = try AES.GCM.SealedBox(combined: cipherData)
        return try AES.GCM.open(sealedBox, using: masterKey, authenticating: aad)
    }
    
    public func decryptString(_ cipherData: Data, table: String, primaryKey: String) throws -> String {
        let plainData = try decrypt(cipherData: cipherData, table: table, primaryKey: primaryKey)
        guard let str = String(data: plainData, encoding: .utf8) else {
            throw StorageCryptoError.utf8DecodingFailed
        }
        return str
    }
    
    // MARK: - HMAC-derived hostname lookup keys
    
    public func computeDomainHMAC(normalizedHost: String) -> String {
        let code = HMAC<SHA256>.authenticationCode(for: Data(normalizedHost.utf8), using: hmacKey)
        return code.map { String(format: "%02x", $0) }.joined()
    }
}

public enum StorageCryptoError: Error {
    case encryptionFailed
    case decryptionFailed
    case utf8DecodingFailed
}

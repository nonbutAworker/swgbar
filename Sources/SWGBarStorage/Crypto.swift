//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 存储加密与密钥管理 (Crypto.swift)
// 遵循技术方案 v1.1 第 33.2 章：AES-GCM + AAD 绑定，HMAC 独立派生密钥
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
            AppLogger.shared.error("Crypto", "创建密钥目录失败，本地加密数据可能无法持久化: \(error.localizedDescription)")
        }
        let keyFile = dir.appendingPathComponent(".storage_key")

        if let data = try? Data(contentsOf: keyFile), data.count == 32 {
            self.masterKey = SymmetricKey(data: data)
        } else {
            // 首次启动无密钥文件属正常情况；已存在但读取失败或长度异常则会导致旧数据无法解密
            if FileManager.default.fileExists(atPath: keyFile.path) {
                AppLogger.shared.error("Crypto", "已存在的密钥文件读取失败或长度异常，将重新生成密钥，此前加密数据将无法解密")
            }
            let newKey = SymmetricKey(size: .bits256)
            let data = newKey.withUnsafeBytes { Data($0) }
            do {
                try data.write(to: keyFile, options: .atomic)
            } catch {
                AppLogger.shared.error("Crypto", "密钥写入失败，重启后将无法解密本次数据: \(error.localizedDescription)")
            }
            do {
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
            } catch {
                AppLogger.shared.warn("Crypto", "密钥文件权限收紧失败: \(error.localizedDescription)")
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
    
    // MARK: - AES-GCM 加密与解密 (带 AAD 绑定表名与主键)
    
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
    
    // MARK: - HMAC 域名派生检索键
    
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

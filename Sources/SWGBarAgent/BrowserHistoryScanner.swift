//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 浏览器历史记录扫描器 (BrowserHistoryScanner.swift)
// 扫描 Chromium 系浏览器 History 数据库，发现本机真实访问的 HTTPS 域名与请求次数
//

import Foundation
import SQLite3
import SWGBarContracts

public final class BrowserHistoryScanner: @unchecked Sendable {
    public static let shared = BrowserHistoryScanner()
    
    public struct DiscoveredDomain: Sendable {
        public let hostname: String
        public let port: Int
        public let requestCount: Int64
        
        public init(hostname: String, port: Int = 443, requestCount: Int64) {
            self.hostname = hostname
            self.port = port
            self.requestCount = requestCount
        }
    }
    
    private struct HistoryKey: Hashable {
        let host: String
        let port: Int
    }
    
    /// 扫描所有 Chromium 系浏览器 History 数据库，返回按请求次数降序排列的 HTTPS 域名与端口
    public func scanAllBrowserHistories() -> [DiscoveredDomain] {
        let historyFiles = findHistoryFiles()
        var aggregated: [HistoryKey: Int64] = [:]
        
        for path in historyFiles {
            let entries = scanSingleHistoryDB(path: path)
            for entry in entries {
                let key = HistoryKey(host: entry.host, port: entry.port)
                aggregated[key, default: 0] += entry.count
            }
        }
        
        return aggregated
            .map { DiscoveredDomain(hostname: $0.key.host, port: $0.key.port, requestCount: $0.value) }
            .sorted { $0.requestCount > $1.requestCount }
    }
    
    // MARK: - 查找浏览器 History 文件
    
    private func findHistoryFiles() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let appSupport = "\(home)/Library/Application Support"
        let fm = FileManager.default
        var discoveredSet = Set<String>()
        
        // 通用纯动态自动发现：零 Hardcode 遍历 ~/Library/Application Support（不限深度）
        // 借助精准剪枝跳过无关系统/缓存/开发目录，自动校验是否为包含 urls 表的真实 Chromium 历史库
        let skipDirs: Set<String> = [
            "MobileSync", "Containers", "Group Containers", "Caches", "Developer",
            "Mail", "CloudDocs", "AddressBook", "CallHistoryTransactions", "CrashReporter",
            "FileProvider", "com.apple.sharedfilelist", "Knowledge", "com.apple.TCC",
            "SyncedPreferences", "Quick Look", "Logs", "Saved Application State",
            // 资源与缓存目录（包含海量无用小文件，永远不会存放 History 数据库）
            "Cache", "Code Cache", "GPUCache", "DawnCache", "ShaderCache", "blob_storage",
            "IndexedDB", "Service Worker", "extensions", "workspaceStorage", "globalStorage",
            "node_modules", "CachedExtensionVSIXs", "Crashpad", "databases"
        ]
        
        if let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: appSupport),
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) {
            while let fileURL = enumerator.nextObject() as? URL {
                let name = fileURL.lastPathComponent
                if skipDirs.contains(name) {
                    enumerator.skipDescendants()
                    continue
                }
                if name == "History" {
                    let path = fileURL.path
                    if !discoveredSet.contains(path) && isChromiumHistoryDB(path: path) {
                        discoveredSet.insert(path)
                    }
                }
            }
        }
        
        return Array(discoveredSet)
    }
    
    /// 校验指定路径是否为标准 Chromium 的 History 数据库（包含 urls 表）
    /// 浏览器运行时会对原库持有写锁，直接打开将返回 SQLITE_BUSY 而被误判为非历史库，
    /// 因此统一先复制到临时副本再校验，与实际读取路径保持一致。
    private func isChromiumHistoryDB(path: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return false }

        let tmpCopy = "\(NSTemporaryDirectory())swgbar_history_check_\(UUID().uuidString).sqlite"
        do {
            try fm.copyItem(atPath: path, toPath: tmpCopy)
        } catch {
            AppLogger.shared.warn("BrowserHistory", "跳过历史库（复制副本失败）: \(path) -> \(error.localizedDescription)")
            return false
        }
        defer { try? fm.removeItem(atPath: tmpCopy) }

        var db: OpaquePointer?
        let openRc = sqlite3_open_v2(tmpCopy, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil)
        guard openRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "跳过历史库（副本打开失败 rc=\(openRc)）: \(path)")
            sqlite3_close(db)
            return false
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        let checkSql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='urls';"
        let prepareRc = sqlite3_prepare_v2(db, checkSql, -1, &stmt, nil)
        guard prepareRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "跳过历史库（urls 表校验失败 rc=\(prepareRc)）: \(path)")
            return false
        }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }
    
    // MARK: - 扫描单个 History 数据库
    
    private func scanSingleHistoryDB(path: String) -> [(host: String, port: Int, count: Int64)] {
        let fm = FileManager.default
        let tmpDir = NSTemporaryDirectory()
        let tmpCopy = "\(tmpDir)swgbar_history_\(UUID().uuidString).sqlite"
        
        // 复制文件（浏览器持有锁）
        do {
            try fm.copyItem(atPath: path, toPath: tmpCopy)
        } catch {
            AppLogger.shared.warn("BrowserHistory", "读取历史库失败（复制副本失败）: \(path) -> \(error.localizedDescription)")
            return []
        }
        
        defer {
            try? fm.removeItem(atPath: tmpCopy)
        }
        
        var db: OpaquePointer?
        let openRc = sqlite3_open_v2(tmpCopy, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil)
        guard openRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "读取历史库失败（副本打开失败 rc=\(openRc)）: \(path)")
            sqlite3_close(db)
            return []
        }
        defer { sqlite3_close(db) }
        
        let sql = "SELECT url, visit_count FROM urls WHERE url LIKE 'https://%' AND visit_count > 0;"
        var stmt: OpaquePointer?
        let prepareRc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "读取历史库失败（查询准备失败 rc=\(prepareRc)）: \(path)")
            return []
        }
        defer { sqlite3_finalize(stmt) }
        
        var entries: [(host: String, port: Int, count: Int64)] = []
        
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let urlCStr = sqlite3_column_text(stmt, 0) else { continue }
            let urlStr = String(cString: urlCStr)
            let visitCount = sqlite3_column_int64(stmt, 1)
            
            // 提取主机名与端口
            guard let comps = URLComponents(string: urlStr),
                  let host = comps.host?.lowercased(),
                  !host.isEmpty else { continue }
            
            let port = comps.port ?? 443
            
            // 过滤内网/本机地址
            if isPrivateOrLocal(host) { continue }
            
            entries.append((host: host, port: port, count: visitCount))
        }
        
        // 聚合同一 (host, port)
        var targetCounts: [HistoryKey: Int64] = [:]
        for entry in entries {
            let key = HistoryKey(host: entry.host, port: entry.port)
            targetCounts[key, default: 0] += entry.count
        }
        
        return targetCounts.map { ($0.key.host, $0.key.port, $0.value) }
    }
    
    // MARK: - 过滤内网地址
    
    private func isPrivateOrLocal(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") || host.hasSuffix(".localhost") {
            return true
        }
        // IPv4 私有地址段
        if host.hasPrefix("10.") || host.hasPrefix("192.168.") || host.hasPrefix("172.") {
            if host.hasPrefix("172.") {
                let parts = host.split(separator: ".")
                if parts.count >= 2, let second = Int(parts[1]), (16...31).contains(second) {
                    return true
                }
            } else {
                return true
            }
        }
        if host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
            return true
        }
        return false
    }
}

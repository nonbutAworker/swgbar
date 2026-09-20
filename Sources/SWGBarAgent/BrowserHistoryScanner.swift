//
// SWGBar / macOS menu bar TLS inspection detector
// Browser history scanner (BrowserHistoryScanner.swift)
// Discover HTTPS hostnames and request counts from local Chromium history databases.
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
    
    /// Scan Chromium history databases and return HTTPS endpoints ordered by request count.
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
    
    // MARK: - Locate browser history files
    
    private func findHistoryFiles() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let appSupport = "\(home)/Library/Application Support"
        let fm = FileManager.default
        var discoveredSet = Set<String>()
        
        // Discover history databases dynamically beneath ~/Library/Application Support.
        // Prune unrelated system, cache, and development directories; validate each database's urls table.
        let skipDirs: Set<String> = [
            "MobileSync", "Containers", "Group Containers", "Caches", "Developer",
            "Mail", "CloudDocs", "AddressBook", "CallHistoryTransactions", "CrashReporter",
            "FileProvider", "com.apple.sharedfilelist", "Knowledge", "com.apple.TCC",
            "SyncedPreferences", "Quick Look", "Logs", "Saved Application State",
            // Resource and cache directories are excluded from history discovery.
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
    
    /// Check whether a file is a Chromium history database with a urls table.
    /// An active browser may hold a write lock, causing direct reads to return SQLITE_BUSY.
    /// Validate a temporary copy, using the same approach as the history reader.
    private func isChromiumHistoryDB(path: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return false }

        let tmpCopy = "\(NSTemporaryDirectory())swgbar_history_check_\(UUID().uuidString).sqlite"
        do {
            try fm.copyItem(atPath: path, toPath: tmpCopy)
        } catch {
            AppLogger.shared.warn("BrowserHistory", "Skipping history database (copy failed): \(path) -> \(error.localizedDescription)")
            return false
        }
        defer { try? fm.removeItem(atPath: tmpCopy) }

        var db: OpaquePointer?
        let openRc = sqlite3_open_v2(tmpCopy, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil)
        guard openRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "Skipping history database (failed to open copy, rc=\(openRc)): \(path)")
            sqlite3_close(db)
            return false
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        let checkSql = "SELECT 1 FROM sqlite_master WHERE type='table' AND name='urls';"
        let prepareRc = sqlite3_prepare_v2(db, checkSql, -1, &stmt, nil)
        guard prepareRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "Skipping history database (invalid urls table, rc=\(prepareRc)): \(path)")
            return false
        }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }
    
    // MARK: - Read one history database
    
    private func scanSingleHistoryDB(path: String) -> [(host: String, port: Int, count: Int64)] {
        let fm = FileManager.default
        let tmpDir = NSTemporaryDirectory()
        let tmpCopy = "\(tmpDir)swgbar_history_\(UUID().uuidString).sqlite"
        
        // Copy the database to avoid the browser's write lock.
        do {
            try fm.copyItem(atPath: path, toPath: tmpCopy)
        } catch {
            AppLogger.shared.warn("BrowserHistory", "Cannot read history database (copy failed): \(path) -> \(error.localizedDescription)")
            return []
        }
        
        defer {
            try? fm.removeItem(atPath: tmpCopy)
        }
        
        var db: OpaquePointer?
        let openRc = sqlite3_open_v2(tmpCopy, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil)
        guard openRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "Cannot read history database (failed to open copy, rc=\(openRc)): \(path)")
            sqlite3_close(db)
            return []
        }
        defer { sqlite3_close(db) }
        
        let sql = "SELECT url, visit_count FROM urls WHERE url LIKE 'https://%' AND visit_count > 0;"
        var stmt: OpaquePointer?
        let prepareRc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRc == SQLITE_OK else {
            AppLogger.shared.warn("BrowserHistory", "Cannot read history database (query preparation failed, rc=\(prepareRc)): \(path)")
            return []
        }
        defer { sqlite3_finalize(stmt) }
        
        var entries: [(host: String, port: Int, count: Int64)] = []
        
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let urlCStr = sqlite3_column_text(stmt, 0) else { continue }
            let urlStr = String(cString: urlCStr)
            let visitCount = sqlite3_column_int64(stmt, 1)
            
            // Extract the hostname and port.
            guard let comps = URLComponents(string: urlStr),
                  let host = comps.host?.lowercased(),
                  !host.isEmpty else { continue }
            
            let port = comps.port ?? 443
            
            // Exclude private and local addresses.
            if isPrivateOrLocal(host) { continue }
            
            entries.append((host: host, port: port, count: visitCount))
        }
        
        // Aggregate by (host, port).
        var targetCounts: [HistoryKey: Int64] = [:]
        for entry in entries {
            let key = HistoryKey(host: entry.host, port: entry.port)
            targetCounts[key, default: 0] += entry.count
        }
        
        return targetCounts.map { ($0.key.host, $0.key.port, $0.value) }
    }
    
    // MARK: - Exclude private addresses
    
    private func isPrivateOrLocal(_ host: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") || host.hasSuffix(".localhost") {
            return true
        }
        // Private IPv4 address ranges
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

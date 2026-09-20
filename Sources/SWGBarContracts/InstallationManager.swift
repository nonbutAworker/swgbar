//
// SWGBar / macOS menu bar TLS inspection detector
// Installation version tracking and upgrade cleanup (InstallationManager.swift)
//
// Drag-and-drop installation and moving an app to the Trash do not invoke application hooks.
// Detect upgrades during early startup, before opening the database or reading its key.
// When the application version increases, the existing implementation clears its local files.
// Subsequent initialization then starts with fresh application state.
//

import Foundation

public enum InstallationManager {

    /// Keep the version marker outside the database so it remains available during cleanup.
    private static let versionMarkerName = ".installed_version"

    public struct UpgradeDecision: Sendable {
        /// Previously recorded version, or nil on the first launch
        public let previousVersion: String?
        public let currentVersion: String
        /// Whether upgrade cleanup was performed
        public let didResetForUpgrade: Bool
    }

    // MARK: - Paths

    public static var dataDirectory: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport.appendingPathComponent("SWGBar", isDirectory: true)
    }

    public static var logDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/SWGBar", isDirectory: true)
    }

    /// Read the bundle version from Info.plist; use 0.0 outside an app bundle, such as in unit tests.
    public static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0"
    }

    // MARK: - Version comparison

    /// Compare numeric release versions, accepting an optional v/V prefix and surrounding whitespace.
    /// Invalid versions cannot establish that an upgrade has occurred.
    static func isVersion(_ lhs: String, newerThan rhs: String) -> Bool {
        compareVersions(lhs, rhs) == .orderedDescending
    }

    private static func versionComponents(_ version: String) -> [Int]? {
        var value = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("v") || value.hasPrefix("V") {
            value.removeFirst()
        }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ part in
            !part.isEmpty && part.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
        }) else { return nil }
        let components = parts.compactMap { Int($0) }
        return components.count == parts.count ? components : nil
    }

    private static func compareVersions(_ lhs: String, _ rhs: String) -> ComparisonResult? {
        guard let l = versionComponents(lhs), let r = versionComponents(rhs) else { return nil }
        for i in 0..<max(l.count, r.count) {
            let a = i < l.count ? l[i] : 0
            let b = i < r.count ? r[i] : 0
            if a != b { return a > b ? .orderedDescending : .orderedAscending }
        }
        return .orderedSame
    }

    // MARK: - Run once during startup

    /// Call before initializing database, encryption, or other persistent application state.
    /// Clean up only on an upgrade; same-version launches and downgrades preserve data.
    @discardableResult
    public static func prepareForLaunch() -> UpgradeDecision {
        prepareForLaunch(currentVersion: currentVersion, dataDirectory: dataDirectory, logDirectory: logDirectory)
    }

    /// Use explicit directories so installation transitions can be verified without touching user data.
    @discardableResult
    static func prepareForLaunch(currentVersion: String, dataDirectory: URL, logDirectory: URL) -> UpgradeDecision {
        let markerURL = dataDirectory.appendingPathComponent(versionMarkerName)
        let previous = readRecordedVersion(at: markerURL)
        guard let components = versionComponents(currentVersion) else {
            AppLogger.shared.warn("Install", "Invalid application version; retaining existing data and version marker")
            return UpgradeDecision(previousVersion: previous, currentVersion: currentVersion, didResetForUpgrade: false)
        }
        let current = components.map(String.init).joined(separator: ".")

        guard let previous else {
            // A missing marker may indicate a first installation or data from an older application version.
            // The current policy clears existing application files before initializing a fresh installation.
            if hasExistingAppData(in: dataDirectory) {
                purgeAllLocalData(dataDirectory: dataDirectory, logDirectory: logDirectory,
                                  reason: "Existing data has no version marker; resetting for a fresh installation")
            }
            writeRecordedVersion(current, at: markerURL)
            return UpgradeDecision(previousVersion: nil, currentVersion: current, didResetForUpgrade: false)
        }

        guard let comparison = compareVersions(current, previous) else {
            AppLogger.shared.warn("Install", "Invalid recorded version; retaining existing data and version marker")
            return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: false)
        }
        guard comparison == .orderedDescending else {
            if comparison == .orderedAscending {
                AppLogger.shared.warn("Install", "Version \(current) is older than recorded version \(previous); retaining existing data")
            } else if previous != current {
                // Normalize equivalent versions without repeating installation cleanup.
                writeRecordedVersion(current, at: markerURL)
            }
            return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: false)
        }

        purgeAllLocalData(dataDirectory: dataDirectory, logDirectory: logDirectory,
                          reason: "Upgrading from \(previous) to \(current)")
        writeRecordedVersion(current, at: markerURL)
        AppLogger.shared.info("Install", "Upgrade cleanup complete; starting with fresh data (\(previous) -> \(current))")
        return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: true)
    }

    // MARK: - Read and write the version marker

    private static func readRecordedVersion(at markerURL: URL) -> String? {
        guard FileManager.default.fileExists(atPath: markerURL.path) else { return nil }
        guard let data = try? Data(contentsOf: markerURL),
              let raw = String(data: data, encoding: .utf8) else {
            return "" // An unreadable marker is invalid, not a fresh installation.
        }
        return raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func writeRecordedVersion(_ version: String, at markerURL: URL) {
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: markerURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        } catch {
            AppLogger.shared.error("Install", "Cannot create the data directory or write the version marker: \(error.localizedDescription)")
            return
        }
        do {
            try Data(version.utf8).write(to: markerURL, options: .atomic)
        } catch {
            AppLogger.shared.error("Install", "Cannot write the version marker; cleanup may repeat on the next launch: \(error.localizedDescription)")
        }
    }

    // MARK: - Cleanup

    /// Check for existing application data, such as the database or encryption key.
    private static func hasExistingAppData(in dataDirectory: URL) -> Bool {
        let fm = FileManager.default
        let markers = [".storage_key", "swgbar.sqlite"]
        return markers.contains { fm.fileExists(atPath: dataDirectory.appendingPathComponent($0).path) }
    }

    /// Remove local application data and its key so initialization starts with fresh state.
    private static func purgeAllLocalData(dataDirectory: URL, logDirectory: URL, reason: String) {
        AppLogger.shared.info("Install", "Clearing historical local data: \(reason)")

        // Data directory: database, WAL/SHM files, encryption key, and version marker
        removeIfExists(dataDirectory, label: "data directory")

        // The logger already holds the active log file open.
        // Remove archived logs while leaving the active log available for continued writes.
        purgeLogArchives(in: logDirectory)
    }

    private static func removeIfExists(_ url: URL, label: String) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else { return }
        do {
            try fm.removeItem(at: url)
        } catch {
            AppLogger.shared.error("Install", "Cannot remove \(label): \(url.path) -> \(error.localizedDescription)")
        }
    }

    /// Remove only archived logs, preserving the file currently held by the logger.
    private static func purgeLogArchives(in logDirectory: URL) {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: logDirectory.path) else { return }
        for name in items where name.hasPrefix("swgbar.log.") {
            removeIfExists(logDirectory.appendingPathComponent(name), label: "archived logs")
        }
    }
}

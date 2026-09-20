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

    private static var versionMarkerURL: URL {
        dataDirectory.appendingPathComponent(versionMarkerName)
    }

    /// Read the bundle version from Info.plist; use 0.0 outside an app bundle, such as in unit tests.
    public static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0"
    }

    // MARK: - Version comparison

    /// Compare numeric components in order, treating unparseable components as zero; 1.10 is newer than 1.9.
    static func isVersion(_ lhs: String, newerThan rhs: String) -> Bool {
        let l = lhs.split(separator: ".").map { Int($0) ?? 0 }
        let r = rhs.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(l.count, r.count) {
            let a = i < l.count ? l[i] : 0
            let b = i < r.count ? r[i] : 0
            if a != b { return a > b }
        }
        return false
    }

    // MARK: - Run once during startup

    /// Call before initializing database, encryption, or other persistent application state.
    /// Clean up only on an upgrade; same-version launches and downgrades preserve data.
    @discardableResult
    public static func prepareForLaunch() -> UpgradeDecision {
        let current = currentVersion
        let previous = readRecordedVersion()

        guard let previous else {
            // A missing marker may indicate a first installation or data from an older application version.
            // The current policy clears existing application files before initializing a fresh installation.
            if hasExistingAppData() {
                purgeAllLocalData(reason: "Existing data has no version marker; resetting for a fresh installation")
            }
            writeRecordedVersion(current)
            return UpgradeDecision(previousVersion: nil, currentVersion: current, didResetForUpgrade: false)
        }

        guard isVersion(current, newerThan: previous) else {
            // Retain data on the same version or a downgrade, logging the latter.
            if previous != current {
                AppLogger.shared.warn("Install", "Version \(current) is older than recorded version \(previous); retaining existing data")
            }
            return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: false)
        }

        purgeAllLocalData(reason: "Upgrading from \(previous) to \(current)")
        writeRecordedVersion(current)
        AppLogger.shared.info("Install", "Upgrade cleanup complete; starting with fresh data (\(previous) -> \(current))")
        return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: true)
    }

    // MARK: - Read and write the version marker

    private static func readRecordedVersion() -> String? {
        guard let data = try? Data(contentsOf: versionMarkerURL),
              let raw = String(data: data, encoding: .utf8) else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func writeRecordedVersion(_ version: String) {
        let fm = FileManager.default
        do {
            try fm.createDirectory(at: dataDirectory, withIntermediateDirectories: true)
        } catch {
            AppLogger.shared.error("Install", "Cannot create the data directory or write the version marker: \(error.localizedDescription)")
            return
        }
        do {
            try Data(version.utf8).write(to: versionMarkerURL, options: .atomic)
        } catch {
            AppLogger.shared.error("Install", "Cannot write the version marker; cleanup may repeat on the next launch: \(error.localizedDescription)")
        }
    }

    // MARK: - Cleanup

    /// Check for existing application data, such as the database or encryption key.
    private static func hasExistingAppData() -> Bool {
        let fm = FileManager.default
        let markers = [".storage_key", "swgbar.sqlite"]
        return markers.contains { fm.fileExists(atPath: dataDirectory.appendingPathComponent($0).path) }
    }

    /// Remove local application data and its key so initialization starts with fresh state.
    private static func purgeAllLocalData(reason: String) {
        AppLogger.shared.info("Install", "Clearing historical local data: \(reason)")
        let fm = FileManager.default

        // Data directory: database, WAL/SHM files, encryption key, and version marker
        removeIfExists(dataDirectory, label: "data directory")

        // The logger already holds the active log file open.
        // Remove archived logs while leaving the active log available for continued writes.
        purgeLogArchives()

        _ = fm
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
    private static func purgeLogArchives() {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: logDirectory.path) else { return }
        for name in items where name.hasPrefix("swgbar.log.") {
            removeIfExists(logDirectory.appendingPathComponent(name), label: "archived logs")
        }
    }
}

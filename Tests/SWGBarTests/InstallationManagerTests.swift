import XCTest
@testable import SWGBarContracts

final class InstallationManagerTests: XCTestCase {
    func testReleaseVersionsCompareNumerically() {
        XCTAssertTrue(InstallationManager.isVersion("1.6.0", newerThan: "1.5.1"))
        XCTAssertTrue(InstallationManager.isVersion("1.6.1", newerThan: "1.6.0"))
        XCTAssertTrue(InstallationManager.isVersion("1.10.0", newerThan: "1.9.9"))
    }

    func testVersionPrefixesAndWhitespaceDoNotChangeOrdering() {
        XCTAssertTrue(InstallationManager.isVersion("v2.0.0", newerThan: "1.9.0"))
        XCTAssertTrue(InstallationManager.isVersion(" V1.6.1\n", newerThan: "v1.6.0"))
        XCTAssertFalse(InstallationManager.isVersion("1.6.0", newerThan: "v1.6.0"))
        XCTAssertFalse(InstallationManager.isVersion("v1.6.0", newerThan: "1.6.0"))
        XCTAssertFalse(InstallationManager.isVersion("1.5.1", newerThan: "v1.6.0"))
        XCTAssertFalse(InstallationManager.isVersion("1.6", newerThan: "1.6.0"))
    }

    func testInvalidVersionsCannotTriggerAnUpgrade() {
        for invalid in ["", "v", "invalid", "1..6", "1.6.", "-1.6.0", "1.6.x", "1.6.0-beta", "1.999999999999999999999999999999"] {
            XCTAssertFalse(InstallationManager.isVersion(invalid, newerThan: "1.0.0"), invalid)
            XCTAssertFalse(InstallationManager.isVersion("1.6.1", newerThan: invalid), invalid)
        }
    }

    func testUpgradeResetsDataOnceAndRecordsTheVersion() throws {
        try withDirectories { data, logs in
            try seedData(data, logs)
            let marker = data.appendingPathComponent(".installed_version")
            try Data(" v1.5.1\n".utf8).write(to: marker)

            let upgrade = InstallationManager.prepareForLaunch(currentVersion: "1.6.0", dataDirectory: data, logDirectory: logs)
            XCTAssertTrue(upgrade.didResetForUpgrade)
            XCTAssertEqual(upgrade.previousVersion, "v1.5.1")
            XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "1.6.0")
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.appendingPathComponent("swgbar.sqlite").path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.appendingPathComponent(".storage_key").path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: logs.appendingPathComponent("swgbar.log.1").path))
            XCTAssertEqual(try String(contentsOf: logs.appendingPathComponent("swgbar.log"), encoding: .utf8), "active log")

            try seedData(data, logs)
            let relaunch = InstallationManager.prepareForLaunch(currentVersion: "v1.6.0", dataDirectory: data, logDirectory: logs)
            XCTAssertFalse(relaunch.didResetForUpgrade)
            try assertDataPreserved(data, logs)

            let patch = InstallationManager.prepareForLaunch(currentVersion: "1.6.1", dataDirectory: data, logDirectory: logs)
            XCTAssertTrue(patch.didResetForUpgrade)
            XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "1.6.1")
        }
    }

    func testEquivalentMarkerAndDowngradePreserveData() throws {
        try withDirectories { data, logs in
            try seedData(data, logs)
            let marker = data.appendingPathComponent(".installed_version")
            try Data("v1.6.1".utf8).write(to: marker)
            for current in ["1.6.1", "1.5.1"] {
                let result = InstallationManager.prepareForLaunch(currentVersion: current, dataDirectory: data, logDirectory: logs)
                XCTAssertFalse(result.didResetForUpgrade)
                XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "1.6.1")
                try assertDataPreserved(data, logs)
            }
        }
    }

    func testInvalidMarkersPreserveDataAndMarkerBytes() throws {
        try withDirectories { data, logs in
            try seedData(data, logs)
            let marker = data.appendingPathComponent(".installed_version")
            for invalid in [Data(), Data("1..6".utf8), Data([0xff, 0xfe])] {
                try invalid.write(to: marker)
                let result = InstallationManager.prepareForLaunch(currentVersion: "1.6.1", dataDirectory: data, logDirectory: logs)
                XCTAssertFalse(result.didResetForUpgrade)
                XCTAssertEqual(try Data(contentsOf: marker), invalid)
                try assertDataPreserved(data, logs)
            }
        }
    }

    func testInvalidCurrentVersionDoesNotInitializeOrClearData() throws {
        try withDirectories { data, logs in
            try seedData(data, logs)
            let marker = data.appendingPathComponent(".installed_version")
            let result = InstallationManager.prepareForLaunch(currentVersion: "invalid", dataDirectory: data, logDirectory: logs)
            XCTAssertFalse(result.didResetForUpgrade)
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
            try assertDataPreserved(data, logs)
        }
    }

    func testFirstLaunchRecordsACanonicalVersion() throws {
        try withDirectories { data, logs in
            let result = InstallationManager.prepareForLaunch(currentVersion: " V1.6.1\n", dataDirectory: data, logDirectory: logs)
            XCTAssertNil(result.previousVersion)
            XCTAssertFalse(result.didResetForUpgrade)
            XCTAssertEqual(result.currentVersion, "1.6.1")
            XCTAssertEqual(try String(contentsOf: data.appendingPathComponent(".installed_version"), encoding: .utf8), "1.6.1")
        }
    }

    func testLegacyDataWithoutAMarkerStillUsesFreshInstallCleanup() throws {
        try withDirectories { data, logs in
            try seedData(data, logs)
            let result = InstallationManager.prepareForLaunch(currentVersion: "1.6.1", dataDirectory: data, logDirectory: logs)
            XCTAssertNil(result.previousVersion)
            XCTAssertFalse(FileManager.default.fileExists(atPath: data.appendingPathComponent("swgbar.sqlite").path))
            XCTAssertEqual(try String(contentsOf: data.appendingPathComponent(".installed_version"), encoding: .utf8), "1.6.1")
        }
    }

    private func withDirectories(_ body: (URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let data = root.appendingPathComponent("data")
        let logs = root.appendingPathComponent("logs")
        try FileManager.default.createDirectory(at: data, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(data, logs)
    }

    private func seedData(_ data: URL, _ logs: URL) throws {
        try Data("test database".utf8).write(to: data.appendingPathComponent("swgbar.sqlite"))
        try Data("test key".utf8).write(to: data.appendingPathComponent(".storage_key"))
        try Data("active log".utf8).write(to: logs.appendingPathComponent("swgbar.log"))
        try Data("archive".utf8).write(to: logs.appendingPathComponent("swgbar.log.1"))
    }

    private func assertDataPreserved(_ data: URL, _ logs: URL) throws {
        XCTAssertEqual(try String(contentsOf: data.appendingPathComponent("swgbar.sqlite"), encoding: .utf8), "test database")
        XCTAssertEqual(try String(contentsOf: data.appendingPathComponent(".storage_key"), encoding: .utf8), "test key")
        XCTAssertEqual(try String(contentsOf: logs.appendingPathComponent("swgbar.log.1"), encoding: .utf8), "archive")
    }
}

import XCTest
@testable import SWGBarAgent

final class CoreWorkerBridgeTests: XCTestCase {
    func testMissingWorkerFailsClosed() async throws {
        let fm = FileManager.default
        let originalDirectory = fm.currentDirectoryPath
        let directory = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        defer {
            _ = fm.changeCurrentDirectoryPath(originalDirectory)
            try? fm.removeItem(at: directory)
        }
        XCTAssertTrue(fm.changeCurrentDirectoryPath(directory.path))

        let result = await CoreWorkerBridge().executeProbe(host: "example.invalid")

        XCTAssertEqual(result.errorCode, "WORKER_NOT_FOUND")
        XCTAssertFalse(result.handshakeCompleted)
        XCTAssertFalse(result.nativeAccepted)
        XCTAssertFalse(result.publicPkixPassed)
        XCTAssertTrue(result.remoteIp.isEmpty)
        XCTAssertTrue(result.presentedDers.isEmpty)
        XCTAssertTrue(result.caSubjects.isEmpty)
    }
}

//
// SWGBar / macOS menu bar TLS inspection detector
// Application entry point (main.swift)
// LSUIElement application without a Dock icon or separate main window.
//

import Cocoa
import SwiftUI
import SWGBarContracts
import SWGBarAgent
import SWGBarStorage
import SWGBarFilter

// 1. Install crash, fatal signal, and uncaught exception handlers before other startup work.
AppLogger.installCrashHandlers()
AppLogger.shared.info("App", "Starting SWGBar (version: v\(InstallationManager.currentVersion), PID: \(ProcessInfo.processInfo.processIdentifier), OS: \(ProcessInfo.processInfo.operatingSystemVersionString))")

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarController: MenuBarController?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        AppLogger.shared.info("App", "AppDelegate started; loading the menu bar controller and UI...")
        // Create the menu bar controller and show the panel after launch.
        menuBarController = MenuBarController()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.menuBarController?.showPopover()
        }
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        AppLogger.shared.info("App", "Application is quitting; stopping BPF capture and the Go CoreWorker process...")
        // Stop BPF capture and terminate the persistent CoreWorker process before quitting.
        SystemPacketSniffer.shared.stop()
        CoreWorkerBridge.shared.terminate()
        AppLogger.shared.info("App", "SWGBar resources released; shutdown complete.")
    }
}

// Handle command-line arguments.
if CommandLine.arguments.contains("--version") {
    print("SWGBar v\(InstallationManager.currentVersion) (macOS TLS Inspection Detector)")
    exit(0)
}

if CommandLine.arguments.contains("--dump-demo") {
    let service = SnapshotService()
    let snapshot = service.generateDemoSnapshot(metricKind: "probe_domain", epochId: "epoch-03", windowSeconds: 3600)
    let data = try! JSONEncoder().encode(snapshot)
    print(String(data: data, encoding: .utf8)!)
    exit(0)
}

// Detect upgrades before opening persistent data, but keep version and demo commands read-only.
InstallationManager.prepareForLaunch()

if CommandLine.arguments.contains("--dump-live") {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let dbFile = appSupport.appendingPathComponent("SWGBar/swgbar.sqlite").path
    let db = (try? SQLiteDatabase(path: dbFile)) ?? (try! SQLiteDatabase.inMemory())
    let service = SnapshotService(repository: StorageRepository(db: db))
    let snapshot = service.getOverviewSnapshot()
    let data = try! JSONEncoder().encode(snapshot)
    print(String(data: data, encoding: .utf8)!)
    exit(0)
}

if CommandLine.arguments.contains("--rescan-browser") {
    let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
    let dbFile = appSupport.appendingPathComponent("SWGBar/swgbar.sqlite").path
    let db = (try? SQLiteDatabase(path: dbFile)) ?? (try! SQLiteDatabase.inMemory())
    let repo = StorageRepository(db: db)
    let scanner = BrowserHistoryScanner.shared
    let discovered = scanner.scanAllBrowserHistories()
    print("Found \(discovered.count) domains in browser history.")
    for d in discovered {
        _ = try? repo.getOrCreateTarget(hostname: d.hostname, port: d.port, requestCount: d.requestCount)
    }
    try? repo.cleanupPhantomPort443Targets()
    print("Rescan complete!")
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// Run as an accessory app with a status item and no Dock icon or main window.
app.setActivationPolicy(.accessory)
app.run()

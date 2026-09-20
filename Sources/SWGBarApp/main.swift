//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 应用主程序入口 (main.swift)
// 遵循技术方案 v1.1 第 01, 15 章：LSUIElement=true、无 Dock、无主窗口
//

import Cocoa
import SwiftUI
import SWGBarContracts
import SWGBarAgent
import SWGBarStorage
import SWGBarFilter

// 1. 在程序最早期安装崩溃、致命信号与未捕获异常拦截器，确保所有异常均能写入日志文件
AppLogger.installCrashHandlers()
AppLogger.shared.info("App", "SWGBar 服务正在启动 (版本: v\(InstallationManager.currentVersion), PID: \(ProcessInfo.processInfo.processIdentifier), 系统版本: \(ProcessInfo.processInfo.operatingSystemVersionString))")

// 2. 版本检查与升级清理：macOS 安装/卸载均无系统钩子，只能在此处判定。
// 必须早于数据库与加密密钥的任何初始化，确保版本升级后得到等价于全新安装的干净状态。
InstallationManager.prepareForLaunch()

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarController: MenuBarController?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        AppLogger.shared.info("App", "AppDelegate 启动完成，正在加载菜单栏控制器与 UI...")
        // 初始化菜单栏控制器并在启动时自动展开面板供用户直接查看
        menuBarController = MenuBarController()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.menuBarController?.showPopover()
        }
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        AppLogger.shared.info("App", "收到程序退出通知，正在清理 BPF 嗅探器和 Go CoreWorker 子进程...")
        // 安全退出：停止 BPF 嗅探器并终止持久化 Go CoreWorker 子进程
        SystemPacketSniffer.shared.stop()
        CoreWorkerBridge.shared.terminate()
        AppLogger.shared.info("App", "SWGBar 资源已释放，安全退出完成。")
    }
}

// 检查命令行参数
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
// 设置为 accessory 应用：无 Dock 图标，无主窗口，仅保留系统状态项
app.setActivationPolicy(.accessory)
app.run()

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 安装版本管理与升级清理 (InstallationManager.swift)
//
// macOS 的拖拽安装与「移到废纸篓」卸载都没有任何系统钩子，应用无法在安装/卸载时刻执行代码。
// 因此升级检测只能放在进程启动的最早期：在数据库与加密密钥初始化之前完成判定与清理，
// 一旦发现当前版本高于上次记录的版本，就把本应用写入的全部本地文件删除，
// 使后续初始化等价于「从未安装过」的全新状态。
//

import Foundation

public enum InstallationManager {

    /// 版本标记文件独立于数据库存放：数据库本身会被清理，标记不能依赖它
    private static let versionMarkerName = ".installed_version"

    public struct UpgradeDecision: Sendable {
        /// 上一次运行记录的版本；首次安装为 nil
        public let previousVersion: String?
        public let currentVersion: String
        /// 是否执行了升级清理
        public let didResetForUpgrade: Bool
    }

    // MARK: - 路径

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

    /// 当前应用版本，取自 Info.plist；非 App 包运行（如单元测试）时回退为 0.0
    public static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0"
    }

    // MARK: - 版本比较

    /// 按数字段逐级比较版本号，例如 1.10 > 1.9；无法解析的段按 0 处理
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

    // MARK: - 启动时执行一次

    /// 必须在数据库、加密密钥、日志之外的任何本地状态初始化之前调用。
    /// 仅当当前版本高于已记录版本时清理；同版本重启或降级都不会清理。
    @discardableResult
    public static func prepareForLaunch() -> UpgradeDecision {
        let current = currentVersion
        let previous = readRecordedVersion()

        guard let previous else {
            // 无标记：可能是真正的首次安装，也可能是旧版本遗留的数据目录。
            // 两者都需要一个干净起点，因此只要目录里已有本应用写入的文件就一并清理。
            if hasExistingAppData() {
                purgeAllLocalData(reason: "检测到未携带版本标记的历史数据，按全新安装处理")
            }
            writeRecordedVersion(current)
            return UpgradeDecision(previousVersion: nil, currentVersion: current, didResetForUpgrade: false)
        }

        guard isVersion(current, newerThan: previous) else {
            // 同版本重启或降级：保留数据，仅在降级时留痕
            if previous != current {
                AppLogger.shared.warn("Install", "当前版本 \(current) 低于已记录版本 \(previous)，保留现有数据不做清理")
            }
            return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: false)
        }

        purgeAllLocalData(reason: "版本由 \(previous) 升级至 \(current)")
        writeRecordedVersion(current)
        AppLogger.shared.info("Install", "已完成升级清理，本次启动等价于全新安装 (\(previous) -> \(current))")
        return UpgradeDecision(previousVersion: previous, currentVersion: current, didResetForUpgrade: true)
    }

    // MARK: - 标记读写

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
            AppLogger.shared.error("Install", "创建数据目录失败，版本标记无法写入: \(error.localizedDescription)")
            return
        }
        do {
            try Data(version.utf8).write(to: versionMarkerURL, options: .atomic)
        } catch {
            AppLogger.shared.error("Install", "版本标记写入失败，下次启动可能重复执行清理: \(error.localizedDescription)")
        }
    }

    // MARK: - 清理

    /// 判断数据目录中是否存在本应用写入的文件（密钥、数据库或版本标记）
    private static func hasExistingAppData() -> Bool {
        let fm = FileManager.default
        let markers = [".storage_key", "swgbar.sqlite"]
        return markers.contains { fm.fileExists(atPath: dataDirectory.appendingPathComponent($0).path) }
    }

    /// 删除本应用写入的全部本地文件，包括加密密钥，使下次初始化等价于从未安装过
    private static func purgeAllLocalData(reason: String) {
        AppLogger.shared.info("Install", "开始清理历史本地数据：\(reason)")
        let fm = FileManager.default

        // 数据目录：数据库、WAL/SHM、加密密钥、版本标记
        removeIfExists(dataDirectory, label: "数据目录")

        // 日志目录：当前日志与全部历史归档；日志文件此时已被 AppLogger 持有句柄，
        // 因此只清理归档与目录内容，当前日志交由 AppLogger 自行续写。
        purgeLogArchives()

        _ = fm
    }

    private static func removeIfExists(_ url: URL, label: String) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path) else { return }
        do {
            try fm.removeItem(at: url)
        } catch {
            AppLogger.shared.error("Install", "清理\(label)失败: \(url.path) -> \(error.localizedDescription)")
        }
    }

    /// 仅删除历史归档日志，避免移除正在被写入的当前日志文件
    private static func purgeLogArchives() {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: logDirectory.path) else { return }
        for name in items where name.hasPrefix("swgbar.log.") {
            removeIfExists(logDirectory.appendingPathComponent(name), label: "历史日志")
        }
    }
}

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 本地服务运行与排查诊断日志系统 (AppLogger.swift)
// 遵循生产级排查规范：滚动文件记录、os_log 双写、关键诊断追踪、崩溃/异常现场记录
//

import Foundation
import os.log

public enum LogLevel: String, Sendable {
    case debug = "DEBUG"
    case info  = "INFO "
    case warn  = "WARN "
    case error = "ERROR"
    case fatal = "FATAL"
}

public final class AppLogger: @unchecked Sendable {
    public static let shared = AppLogger()
    
    private let logQueue = DispatchQueue(label: "com.swgbar.app.logger", qos: .utility)
    private let fileManager = FileManager.default
    private let logDirectory: URL
    public let logFilePath: URL
    
    private var fileHandle: FileHandle?
    private var currentFileSize: UInt64 = 0
    private let maxFileSize: UInt64 = 10 * 1024 * 1024 // 10 MB 单文件上限
    private let maxBackupFiles = 10                    // 保留最多 10 个历史归档
    
    private let dateFormatter: DateFormatter
    private let osLogger = os.Logger(subsystem: "com.swgbar.app", category: "Core")
    
    // C 兼容文件描述符用于信号发生时的直接写入
    nonisolated(unsafe) public static var crashFd: Int32 = -1
    private static let crashFilePath: String = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Logs/SWGBar/swgbar.log"
    }()
    
    public init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        self.logDirectory = home.appendingPathComponent("Library/Logs/SWGBar", isDirectory: true)
        self.logFilePath = self.logDirectory.appendingPathComponent("swgbar.log")
        
        self.dateFormatter = DateFormatter()
        self.dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        self.dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        
        setupLogDirectoryAndFile()
    }
    
    private func setupLogDirectoryAndFile() {
        do {
            if !fileManager.fileExists(atPath: logDirectory.path) {
                try fileManager.createDirectory(at: logDirectory, withIntermediateDirectories: true)
            }
            if !fileManager.fileExists(atPath: logFilePath.path) {
                fileManager.createFile(atPath: logFilePath.path, contents: nil)
            }
            let handle = try FileHandle(forWritingTo: logFilePath)
            let endOffset = handle.seekToEndOfFile()
            self.fileHandle = handle
            self.currentFileSize = endOffset
            
            // 为信号处理器预存非缓冲文件描述符
            Self.crashFd = open(Self.crashFilePath, O_WRONLY | O_CREAT | O_APPEND, 0o644)
        } catch {
            print("[AppLogger] Failed to setup log file: \(error.localizedDescription)")
        }
    }
    
    // MARK: - 核心输出方法
    
    public func log(_ level: LogLevel, tag: String, _ message: String, file: String = #file, line: Int = #line) {
        let nowStr = dateFormatter.string(from: Date())
        let fileName = (file as NSString).lastPathComponent
        let formatted = "[\(nowStr)] [\(level.rawValue)] [\(tag)] \(message) (\(fileName):\(line))\n"
        
        // 1. 同步镜像至 macOS 统一日志 os_log (Console.app 可视化筛选)
        switch level {
        case .debug:
            osLogger.debug("[\(tag)] \(message, privacy: .public)")
        case .info:
            osLogger.info("[\(tag)] \(message, privacy: .public)")
        case .warn:
            osLogger.warning("[\(tag)] \(message, privacy: .public)")
        case .error, .fatal:
            osLogger.error("[\(tag)] \(message, privacy: .public)")
        }
        
        // 2. 异步入队列写入文件 (避免阻塞抓包与 UI 交互主线程)
        logQueue.async { [weak self] in
            guard let self = self else { return }
            self.writeToFile(formatted)
        }
    }
    
    public func debug(_ tag: String, _ message: String, file: String = #file, line: Int = #line) {
        log(.debug, tag: tag, message, file: file, line: line)
    }
    
    public func info(_ tag: String, _ message: String, file: String = #file, line: Int = #line) {
        log(.info, tag: tag, message, file: file, line: line)
    }
    
    public func warn(_ tag: String, _ message: String, file: String = #file, line: Int = #line) {
        log(.warn, tag: tag, message, file: file, line: line)
    }
    
    public func error(_ tag: String, _ message: String, file: String = #file, line: Int = #line) {
        log(.error, tag: tag, message, file: file, line: line)
    }
    
    public func fatal(_ tag: String, _ message: String, file: String = #file, line: Int = #line) {
        log(.fatal, tag: tag, message, file: file, line: line)
    }
    
    // MARK: - 文件写入与日志轮转
    
    private func writeToFile(_ text: String) {
        guard let data = text.data(using: .utf8) else { return }
        
        currentFileSize += UInt64(data.count)
        if currentFileSize >= maxFileSize {
            checkAndRotateIfNeeded()
        }
        
        if let handle = fileHandle {
            do {
                try handle.write(contentsOf: data)
            } catch {
                print("[AppLogger] Write failed: \(error)")
            }
        }
    }
    
    private func checkAndRotateIfNeeded() {
        guard let attrs = try? fileManager.attributesOfItem(atPath: logFilePath.path),
              let size = attrs[.size] as? UInt64,
              size >= maxFileSize else {
            return
        }
        
        // 关闭当前文件句柄
        try? fileHandle?.close()
        fileHandle = nil
        
        // 轮转: .2 -> .3, .1 -> .2, log -> .1
        for i in stride(from: maxBackupFiles - 1, through: 1, by: -1) {
            let src = logDirectory.appendingPathComponent("swgbar.log.\(i)")
            let dst = logDirectory.appendingPathComponent("swgbar.log.\(i + 1)")
            if fileManager.fileExists(atPath: src.path) {
                try? fileManager.removeItem(at: dst)
                try? fileManager.moveItem(at: src, to: dst)
            }
        }
        let backup1 = logDirectory.appendingPathComponent("swgbar.log.1")
        try? fileManager.removeItem(at: backup1)
        try? fileManager.moveItem(at: logFilePath, to: backup1)
        
        // 创建全新日志文件
        fileManager.createFile(atPath: logFilePath.path, contents: nil)
        self.fileHandle = try? FileHandle(forWritingTo: logFilePath)
        self.currentFileSize = 0
    }
    
    // MARK: - 未捕获异常与 Crash 拦截
    
    public static func installCrashHandlers() {
        // 1. 注册 Objective-C / Swift 未捕获异常捕获
        NSSetUncaughtExceptionHandler { exception in
            let name = exception.name.rawValue
            let reason = exception.reason ?? "Unknown reason"
            let callStack = exception.callStackSymbols.joined(separator: "\n    ")
            let msg = """
            ==================== UNCAUGHT EXCEPTION CRASH ====================
            Exception Name: \(name)
            Reason: \(reason)
            Call Stack:
                \(callStack)
            ==================================================================
            """
            AppLogger.shared.logDirectSync(level: "FATAL", tag: "CrashReporter", message: msg)
        }
        
        // 2. 拦截致命 Unix 信号
        let fatalSignals = [SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGTRAP, SIGFPE]
        for sig in fatalSignals {
            signal(sig) { signum in
                let sigName: String
                switch signum {
                case SIGSEGV: sigName = "SIGSEGV (Segmentation fault)"
                case SIGBUS:  sigName = "SIGBUS (Bus error)"
                case SIGABRT: sigName = "SIGABRT (Abort)"
                case SIGILL:  sigName = "SIGILL (Illegal instruction)"
                case SIGTRAP: sigName = "SIGTRAP (Trace/BPT trap)"
                case SIGFPE:  sigName = "SIGFPE (Floating point exception)"
                default:      sigName = "SIGNAL \(signum)"
                }
                
                let callStack = Thread.callStackSymbols.joined(separator: "\n    ")
                let msg = """
                \n==================== FATAL SIGNAL CRASH ====================
                Received Signal: \(sigName)
                Thread Call Stack:
                    \(callStack)
                ============================================================\n
                """
                
                // 使用非缓冲直接写入，保证进程在被杀死前已将堆栈写入文件
                if AppLogger.crashFd > 0 {
                    _ = msg.withCString { ptr in
                        write(AppLogger.crashFd, ptr, strlen(ptr))
                    }
                    fsync(AppLogger.crashFd)
                }
                
                // 恢复默认处理并重新引发信号以生成 macOS 崩溃分析转储
                signal(signum, SIG_DFL)
                raise(signum)
            }
        }
    }
    
    /// 用于异常发生时的同步直接写入（不经由异步队列）
    public func logDirectSync(level: String, tag: String, message: String) {
        let nowStr = dateFormatter.string(from: Date())
        let formatted = "[\(nowStr)] [\(level)] [\(tag)] \(message)\n"
        if let data = formatted.data(using: .utf8), let handle = fileHandle {
            try? handle.write(contentsOf: data)
            try? handle.synchronize()
        }
    }
}

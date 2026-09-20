//
// SWGBar / macOS menu bar TLS inspection detector
// Local diagnostic logging (AppLogger.swift)
// Write rotating local logs and unified system logs, including crash and exception diagnostics.
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
    private let maxFileSize: UInt64 = 10 * 1024 * 1024 // 10 MB maximum per log file
    private let maxBackupFiles = 10                    // Retain at most 10 archived logs
    
    private let dateFormatter: DateFormatter
    private let osLogger = os.Logger(subsystem: "com.swgbar.app", category: "Core")
    
    // C file descriptor for direct writes from signal handlers
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
            
            // Open an unbuffered descriptor for the signal handlers.
            Self.crashFd = open(Self.crashFilePath, O_WRONLY | O_CREAT | O_APPEND, 0o644)
        } catch {
            print("[AppLogger] Failed to setup log file: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Log output
    
    public func log(_ level: LogLevel, tag: String, _ message: String, file: String = #file, line: Int = #line) {
        let nowStr = dateFormatter.string(from: Date())
        let fileName = (file as NSString).lastPathComponent
        let formatted = "[\(nowStr)] [\(level.rawValue)] [\(tag)] \(message) (\(fileName):\(line))\n"
        
        // 1. Mirror messages to the macOS unified log for Console filtering.
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
        
        // 2. Queue file writes asynchronously to avoid blocking capture or the UI.
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
    
    // MARK: - File writes and log rotation
    
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
        
        // Close the current file handle.
        try? fileHandle?.close()
        fileHandle = nil
        
        // Rotate .2 to .3, .1 to .2, and the current log to .1.
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
        
        // Create a new log file.
        fileManager.createFile(atPath: logFilePath.path, contents: nil)
        self.fileHandle = try? FileHandle(forWritingTo: logFilePath)
        self.currentFileSize = 0
    }
    
    // MARK: - Uncaught exceptions and crashes
    
    public static func installCrashHandlers() {
        // 1. Register an uncaught Objective-C exception handler.
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
        
        // 2. Handle fatal Unix signals.
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
                
                // Write the stack directly before the process terminates.
                if AppLogger.crashFd > 0 {
                    _ = msg.withCString { ptr in
                        write(AppLogger.crashFd, ptr, strlen(ptr))
                    }
                    fsync(AppLogger.crashFd)
                }
                
                // Restore the default handler and raise the signal again to produce a system crash report.
                signal(signum, SIG_DFL)
                raise(signum)
            }
        }
    }
    
    /// Write synchronously during an exception, without using the asynchronous queue.
    public func logDirectSync(level: String, tag: String, message: String) {
        let nowStr = dateFormatter.string(from: Date())
        let formatted = "[\(nowStr)] [\(level)] [\(tag)] \(message)\n"
        if let data = formatted.data(using: .utf8), let handle = fileHandle {
            try? handle.write(contentsOf: data)
            try? handle.synchronize()
        }
    }
}

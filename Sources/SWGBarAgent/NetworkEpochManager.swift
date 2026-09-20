//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 网络阶段管理器 (NetworkEpochManager.swift)
// 遵循技术方案 v1.1 第 13.2 章：去抖 2s，阶段隔离，取消未发出任务
//

import Foundation
import Network
import SWGBarContracts

public final class NetworkEpochManager: @unchecked Sendable {
    public static let shared = NetworkEpochManager()
    
    private var currentEpochIndex: Int = 1
    public private(set) var currentEpochId: String = "epoch-01"
    public private(set) var currentEpochName: String = "网络阶段 01"
    
    private let pathMonitor: NWPathMonitor
    private let monitorQueue = DispatchQueue(label: "com.swgbar.epochmonitor")
    private var debounceTimer: DispatchWorkItem?
    private let lock = NSLock()
    
    public var onEpochChanged: ((_ newEpochId: String, _ newEpochName: String) -> Void)?
    
    public init() {
        self.pathMonitor = NWPathMonitor()
        setupMonitor()
    }
    
    private func setupMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            self.handlePathUpdate(path)
        }
        pathMonitor.start(queue: monitorQueue)
    }
    
    private func handlePathUpdate(_ path: NWPath) {
        lock.lock()
        defer { lock.unlock() }
        
        debounceTimer?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.triggerNewEpoch(reason: "PATH_CHANGED")
        }
        debounceTimer = workItem
        monitorQueue.asyncAfter(deadline: .now() + 2.0, execute: workItem)
    }
    
    public func triggerNewEpoch(reason: String) {
        lock.lock()
        currentEpochIndex += 1
        let newId = String(format: "epoch-%02d", currentEpochIndex)
        let newName = String(format: "网络阶段 %02d", currentEpochIndex)
        currentEpochId = newId
        currentEpochName = newName
        let callback = onEpochChanged
        lock.unlock()
        
        callback?(newId, newName)
    }
    
}

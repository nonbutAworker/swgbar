//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 系统流采集与域名归一化 (Filter.swift)
// 遵循技术方案 v1.1 第 07-08 章：非阻塞、立即放行、域名归一化与隐私保护
//

import Foundation
import SWGBarContracts

public struct FlowMetadata: Sendable {
    public let flowId: String
    public let remoteHostname: String?
    public let remoteAddress: String
    public let remotePort: Int
    public let sourceBundleId: String?
    public let sourceDisplayName: String?
    public let observedAtMs: Int64
    public let isIpOnly: Bool
    public let isPrivateScope: Bool
    
    public init(
        flowId: String = UUID().uuidString,
        remoteHostname: String?,
        remoteAddress: String,
        remotePort: Int,
        sourceBundleId: String?,
        sourceDisplayName: String?,
        observedAtMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) {
        self.flowId = flowId
        self.remoteHostname = remoteHostname
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.sourceBundleId = sourceBundleId
        self.sourceDisplayName = sourceDisplayName
        self.observedAtMs = observedAtMs
        self.isIpOnly = (remoteHostname == nil || remoteHostname?.isEmpty == true)
        self.isPrivateScope = DomainNormalizer.isPrivateOrReservedIP(remoteAddress)
    }
}

public typealias DomainNormalizer = SWGBarContracts.DomainNormalizer

/// 有界非阻塞流队列（第 07 & 34.1 章）：≤8 MiB / 8192 项，满则计数丢弃，绝不阻塞网络
public final class BoundedFlowQueue: @unchecked Sendable {
    private var queue: [FlowMetadata] = []
    private let capacity: Int
    private let lock = NSLock()
    public private(set) var droppedCount: Int64 = 0
    
    public init(capacity: Int = 8192) {
        self.capacity = capacity
    }
    
    public func offer(_ metadata: FlowMetadata) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if queue.count >= capacity {
            droppedCount += 1
            return false // 满则丢弃
        }
        queue.append(metadata)
        return true
    }
    
    public func drain(limit: Int = 100) -> [FlowMetadata] {
        lock.lock()
        defer { lock.unlock() }
        if queue.isEmpty { return [] }
        let count = min(limit, queue.count)
        let items = Array(queue.prefix(count))
        queue.removeFirst(count)
        return items
    }
    
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return queue.count
    }
}

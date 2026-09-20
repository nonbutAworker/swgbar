//
// SWGBar / macOS menu bar TLS inspection detector
// System flow metadata and hostname normalization (Filter.swift)
// Nonblocking metadata processing, immediate traffic allowance, and hostname normalization.
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

/// Bound the queue to 8 MiB or 8,192 entries; count and drop overflow without blocking traffic.
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
            return false // Drop the event when the queue is full.
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

//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 实时探测事件通道 (DomainProbeChannel.swift)
// 采用类似 Go channel 的带缓冲并发管道模型，网络层一旦捕获域名+端口即刻入队并触发工作协程并发探测
//

import Foundation
import SWGBarContracts

public struct ProbeTarget: Hashable, Sendable {
    public let host: String
    public let port: Int
    
    public init(host: String, port: Int = 443) {
        self.host = host
        self.port = port
    }
}

public actor DomainProbeChannel {
    public static let shared = DomainProbeChannel()
    
    private var queue: [ProbeTarget] = []
    private var waiters: [CheckedContinuation<ProbeTarget?, Never>] = []
    private var idleWaiters: [CheckedContinuation<Void, Never>] = []
    private var inFlight = 0
    
    // 内存防抖冷却字典：防止同一目标 (host:port) 在几秒内因多并发连接产生重复的 TLS 握手探测
    private var lastQueuedAt: [ProbeTarget: Date] = [:]
    private let cooldownSeconds: TimeInterval = 600.0 // 10分钟内同目标不重复发起探测
    private let bufferCapacity = 4096
    
    public init() {}
    
    /// 发送新捕获的目标至探测通道 (host:port)
    public func send(host: String, port: Int = 443, force: Bool = false) {
        let normalized = host.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }
        let target = ProbeTarget(host: normalized, port: port > 0 ? port : 443)
        
        let now = Date()
        if !force, let last = lastQueuedAt[target], now.timeIntervalSince(last) < cooldownSeconds {
            return // 冷却中，跳过重复探测，但网络层仍然会计数
        }
        lastQueuedAt[target] = now
        
        // 周期性修剪过期冷却条目，防止长时间运行下内存无限增长
        if lastQueuedAt.count > 1000 {
            let expiredKeys = lastQueuedAt.filter { now.timeIntervalSince($0.value) >= cooldownSeconds }.map { $0.key }
            for key in expiredKeys {
                lastQueuedAt.removeValue(forKey: key)
            }
        }
        
        if !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            inFlight += 1
            waiter.resume(returning: target)
        } else if queue.count < bufferCapacity {
            queue.append(target)
        }
    }
    
    /// 兼容仅传域名的重载（默认端口 443）
    public func send(domain: String, force: Bool = false) {
        send(host: domain, port: 443, force: force)
    }
    
    /// 从通道接收下一个待探测目标 (ProbeTarget)
    public func receive() async -> ProbeTarget? {
        if !queue.isEmpty {
            inFlight += 1
            return queue.removeFirst()
        }
        return await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }
    
    /// worker 完成一次探测（含跳过）后必须调用，以便分批 feeder 等待本批排空
    public func markFinished() {
        inFlight = max(0, inFlight - 1)
        resumeIdleWaitersIfNeeded()
    }
    
    /// 等待队列清空且没有进行中的探测
    public func waitUntilIdle() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            if queue.isEmpty && inFlight == 0 {
                cont.resume()
            } else {
                idleWaiters.append(cont)
            }
        }
    }
    
    /// 清理所有冷却历史（在清除本地历史时调用）
    public func clearCooldowns() {
        lastQueuedAt.removeAll()
        queue.removeAll()
        resumeIdleWaitersIfNeeded()
    }
    
    /// 关闭或重置通道，唤醒所有挂起等待的 worker
    public func closeOrReset() {
        queue.removeAll()
        let pending = waiters
        waiters.removeAll()
        for w in pending {
            w.resume(returning: nil)
        }
        inFlight = 0
        resumeIdleWaitersIfNeeded()
    }
    
    private func resumeIdleWaitersIfNeeded() {
        guard queue.isEmpty && inFlight == 0 else { return }
        let pending = idleWaiters
        idleWaiters.removeAll()
        for w in pending {
            w.resume()
        }
    }
}

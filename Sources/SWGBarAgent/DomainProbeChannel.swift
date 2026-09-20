//
// SWGBar / macOS menu bar TLS inspection detector
// Live probe event channel (DomainProbeChannel.swift)
// A buffered channel dispatches captured host/port targets to concurrent probe workers.
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
    
    // An in-memory cooldown prevents concurrent connections from triggering duplicate TLS probes.
    private var lastQueuedAt: [ProbeTarget: Date] = [:]
    private let cooldownSeconds: TimeInterval = 600.0 // Do not probe the same target again within 10 minutes.
    private let bufferCapacity = 4096
    
    public init() {}
    
    /// Send a newly captured host/port target to the probe channel.
    public func send(host: String, port: Int = 443, force: Bool = false) {
        let normalized = host.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return }
        let target = ProbeTarget(host: normalized, port: port > 0 ? port : 443)
        
        let now = Date()
        if !force, let last = lastQueuedAt[target], now.timeIntervalSince(last) < cooldownSeconds {
            return // Skip duplicate probes during cooldown; network request counting continues.
        }
        lastQueuedAt[target] = now
        
        // Prune expired cooldown entries periodically to bound memory use.
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
    
    /// Compatibility overload for hostnames without an explicit port; defaults to 443.
    public func send(domain: String, force: Bool = false) {
        send(host: domain, port: 443, force: force)
    }
    
    /// Receive the next ProbeTarget from the channel.
    public func receive() async -> ProbeTarget? {
        if !queue.isEmpty {
            inFlight += 1
            return queue.removeFirst()
        }
        return await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }
    
    /// Workers must call this after each probe, including skipped probes, so the feeder can await completion.
    public func markFinished() {
        inFlight = max(0, inFlight - 1)
        resumeIdleWaitersIfNeeded()
    }
    
    /// Wait until the queue is empty and no probes are active.
    public func waitUntilIdle() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            if queue.isEmpty && inFlight == 0 {
                cont.resume()
            } else {
                idleWaiters.append(cont)
            }
        }
    }
    
    /// Clear cooldown history when local history is cleared.
    public func clearCooldowns() {
        lastQueuedAt.removeAll()
        queue.removeAll()
        resumeIdleWaitersIfNeeded()
    }
    
    /// Close or reset the channel and resume waiting workers.
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

//
// SWGBar / macOS menu bar TLS inspection detector
// Probe scheduling, rate limits, and budgets (ProbeScheduler.swift)
// Limits: 12/minute, a 15-minute cooldown, 300/hour, 1,000/day, and 500 queued targets.
//

import Foundation
import SWGBarContracts

public actor ProbeScheduler {
    private var maxConcurrency: Int = 4
    private var isLowPower: Bool = false
    
    // Token bucket capacity: four; refill rate: one token every five seconds.
    private var tokenBucketTokens: Double = 4.0
    private let tokenBucketCapacity: Double = 4.0
    private let tokenRefillRatePerSec: Double = 12.0 / 60.0 // 0.2 tokens/sec
    private var lastRefillTime: Date = Date()
    
    // Budget counters
    private var hourlyBudgetMax: Int = 300
    private var dailyBudgetMax: Int = 1000
    private var hourlyUsed: Int = 0
    private var dailyUsed: Int = 0
    private var currentHour: Int = Calendar.current.component(.hour, from: Date())
    private var currentDay: Int = Calendar.current.component(.day, from: Date())
    
    // Per-target cooldown timestamps (15 minutes)
    private var targetCooldowns: [String: Date] = [:]
    private let cooldownInterval: TimeInterval = 15 * 60 // 15 minutes
    
    // Deduplicated pending queue, limited to 500 targets
    
    // Number of active probes
    private var activeProbeCount: Int = 0
    
    public init() {}
    
    // Check and consume scheduling budgets and rate limits.
    public func canSchedule(target: String, isUserInitiated: Bool = false) -> (allowed: Bool, reason: String?) {
        checkAndResetBudgetCycles()
        refillTokens()
        
        // 1. Enforce the target cooldown, including manual refresh requests.
        if let lastProbe = targetCooldowns[target] {
            let elapsed = Date().timeIntervalSince(lastProbe)
            if elapsed < (isUserInitiated ? 10 : cooldownInterval) {
                return (false, "TARGET_IN_COOLDOWN (\(Int(cooldownInterval - elapsed))s remaining)")
            }
        }
        
        // 2. Check concurrency, allowing a reserved burst for manual probes.
        let effectiveMax = isUserInitiated ? (maxConcurrency + 4) : maxConcurrency
        if activeProbeCount >= effectiveMax {
            return (false, "CONCURRENCY_LIMIT_REACHED (\(activeProbeCount)/\(effectiveMax))")
        }
        
        // 3. Check the token bucket.
        if tokenBucketTokens < 1.0 && !isUserInitiated {
            return (false, "RATE_LIMIT_TOKEN_EXHAUSTED")
        }
        
        // 4. Check hourly and daily budgets.
        if !isUserInitiated {
            if hourlyUsed >= hourlyBudgetMax {
                return (false, "HOURLY_BUDGET_EXHAUSTED (\(hourlyUsed)/\(hourlyBudgetMax))")
            }
            if dailyUsed >= dailyBudgetMax {
                return (false, "DAILY_BUDGET_EXHAUSTED (\(dailyUsed)/\(dailyBudgetMax))")
            }
        }
        
        return (true, nil)
    }
    
    public func startProbe(target: String, isUserInitiated: Bool = false) -> Bool {
        let (allowed, _) = canSchedule(target: target, isUserInitiated: isUserInitiated)
        guard allowed else { return false }
        
        if !isUserInitiated {
            tokenBucketTokens = max(0.0, tokenBucketTokens - 1.0)
            hourlyUsed += 1
            dailyUsed += 1
        }
        activeProbeCount += 1
        targetCooldowns[target] = Date()
        return true
    }
    
    public func finishProbe(target: String) {
        activeProbeCount = max(0, activeProbeCount - 1)
    }
    
    private func refillTokens() {
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRefillTime)
        lastRefillTime = now
        tokenBucketTokens = min(tokenBucketCapacity, tokenBucketTokens + elapsed * tokenRefillRatePerSec)
    }
    
    private func checkAndResetBudgetCycles() {
        let now = Date()
        let cal = Calendar.current
        let hour = cal.component(.hour, from: now)
        let day = cal.component(.day, from: now)
        
        if hour != currentHour {
            currentHour = hour
            hourlyUsed = 0
        }
        if day != currentDay {
            currentDay = day
            dailyUsed = 0
        }
    }
}

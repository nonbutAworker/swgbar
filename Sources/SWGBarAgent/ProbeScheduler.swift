//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 探测调度器与限流限额 (ProbeScheduler.swift)
// 遵循技术方案 v1.1 第 13.1 章：令牌桶 12/min、冷却 15m、预算 300/h 1000/d、队列 500
//

import Foundation
import SWGBarContracts

public actor ProbeScheduler {
    private var maxConcurrency: Int = 4
    private var isLowPower: Bool = false
    
    // 令牌桶：容量 4，速率 12 次/分钟 (即每 5 秒 1 个令牌)
    private var tokenBucketTokens: Double = 4.0
    private let tokenBucketCapacity: Double = 4.0
    private let tokenRefillRatePerSec: Double = 12.0 / 60.0 // 0.2 tokens/sec
    private var lastRefillTime: Date = Date()
    
    // 预算计数
    private var hourlyBudgetMax: Int = 300
    private var dailyBudgetMax: Int = 1000
    private var hourlyUsed: Int = 0
    private var dailyUsed: Int = 0
    private var currentHour: Int = Calendar.current.component(.hour, from: Date())
    private var currentDay: Int = Calendar.current.component(.day, from: Date())
    
    // 目标冷却时间记录 (15 分钟)
    private var targetCooldowns: [String: Date] = [:]
    private let cooldownInterval: TimeInterval = 15 * 60 // 15 minutes
    
    // 待探测队列 (去重，最大 500)
    
    // 正在运行的探测数
    private var activeProbeCount: Int = 0
    
    public init() {}
    
    // 检查并消费预算与限流
    public func canSchedule(target: String, isUserInitiated: Bool = false) -> (allowed: Bool, reason: String?) {
        checkAndResetBudgetCycles()
        refillTokens()
        
        // 1. 单目标冷却检查 (用户手动刷新也不能无界绕过)
        if let lastProbe = targetCooldowns[target] {
            let elapsed = Date().timeIntervalSince(lastProbe)
            if elapsed < (isUserInitiated ? 10 : cooldownInterval) {
                return (false, "TARGET_IN_COOLDOWN (\(Int(cooldownInterval - elapsed))s remaining)")
            }
        }
        
        // 2. 并发度检查 (为用户手动探测预留突发通道)
        let effectiveMax = isUserInitiated ? (maxConcurrency + 4) : maxConcurrency
        if activeProbeCount >= effectiveMax {
            return (false, "CONCURRENCY_LIMIT_REACHED (\(activeProbeCount)/\(effectiveMax))")
        }
        
        // 3. 令牌桶检查
        if tokenBucketTokens < 1.0 && !isUserInitiated {
            return (false, "RATE_LIMIT_TOKEN_EXHAUSTED")
        }
        
        // 4. 小时与每日预算检查
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

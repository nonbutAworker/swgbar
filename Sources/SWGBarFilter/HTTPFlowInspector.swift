//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// TLS / DNS 流量检查器 (HTTPFlowInspector.swift)
// 从 TLS SNI、DNS 应答与 HTTPS 连接复用中还原「域名+端口」
// HTTPS 应用数据本身是加密的，无法直接读 Host；复用连接依赖此前学到的 SNI/DNS。
//

import Foundation

public final class FlowHostnameCache: @unchecked Sendable {
    private let lock = NSLock()
    private var flowToHost: [String: String] = [:]
    private var ipToHost: [String: (host: String, expiresAt: TimeInterval)] = [:]
    private let dnsTTL: TimeInterval = 300
    
    public init() {}
    
    public func rememberFlow(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int, hostname: String) {
        let host = hostname.lowercased()
        lock.lock()
        flowToHost[Self.flowKey(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort)] = host
        ipToHost[dstIP] = (host, ProcessInfo.processInfo.systemUptime + dnsTTL)
        lock.unlock()
    }
    
    public func rememberDNS(ip: String, hostname: String) {
        lock.lock()
        ipToHost[ip] = (hostname.lowercased(), ProcessInfo.processInfo.systemUptime + dnsTTL)
        lock.unlock()
    }
    
    public func hostname(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int) -> String? {
        lock.lock()
        defer { lock.unlock() }
        if let host = flowToHost[Self.flowKey(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort)] {
            return host
        }
        if let entry = ipToHost[dstIP], entry.expiresAt > ProcessInfo.processInfo.systemUptime {
            return entry.host
        }
        return nil
    }
    
    public func hostname(forIP ip: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = ipToHost[ip], entry.expiresAt > ProcessInfo.processInfo.systemUptime else { return nil }
        return entry.host
    }
    
    public func pruneIfNeeded() {
        lock.lock()
        defer { lock.unlock() }
        if flowToHost.count > 4000 {
            flowToHost.removeAll(keepingCapacity: true)
        }
        if ipToHost.count > 4000 {
            let now = ProcessInfo.processInfo.systemUptime
            ipToHost = ipToHost.filter { $0.value.expiresAt > now }
        }
    }
    
    public static func flowKey(srcIP: String, srcPort: Int, dstIP: String, dstPort: Int) -> String {
        "\(srcIP):\(srcPort)>\(dstIP):\(dstPort)"
    }
}

public enum HTTPFlowInspector {
    /// TLS 记录层：Handshake / ChangeCipherSpec / Alert / ApplicationData
    public static func looksLikeTLSRecord(_ payload: Data) -> Bool {
        guard payload.count >= 5 else { return false }
        let contentType = payload[0]
        guard (0x14...0x17).contains(contentType) else { return false }
        return payload[1] == 0x03 && payload[2] <= 0x04
    }
    
    /// IETF QUIC：长头或 short header 的 fixed bit
    public static func looksLikeQUIC(_ payload: Data) -> Bool {
        guard payload.count >= 5 else { return false }
        if payload[0] & 0x80 != 0 { return true }
        return payload[0] & 0x40 != 0
    }
    
    /// 解析 TLS ClientHello 中的 SNI
    public static func parseTLSServerName(from payload: Data) -> String? {
        guard payload.count >= 43 else { return nil }
        guard payload[0] == 0x16, payload[5] == 0x01 else { return nil }
        
        var idx = 43
        guard idx < payload.count else { return nil }
        
        let sessLen = Int(payload[idx])
        idx += 1 + sessLen
        guard idx + 2 <= payload.count else { return nil }
        
        let cipherLen = Int(payload[idx]) << 8 | Int(payload[idx + 1])
        idx += 2 + cipherLen
        guard idx + 1 <= payload.count else { return nil }
        
        let compLen = Int(payload[idx])
        idx += 1 + compLen
        guard idx + 2 <= payload.count else { return nil }
        
        let extLen = Int(payload[idx]) << 8 | Int(payload[idx + 1])
        idx += 2
        let extEnd = min(idx + extLen, payload.count)
        
        while idx + 4 <= extEnd {
            let extType = Int(payload[idx]) << 8 | Int(payload[idx + 1])
            let elen = Int(payload[idx + 2]) << 8 | Int(payload[idx + 3])
            idx += 4
            
            if extType == 0 {
                guard idx + 2 <= payload.count else { break }
                idx += 2
                guard idx + 3 <= payload.count else { break }
                let nameType = payload[idx]
                let nameLen = Int(payload[idx + 1]) << 8 | Int(payload[idx + 2])
                idx += 3
                if nameType == 0 && idx + nameLen <= payload.count {
                    let nameData = payload.subdata(in: idx..<(idx + nameLen))
                    return String(data: nameData, encoding: .utf8)
                }
                break
            }
            idx += elen
        }
        return nil
    }
    
    /// 从 DNS 应答中提取 A/AAAA → 主机名
    public static func parseDNSAddressRecords(from payload: Data) -> [(ip: String, hostname: String)] {
        guard payload.count >= 12 else { return [] }
        let flags = Int(payload[2]) << 8 | Int(payload[3])
        guard (flags & 0x8000) != 0 else { return [] } // 仅处理应答
        let qd = Int(payload[4]) << 8 | Int(payload[5])
        let an = Int(payload[6]) << 8 | Int(payload[7])
        guard qd > 0, an > 0, qd < 32, an < 64 else { return [] }
        
        var idx = 12
        var questionName: String?
        for _ in 0..<qd {
            guard let (name, next) = readDNSName(payload, start: idx) else { return [] }
            questionName = name
            idx = next + 4 // type + class
            guard idx <= payload.count else { return [] }
        }
        
        var records: [(ip: String, hostname: String)] = []
        for _ in 0..<an {
            guard let (name, afterName) = readDNSName(payload, start: idx) else { break }
            idx = afterName
            guard idx + 10 <= payload.count else { break }
            let type = Int(payload[idx]) << 8 | Int(payload[idx + 1])
            let rdlen = Int(payload[idx + 8]) << 8 | Int(payload[idx + 9])
            idx += 10
            guard idx + rdlen <= payload.count else { break }
            let owner = name.isEmpty ? (questionName ?? "") : name
            if type == 1, rdlen == 4 { // A
                let ip = "\(payload[idx]).\(payload[idx + 1]).\(payload[idx + 2]).\(payload[idx + 3])"
                if !owner.isEmpty { records.append((ip, owner.lowercased())) }
            } else if type == 28, rdlen == 16 { // AAAA
                let ip = formatIPv6(payload, offset: idx)
                if !owner.isEmpty { records.append((ip, owner.lowercased())) }
            }
            idx += rdlen
        }
        return records
    }
    
    public static func formatIPv6(_ data: Data, offset: Int) -> String {
        guard offset + 16 <= data.count else { return "" }
        var groups: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let v = UInt16(data[offset + i]) << 8 | UInt16(data[offset + i + 1])
            groups.append(String(v, radix: 16))
        }
        return groups.joined(separator: ":")
    }
    
    private static func readDNSName(_ data: Data, start: Int) -> (String, Int)? {
        var idx = start
        var labels: [String] = []
        var jumped = false
        var returnIdx = start
        var hops = 0
        while idx < data.count, hops < 10 {
            let len = Int(data[idx])
            if len == 0 {
                if !jumped { returnIdx = idx + 1 }
                return (labels.joined(separator: "."), returnIdx)
            }
            if (len & 0xC0) == 0xC0 {
                guard idx + 1 < data.count else { return nil }
                let ptr = ((len & 0x3F) << 8) | Int(data[idx + 1])
                if !jumped { returnIdx = idx + 2 }
                idx = ptr
                jumped = true
                hops += 1
                continue
            }
            idx += 1
            guard idx + len <= data.count else { return nil }
            if let label = String(data: data.subdata(in: idx..<(idx + len)), encoding: .utf8) {
                labels.append(label)
            }
            idx += len
            if !jumped { returnIdx = idx }
        }
        return nil
    }
}

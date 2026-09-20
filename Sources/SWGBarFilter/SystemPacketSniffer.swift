//
// SWGBar / macOS 菜单栏 TLS 检查检测器
// 系统网络层出站 HTTPS 实时嗅探器 (SystemPacketSniffer.swift)
// 按 TLS 记录识别 HTTPS（任意 TCP 端口），并用地图 DNS / 连接复用还原域名+真实端口
// 支持物理网卡 (en*) 与 VPN 虚拟网卡 (utun*) 多链路并发嗅探，自适应以太网与 BSD Loopback (DLT_NULL) 封装
//

import Foundation
import SWGBarContracts

public final class SystemPacketSniffer: @unchecked Sendable {
    public static let shared = SystemPacketSniffer()

    private var activeProcesses: [String: Process] = [:]
    private var isRunning = false
    private let lock = NSLock()
    private let flowCache = FlowHostnameCache()
    private var syncTimer: DispatchSourceTimer?

    /// 回调：当在系统网络层捕获到任意应用发起的出站 HTTPS 请求时触发 (hostname, port, remoteIp, egressInterface)
    public var onTargetCaptured: (@Sendable (String, Int, String, String) -> Void)?

    /// 兼容旧版回调 (hostname, remoteIp)
    public var onDomainCaptured: (@Sendable (String, String) -> Void)?

    public init() {}

    /// 动态获取当前系统所有活跃的出站接口（包含物理网卡 en0/en8 与 VPN 虚拟网卡 utun*）
    public static func getActiveInterfaces() -> [String] {
        var results = Set<String>()

        // 1. 首选：向系统路由表查询公网 IP (1.1.1.1) 的实际出口网卡 (如 VPN 开启时的 utun6，或 en0)
        if let iface = queryRouteInterface(target: "1.1.1.1") {
            results.insert(iface)
        }

        // 2. 查询系统默认网关对应的出口网卡 (如 en0, en8)
        if let iface = queryRouteInterface(target: "default") {
            results.insert(iface)
        }

        // 3. 扫描活跃网卡：查找所有持有有效 IPv4 地址且处于 UP 状态的 en* 和 utun* 网卡
        let ifaces = scanActiveInterfacesFromIfconfig()
        for iface in ifaces {
            results.insert(iface)
        }

        // 如果都没查到，默认兜底 en0
        if results.isEmpty {
            results.insert("en0")
        }

        return Array(results).sorted()
    }

    /// 兼容旧接口：返回首选活跃出网网卡
    public static func getDefaultInterface() -> String {
        return getActiveInterfaces().first ?? "en0"
    }

    private static func queryRouteInterface(target: String) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/route")
        task.arguments = ["-n", "get", target]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        guard (try? task.run()) != nil else { return nil }
        task.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let out = String(data: data, encoding: .utf8) else { return nil }
        for line in out.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                let iface = trimmed.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespaces)
                if !iface.isEmpty { return iface }
            }
        }
        return nil
    }

    private static func scanActiveInterfacesFromIfconfig() -> [String] {
        let ifTask = Process()
        ifTask.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        let ifPipe = Pipe()
        ifTask.standardOutput = ifPipe
        ifTask.standardError = Pipe()
        guard (try? ifTask.run()) != nil else { return [] }
        ifTask.waitUntilExit()
        let data = ifPipe.fileHandleForReading.readDataToEndOfFile()
        guard let out = String(data: data, encoding: .utf8) else { return [] }

        var currentIf = ""
        var activeInterfaces: [String] = []
        for line in out.components(separatedBy: .newlines) {
            if !line.hasPrefix("\t") && line.contains(":") {
                currentIf = line.split(separator: ":").first.map(String.init) ?? ""
            } else if line.contains("inet ") && !currentIf.isEmpty {
                let parts = line.split(whereSeparator: { $0.isWhitespace })
                if parts.count >= 2 {
                    let ip = String(parts[1])
                    if !ip.hasPrefix("127.") {
                        // 只纳入物理网卡 (en*) 与 VPN 虚拟网卡 (utun*)
                        if currentIf.hasPrefix("en") || currentIf.hasPrefix("utun") || currentIf.hasPrefix("eth") {
                            activeInterfaces.append(currentIf)
                        }
                    }
                }
            }
        }
        return activeInterfaces
    }

    /// 启动系统层实时出站 HTTPS 监听（多网卡自适应并发）
    public func start() {
        lock.lock()
        defer { lock.unlock() }
        guard !isRunning else { return }
        isRunning = true

        AppLogger.shared.info("Sniffer", "正在初始化 BPF 网络层多网卡实时嗅探器...")
        checkAndSyncInterfacesLocked()
        startInterfaceSyncTimerLocked()
    }

    /// 停止监听所有网卡
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        AppLogger.shared.info("Sniffer", "正在停止系统网络嗅探器...")
        isRunning = false

        syncTimer?.cancel()
        syncTimer = nil

        for (iface, proc) in activeProcesses {
            AppLogger.shared.info("Sniffer", "停止网卡 [\(iface)] 抓包进程 (PID: \(proc.processIdentifier))")
            proc.terminate()
        }
        activeProcesses.removeAll()
    }

    private func startInterfaceSyncTimerLocked() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .background))
        timer.schedule(deadline: .now() + 60.0, repeating: 60.0)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            defer { self.lock.unlock() }
            self.checkAndSyncInterfacesLocked()
        }
        timer.resume()
        self.syncTimer = timer
    }

    private func checkAndSyncInterfacesLocked() {
        guard isRunning else { return }
        let currentCandidates = Set(Self.getActiveInterfaces())
        let existing = Set(activeProcesses.keys)

        // 启动新增网卡的嗅探
        for iface in currentCandidates.subtracting(existing) {
            startSnifferProcessLocked(for: iface)
        }

        // 停止已经失效或移除的网卡
        for iface in existing.subtracting(currentCandidates) {
            stopSnifferProcessLocked(for: iface)
        }
    }

    private func startSnifferProcessLocked(for iface: String) {
        guard activeProcesses[iface] == nil else { return }

        AppLogger.shared.info("Sniffer", "正在为网卡 [\(iface)] 启动 tcpdump 抓包子进程...")

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        // -i: 监听系统出站网卡
        // -n: 不做反向 DNS
        // -s 1500: 截取前 1500 字节
        // -U: 逐包实时刷新缓冲区
        // -w -: 输出标准 pcap 二进制流至 stdout
        // TCP 不按端口过滤：HTTPS 靠 TLS 记录识别，端口以包里的真实目的端口为准。
        // UDP/53 学 DNS；QUIC 无稳定跨端口指纹，只听默认 UDP/443。
        proc.arguments = [
            "-i", iface,
            "-n",
            "-s", "1500",
            "-U",
            "-w", "-",
            "tcp or udp port 53 or udp port 443"
        ]

        let pipe = Pipe()
        proc.standardOutput = pipe
        let errPipe = Pipe()
        proc.standardError = errPipe

        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if let errStr = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !errStr.isEmpty {
                AppLogger.shared.warn("Sniffer", "[\(iface)] tcpdump 警告/输出: \(errStr)")
            }
        }

        proc.terminationHandler = { [weak self] p in
            guard let self = self else { return }
            let code = p.terminationStatus
            if code != 0 {
                AppLogger.shared.warn("Sniffer", "⚠️ [\(iface)] tcpdump 进程退出 (退出码: \(code))")
            } else {
                AppLogger.shared.info("Sniffer", "[\(iface)] tcpdump 抓包进程正常退出。")
            }
            self.lock.lock()
            if self.activeProcesses[iface] === p {
                self.activeProcesses.removeValue(forKey: iface)
            }
            self.lock.unlock()
        }

        do {
            try proc.run()
            self.activeProcesses[iface] = proc
            AppLogger.shared.info("Sniffer", "✅ 网卡 [\(iface)] tcpdump 抓包进程启动成功 (PID: \(proc.processIdentifier))")
        } catch {
            AppLogger.shared.error("Sniffer", "❌ 网卡 [\(iface)] 无法启动 tcpdump 抓包子进程: \(error.localizedDescription)")
            return
        }

        let handle = pipe.fileHandleForReading
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.readPcapLoop(handle: handle, interface: iface)
        }
    }

    private func stopSnifferProcessLocked(for iface: String) {
        if let proc = activeProcesses.removeValue(forKey: iface) {
            AppLogger.shared.info("Sniffer", "正在终止网卡 [\(iface)] 抓包进程 (PID: \(proc.processIdentifier))")
            proc.terminate()
        }
    }

    private func readPcapLoop(handle: FileHandle, interface: String) {
        var streamBuffer = Data()
        var hasReadGlobalHeader = false
        var linkType: UInt32 = 1 // 默认以太网 DLT_EN10MB
        var recentCaptures: [String: TimeInterval] = [:]

        while isRunning {
            let chunk = handle.availableData
            if chunk.isEmpty { break }
            streamBuffer.append(chunk)

            if !hasReadGlobalHeader {
                if streamBuffer.count >= 24 {
                    let dlt = streamBuffer.withUnsafeBytes { ptr -> UInt32 in
                        ptr.load(fromByteOffset: 20, as: UInt32.self)
                    }
                    linkType = dlt
                    streamBuffer.removeSubrange(0..<24)
                    hasReadGlobalHeader = true
                    AppLogger.shared.info("Sniffer", "网卡 [\(interface)] 链路层类型识别: DLT=\(dlt)")
                } else {
                    continue
                }
            }

            while streamBuffer.count >= 16 {
                let caplen = streamBuffer.withUnsafeBytes { ptr -> UInt32 in
                    ptr.load(fromByteOffset: 8, as: UInt32.self)
                }
                guard caplen > 0 && caplen <= 65535 else {
                    streamBuffer.removeAll()
                    break
                }

                let totalPacketLen = 16 + Int(caplen)
                if streamBuffer.count < totalPacketLen {
                    break
                }

                let pktData = streamBuffer.subdata(in: 16..<totalPacketLen)
                streamBuffer.removeSubrange(0..<totalPacketLen)
                handlePacket(pktData, linkType: linkType, interface: interface, recentCaptures: &recentCaptures)
            }
        }
    }

    private func handlePacket(_ pktData: Data, linkType: UInt32, interface: String, recentCaptures: inout [String: TimeInterval]) {
        guard let frame = Self.parseL3L4(pktData, linkType: linkType) else { return }

        if frame.ipProtocol == 17 { // UDP
            if frame.dstPort == 53 || frame.srcPort == 53 {
                for rec in HTTPFlowInspector.parseDNSAddressRecords(from: frame.payload) {
                    flowCache.rememberDNS(ip: rec.ip, hostname: rec.hostname)
                }
            }
            if frame.dstPort != 53, frame.srcPort != 53,
               HTTPFlowInspector.looksLikeQUIC(frame.payload),
               let host = flowCache.hostname(forIP: frame.dstIP) {
                emit(host: host, port: frame.dstPort, dstIP: frame.dstIP, interface: interface, reason: "dns-quic", recentCaptures: &recentCaptures)
            }
            return
        }

        guard frame.ipProtocol == 6 else { return } // TCP
        guard frame.dstPort != 53 else { return }

        if let sni = HTTPFlowInspector.parseTLSServerName(from: frame.payload) {
            let host = sni.lowercased()
            flowCache.rememberFlow(srcIP: frame.srcIP, srcPort: frame.srcPort, dstIP: frame.dstIP, dstPort: frame.dstPort, hostname: host)
            emit(host: host, port: frame.dstPort, dstIP: frame.dstIP, interface: interface, reason: "tls-sni", recentCaptures: &recentCaptures)
            return
        }

        guard HTTPFlowInspector.looksLikeTLSRecord(frame.payload) else { return }

        if let host = flowCache.hostname(srcIP: frame.srcIP, srcPort: frame.srcPort, dstIP: frame.dstIP, dstPort: frame.dstPort)
            ?? flowCache.hostname(forIP: frame.dstIP) {
            // 连接复用或仅有 DNS：目的端口以数据包为准，不假设 443
            emit(host: host, port: frame.dstPort, dstIP: frame.dstIP, interface: interface, reason: "reused-flow", minInterval: 1.0, recentCaptures: &recentCaptures)
        }
        flowCache.pruneIfNeeded()
    }

    private func emit(host: String, port: Int, dstIP: String, interface: String, reason: String, minInterval: TimeInterval = 0.10, recentCaptures: inout [String: TimeInterval]) {
        let normalized = host.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty, (1...65535).contains(port), !DomainNormalizer.isPrivateOrReservedIP(normalized) else { return }
        let targetKey = "\(normalized):\(port)"
        let now = ProcessInfo.processInfo.systemUptime
        if let lastTime = recentCaptures[targetKey], now - lastTime < minInterval {
            return
        }
        recentCaptures[targetKey] = now
        if recentCaptures.count > 500 {
            let cutoff = now - 1.0
            recentCaptures = recentCaptures.filter { $0.value >= cutoff }
        }
        AppLogger.shared.debug("Sniffer", "捕获到出站 HTTPS 请求 \(reason) -> \(targetKey) (目标IP: \(dstIP), 出口网卡: \(interface))")
        onTargetCaptured?(normalized, port, dstIP, interface)
    }

    private struct ParsedFrame {
        let srcIP: String
        let dstIP: String
        let srcPort: Int
        let dstPort: Int
        let ipProtocol: Int
        let payload: Data
    }

    /// 解析以太网/Loopback/Raw IP + IPv4/IPv6 + TCP/UDP
    private static func parseL3L4(_ pktData: Data, linkType: UInt32) -> ParsedFrame? {
        var ipOffset = 0

        switch linkType {
        case 0: // DLT_NULL (BSD Loopback / utun VPN 虚拟网卡 / lo0)
            guard pktData.count >= 24 else { return nil }
            ipOffset = 4
        case 1: // DLT_EN10MB (以太网 / en0, en8 等)
            guard pktData.count >= 14 else { return nil }
            ipOffset = 14
            let ethType = UInt16(pktData[12]) << 8 | UInt16(pktData[13])
            if ethType == 0x8100, pktData.count >= 18 {
                ipOffset = 18
            }
        case 12, 101: // DLT_RAW (纯原始 IP 包)
            ipOffset = 0
        default: // 未知链路层类型，执行自适应嗅探
            if pktData.count >= 14 {
                let ethType = UInt16(pktData[12]) << 8 | UInt16(pktData[13])
                if ethType == 0x0800 || ethType == 0x86DD {
                    ipOffset = 14
                } else if (pktData[4] >> 4) == 4 || (pktData[4] >> 4) == 6 {
                    ipOffset = 4
                } else if (pktData[0] >> 4) == 4 || (pktData[0] >> 4) == 6 {
                    ipOffset = 0
                } else {
                    return nil
                }
            } else if pktData.count >= 20 && ((pktData[0] >> 4) == 4 || (pktData[0] >> 4) == 6) {
                ipOffset = 0
            } else {
                return nil
            }
        }

        guard pktData.count >= ipOffset + 20 else { return nil }
        let ipVersion = pktData[ipOffset] >> 4

        if ipVersion == 4 {
            let ihl = Int(pktData[ipOffset] & 0x0F) * 4
            guard ihl >= 20, pktData.count >= ipOffset + ihl else { return nil }
            let proto = Int(pktData[ipOffset + 9])
            let srcIP = "\(pktData[ipOffset + 12]).\(pktData[ipOffset + 13]).\(pktData[ipOffset + 14]).\(pktData[ipOffset + 15])"
            let dstIP = "\(pktData[ipOffset + 16]).\(pktData[ipOffset + 17]).\(pktData[ipOffset + 18]).\(pktData[ipOffset + 19])"
            return parsePorts(pktData, l4: ipOffset + ihl, proto: proto, srcIP: srcIP, dstIP: dstIP)
        } else if ipVersion == 6 {
            guard pktData.count >= ipOffset + 40 else { return nil }
            let proto = Int(pktData[ipOffset + 6])
            let srcIP = HTTPFlowInspector.formatIPv6(pktData, offset: ipOffset + 8)
            let dstIP = HTTPFlowInspector.formatIPv6(pktData, offset: ipOffset + 24)
            return parsePorts(pktData, l4: ipOffset + 40, proto: proto, srcIP: srcIP, dstIP: dstIP)
        }

        return nil
    }

    private static func parsePorts(_ pktData: Data, l4: Int, proto: Int, srcIP: String, dstIP: String) -> ParsedFrame? {
        guard pktData.count >= l4 + 8 else { return nil }
        if proto == 6 {
            let srcPort = Int(pktData[l4]) << 8 | Int(pktData[l4 + 1])
            let dstPort = Int(pktData[l4 + 2]) << 8 | Int(pktData[l4 + 3])
            let dataOffset = Int((pktData[l4 + 12] >> 4) & 0x0F) * 4
            let payloadOffset = l4 + max(dataOffset, 20)
            let payload = payloadOffset < pktData.count ? pktData.subdata(in: payloadOffset..<pktData.count) : Data()
            return ParsedFrame(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, ipProtocol: proto, payload: payload)
        }
        if proto == 17 {
            let srcPort = Int(pktData[l4]) << 8 | Int(pktData[l4 + 1])
            let dstPort = Int(pktData[l4 + 2]) << 8 | Int(pktData[l4 + 3])
            let payloadOffset = l4 + 8
            let payload = payloadOffset < pktData.count ? pktData.subdata(in: payloadOffset..<pktData.count) : Data()
            return ParsedFrame(srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, ipProtocol: proto, payload: payload)
        }
        return nil
    }
}

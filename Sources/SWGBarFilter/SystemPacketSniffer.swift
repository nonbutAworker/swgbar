//
// SWGBar / macOS menu bar TLS inspection detector
// Live outbound HTTPS metadata capture (SystemPacketSniffer.swift)
// Identify TLS records on any TCP port and recover endpoints using DNS mappings and connection reuse.
// Capture physical and VPN interfaces concurrently, handling Ethernet and BSD loopback encapsulation.
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

    /// Invoke the callback when outbound HTTPS metadata is captured: hostname, port, remoteIp, egressInterface.
    public var onTargetCaptured: (@Sendable (String, Int, String, String) -> Void)?

    /// Compatibility callback: hostname and remoteIp
    public var onDomainCaptured: (@Sendable (String, String) -> Void)?

    public init() {}

    /// Discover active outbound physical and VPN interfaces dynamically.
    public static func getActiveInterfaces() -> [String] {
        var results = Set<String>()

        // 1. Prefer the interface selected by the routing table for 1.1.1.1.
        if let iface = queryRouteInterface(target: "1.1.1.1") {
            results.insert(iface)
        }

        // 2. Query the default gateway's interface.
        if let iface = queryRouteInterface(target: "default") {
            results.insert(iface)
        }

        // 3. Find active en* and utun* interfaces with a valid IPv4 address.
        let ifaces = scanActiveInterfacesFromIfconfig()
        for iface in ifaces {
            results.insert(iface)
        }

        // Fall back to en0 if discovery returns no interfaces.
        if results.isEmpty {
            results.insert("en0")
        }

        return Array(results).sorted()
    }

    /// Compatibility API returning the preferred active outbound interface.
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
                        // Include physical en* and VPN utun* interfaces only.
                        if currentIf.hasPrefix("en") || currentIf.hasPrefix("utun") || currentIf.hasPrefix("eth") {
                            activeInterfaces.append(currentIf)
                        }
                    }
                }
            }
        }
        return activeInterfaces
    }

    /// Start adaptive concurrent HTTPS metadata capture across active interfaces.
    public func start() {
        lock.lock()
        defer { lock.unlock() }
        guard !isRunning else { return }
        isRunning = true

        AppLogger.shared.info("Sniffer", "Initializing BPF capture across active interfaces...")
        checkAndSyncInterfacesLocked()
        startInterfaceSyncTimerLocked()
    }

    /// Stop capture on all interfaces.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        AppLogger.shared.info("Sniffer", "Stopping network capture...")
        isRunning = false

        syncTimer?.cancel()
        syncTimer = nil

        for (iface, proc) in activeProcesses {
            AppLogger.shared.info("Sniffer", "Stopping capture on interface [\(iface)] (PID: \(proc.processIdentifier))")
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

        // Start capture on newly discovered interfaces.
        for iface in currentCandidates.subtracting(existing) {
            startSnifferProcessLocked(for: iface)
        }

        // Stop capture on interfaces that are no longer available.
        for iface in existing.subtracting(currentCandidates) {
            stopSnifferProcessLocked(for: iface)
        }
    }

    private func startSnifferProcessLocked(for iface: String) {
        guard activeProcesses[iface] == nil else { return }

        AppLogger.shared.info("Sniffer", "Starting tcpdump capture on interface [\(iface)]...")

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        // -i: select the outbound interface.
        // -n: disable reverse DNS lookup.
        // -s 1500: capture the first 1,500 bytes of each packet.
        // -U: flush packets immediately.
        // -w -: write the binary pcap stream to standard output.
        // Do not filter TCP by port: detect TLS records and use each packet's actual destination port.
        // Learn DNS on UDP/53; observe QUIC on its default UDP/443 port.
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
                AppLogger.shared.warn("Sniffer", "[\(iface)] tcpdump warning/output: \(errStr)")
            }
        }

        proc.terminationHandler = { [weak self] p in
            guard let self = self else { return }
            let code = p.terminationStatus
            if code != 0 {
                AppLogger.shared.warn("Sniffer", "⚠️ [\(iface)] tcpdump exited (status: \(code))")
            } else {
                AppLogger.shared.info("Sniffer", "[\(iface)] tcpdump capture process exited normally.")
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
            AppLogger.shared.info("Sniffer", "✅ Interface [\(iface)] tcpdump capture started (PID: \(proc.processIdentifier))")
        } catch {
            AppLogger.shared.error("Sniffer", "❌ Interface [\(iface)] could not start tcpdump capture: \(error.localizedDescription)")
            return
        }

        let handle = pipe.fileHandleForReading
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.readPcapLoop(handle: handle, interface: iface)
        }
    }

    private func stopSnifferProcessLocked(for iface: String) {
        if let proc = activeProcesses.removeValue(forKey: iface) {
            AppLogger.shared.info("Sniffer", "Terminating capture on interface [\(iface)] (PID: \(proc.processIdentifier))")
            proc.terminate()
        }
    }

    private func readPcapLoop(handle: FileHandle, interface: String) {
        var streamBuffer = Data()
        var hasReadGlobalHeader = false
        var linkType: UInt32 = 1 // Default to Ethernet (DLT_EN10MB).
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
                    AppLogger.shared.info("Sniffer", "Interface [\(interface)] link-layer type: DLT=\(dlt)")
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
            // For reused connections or DNS-only evidence, use the packet's actual port instead of assuming 443.
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
        AppLogger.shared.debug("Sniffer", "Captured outbound HTTPS \(reason) -> \(targetKey) (destination IP: \(dstIP), interface: \(interface))")
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

    /// Parse Ethernet, loopback, or raw IP frames followed by IPv4/IPv6 and TCP/UDP.
    private static func parseL3L4(_ pktData: Data, linkType: UInt32) -> ParsedFrame? {
        var ipOffset = 0

        switch linkType {
        case 0: // DLT_NULL: BSD loopback, utun VPN interfaces, and lo0
            guard pktData.count >= 24 else { return nil }
            ipOffset = 4
        case 1: // DLT_EN10MB: Ethernet interfaces such as en0 and en8
            guard pktData.count >= 14 else { return nil }
            ipOffset = 14
            let ethType = UInt16(pktData[12]) << 8 | UInt16(pktData[13])
            if ethType == 0x8100, pktData.count >= 18 {
                ipOffset = 18
            }
        case 12, 101: // DLT_RAW: raw IP packets
            ipOffset = 0
        default: // Attempt adaptive parsing for an unknown link-layer type.
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

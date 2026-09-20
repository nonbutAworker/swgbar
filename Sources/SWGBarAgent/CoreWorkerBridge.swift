//
// SWGBar / macOS menu bar TLS inspection detector
// Go CoreWorker bridge and probe dispatch (CoreWorkerBridge.swift)
// Bidirectional IPC with native trust callbacks and deadlock prevention.
//

import Foundation
import SWGBarContracts

public struct ProbeExecutionResult: Sendable {
    public let host: String
    public let port: Int
    public let remoteIp: String
    public let routeType: String
    public let handshakeCompleted: Bool
    public let presentedCertIds: [String]
    public let presentedSpkiIds: [String]
    public let presentedDers: [Data]
    public let caSubjects: [String]
    public let issuers: [String]
    public let notBeforeMs: [Int64]
    public let notAfterMs: [Int64]
    public let nativeAccepted: Bool
    public let publicPkixPassed: Bool
    public let isExtraAnchor: Bool
    public let extraAnchorSubject: String?
    public let durationMs: Int64
    public let errorCode: String?
    public let errorMessage: String?
    
    public init(
        host: String,
        port: Int,
        remoteIp: String,
        routeType: String = "DIRECT",
        handshakeCompleted: Bool,
        presentedCertIds: [String] = [],
        presentedSpkiIds: [String] = [],
        presentedDers: [Data] = [],
        caSubjects: [String] = [],
        issuers: [String] = [],
        notBeforeMs: [Int64] = [],
        notAfterMs: [Int64] = [],
        nativeAccepted: Bool = false,
        publicPkixPassed: Bool = false,
        isExtraAnchor: Bool = false,
        extraAnchorSubject: String? = nil,
        durationMs: Int64 = 0,
        errorCode: String? = nil,
        errorMessage: String? = nil
    ) {
        self.host = host
        self.port = port
        self.remoteIp = remoteIp
        self.routeType = routeType
        self.handshakeCompleted = handshakeCompleted
        self.presentedCertIds = presentedCertIds
        self.presentedSpkiIds = presentedSpkiIds
        self.presentedDers = presentedDers
        self.caSubjects = caSubjects
        self.issuers = issuers
        self.notBeforeMs = notBeforeMs
        self.notAfterMs = notAfterMs
        self.nativeAccepted = nativeAccepted
        self.publicPkixPassed = publicPkixPassed
        self.isExtraAnchor = isExtraAnchor
        self.extraAnchorSubject = extraAnchorSubject
        self.durationMs = durationMs
        self.errorCode = errorCode
        self.errorMessage = errorMessage
    }
}

public final class CoreWorkerBridge: @unchecked Sendable {
    public static let shared = CoreWorkerBridge()
    
    private var process: Process?
    private var stdinPipe: Pipe?
    private var stdoutPipe: Pipe?
    private let lock = NSLock()
    private var pendingProbes: [String: CheckedContinuation<ProbeExecutionResult, Never>] = [:]
    
    public init() {}
    
    /// Execute one independent IPv4 probe.
    public func executeProbe(
        host: String,
        port: Int = 443,
        route: String = "DIRECT",
        proxyEndpoint: String? = nil,
        allowPrivate: Bool = false,
        deadlineMs: Int64 = 8000
    ) async -> ProbeExecutionResult {
        let reqId = UUID().uuidString
        
        // Use the external Go CoreWorker process for the network probe.
        if let binaryPath = findCoreWorkerBinary() {
            return await executeViaGoWorker(
                binaryPath: binaryPath,
                requestId: reqId,
                host: host,
                port: port,
                route: route,
                proxyEndpoint: proxyEndpoint,
                allowPrivate: allowPrivate,
                deadlineMs: deadlineMs
            )
        }
        
        return ProbeExecutionResult(
            host: host, port: port, remoteIp: "",
            handshakeCompleted: false,
            errorCode: "WORKER_NOT_FOUND",
            errorMessage: "CoreWorker was not found. Reinstall the complete application to run TLS probes."
        )
    }
    
    private func findCoreWorkerBinary() -> String? {
        let candidates = [
            Bundle.main.bundlePath + "/Contents/MacOS/coreworker",
            FileManager.default.currentDirectoryPath + "/build/coreworker",
            FileManager.default.currentDirectoryPath + "/coreworker/coreworker"
        ]
        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }
    
    private func ensureWorkerRunning(binaryPath: String) throws {
        lock.lock()
        defer { lock.unlock() }
        
        if let proc = process, proc.isRunning {
            return
        }
        
        // Release resources from the previous process.
        process?.terminate()
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
        
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binaryPath)
        let inPipe = Pipe()
        let outPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        
        AppLogger.shared.info("CoreWorker", "Starting the persistent Go CoreWorker probe process (\(binaryPath))...")
        try proc.run()
        self.process = proc
        self.stdinPipe = inPipe
        self.stdoutPipe = outPipe
        AppLogger.shared.info("CoreWorker", "✅ Go CoreWorker process is ready (PID: \(proc.processIdentifier))")
        
        let handle = outPipe.fileHandleForReading
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.readWorkerStdoutLoop(handle: handle)
        }
    }
    
    private func sendRawDataToWorker(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        try? stdinPipe?.fileHandleForWriting.write(contentsOf: data)
    }
    
    private func readWorkerStdoutLoop(handle: FileHandle) {
        var buffer = Data()
        while true {
            let chunk = handle.availableData
            if chunk.isEmpty {
                break
            }
            buffer.append(chunk)
            
            while let newlineRange = buffer.range(of: Data([0x0A])) {
                let lineData = buffer.subdata(in: buffer.startIndex..<newlineRange.lowerBound)
                buffer.removeSubrange(buffer.startIndex...newlineRange.lowerBound)
                
                guard let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any],
                      let method = obj["method"] as? String,
                      let reqId = obj["request_id"] as? String else {
                    continue
                }
                
                if method == "native_trust.evaluate" {
                    // Handle a macOS SecTrust validation callback from CoreWorker.
                    let h = obj["host"] as? String ?? ""
                    var ders: [Data] = []
                    if let b64s = obj["der_chain_base64"] as? [String] {
                        for b in b64s {
                            if let d = Data(base64Encoded: b) { ders.append(d) }
                        }
                    }
                    
                    let evalResult = NativeTrustEvaluator.shared.evaluate(host: h, peerCertsDER: ders)
                    let respObj: [String: Any] = [
                        "request_id": reqId,
                        "method": "native_trust.response",
                        "accepted": evalResult.accepted,
                        "errors": evalResult.errors,
                        "is_extra_trust_anchor": evalResult.isExtraTrustAnchor,
                        "extra_anchor_subject": evalResult.extraAnchorSubject ?? "",
                        "native_result": [
                            "accepted": evalResult.accepted,
                            "errors": evalResult.errors,
                            "is_extra_trust_anchor": evalResult.isExtraTrustAnchor,
                            "extra_anchor_subject": evalResult.extraAnchorSubject ?? ""
                        ]
                    ]
                    if let respData = try? JSONSerialization.data(withJSONObject: respObj),
                       var respStr = String(data: respData, encoding: .utf8) {
                        respStr.append("\n")
                        sendRawDataToWorker(Data(respStr.utf8))
                    }
                    
                } else if method == "probe.result" {
                    // Decode probe.result and resume the continuation for its request_id.
                    let outcomeRes = parseProbeResult(obj: obj)
                    lock.lock()
                    let cont = pendingProbes.removeValue(forKey: reqId)
                    lock.unlock()
                    cont?.resume(returning: outcomeRes)
                }
            }
        }
        
        // Resume all pending requests when the worker exits.
        lock.lock()
        let pendings = pendingProbes
        pendingProbes.removeAll()
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
        lock.unlock()
        
        for (_, cont) in pendings {
            cont.resume(returning: ProbeExecutionResult(
                host: "unknown", port: 443, remoteIp: "",
                handshakeCompleted: false, errorCode: "WORKER_DISCONNECTED", errorMessage: "CoreWorker process exited"
            ))
        }
    }
    
    private func parseProbeResult(obj: [String: Any]) -> ProbeExecutionResult {
        var outcomeRes = ProbeExecutionResult(
            host: "unknown", port: 443, remoteIp: "",
            handshakeCompleted: false
        )
        
        if let outcome = obj["outcome"] as? [String: Any] {
            let host = outcome["target_host"] as? String ?? ""
            let port = outcome["target_port"] as? Int ?? 443
            let route = outcome["route_type"] as? String ?? "DIRECT"
            let completed = outcome["handshake_completed"] as? Bool ?? false
            let duration = (outcome["duration_ms"] as? NSNumber)?.int64Value ?? 0
            let rIP = outcome["remote_ip"] as? String ?? ""
            let pChain = outcome["presented_chain_ids"] as? [String] ?? []
            let errCode = outcome["error_code"] as? String
            let errMsg = outcome["error_message"] as? String
            
            var certIds: [String] = []
            var spkiIds: [String] = []
            var subjects: [String] = []
            var issuers: [String] = []
            var notBefores: [Int64] = []
            var notAfters: [Int64] = []
            var ders: [Data] = []
            
            if let certs = outcome["presented_certs"] as? [[String: Any]] {
                for c in certs {
                    if let cId = c["cert_id"] as? String { certIds.append(cId) }
                    if let sId = c["spki_id"] as? String { spkiIds.append(sId) }
                    if let subj = c["subject"] as? String { subjects.append(subj) }
                    if let iss = c["issuer"] as? String { issuers.append(iss) }
                    let nb = (c["not_before_ms"] as? NSNumber)?.int64Value ?? 0
                    let na = (c["not_after_ms"] as? NSNumber)?.int64Value ?? 0
                    notBefores.append(nb)
                    notAfters.append(na)
                    if let b64 = c["der_base64"] as? String, let d = Data(base64Encoded: b64) {
                        ders.append(d)
                    }
                }
            }
            
            var pkixPassed = false
            if let pkix = outcome["public_pkix_result"] as? [String: Any] {
                pkixPassed = pkix["passed"] as? Bool ?? false
            }
            
            var nativePass = false
            var extraAnchor = false
            var extraSubject: String? = nil
            if let nat = outcome["native_trust_result"] as? [String: Any] {
                nativePass = nat["accepted"] as? Bool ?? false
                extraAnchor = nat["is_extra_trust_anchor"] as? Bool ?? false
                extraSubject = nat["extra_anchor_subject"] as? String
            }
            
            outcomeRes = ProbeExecutionResult(
                host: host,
                port: port,
                remoteIp: rIP,
                routeType: route,
                handshakeCompleted: completed,
                presentedCertIds: certIds.isEmpty ? pChain : certIds,
                presentedSpkiIds: spkiIds,
                presentedDers: ders,
                caSubjects: subjects,
                issuers: issuers,
                notBeforeMs: notBefores,
                notAfterMs: notAfters,
                nativeAccepted: nativePass,
                publicPkixPassed: pkixPassed,
                isExtraAnchor: extraAnchor,
                extraAnchorSubject: extraSubject,
                durationMs: duration,
                errorCode: errCode,
                errorMessage: errMsg
            )
        }
        return outcomeRes
    }
    
    private func executeViaGoWorker(
        binaryPath: String,
        requestId: String,
        host: String,
        port: Int,
        route: String,
        proxyEndpoint: String?,
        allowPrivate: Bool,
        deadlineMs: Int64
    ) async -> ProbeExecutionResult {
        do {
            try ensureWorkerRunning(binaryPath: binaryPath)
        } catch {
            return ProbeExecutionResult(
                host: host, port: port, remoteIp: "",
                handshakeCompleted: false, errorCode: "WORKER_SPAWN_FAILED", errorMessage: error.localizedDescription
            )
        }
        
        var reqDict: [String: Any] = [
            "request_id": requestId,
            "method": "probe.start",
            "host": host,
            "port": port,
            "route": route,
            "allow_private": allowPrivate,
            "deadline_ms": deadlineMs
        ]
        if let pe = proxyEndpoint { reqDict["proxy_endpoint"] = pe }
        
        guard let jsonData = try? JSONSerialization.data(withJSONObject: reqDict),
              var jsonStr = String(data: jsonData, encoding: .utf8) else {
            return ProbeExecutionResult(
                host: host, port: port, remoteIp: "",
                handshakeCompleted: false, errorCode: "ENCODE_FAILED", errorMessage: "Failed to serialize request"
            )
        }
        jsonStr.append("\n")
        let bytes = Data(jsonStr.utf8)
        
        let res = await withCheckedContinuation { continuation in
            lock.lock()
            pendingProbes[requestId] = continuation
            lock.unlock()
            
            sendRawDataToWorker(bytes)
        }
        AppLogger.shared.info("Probe", "Probe result host=\(host):\(port) -> IP=\(res.remoteIp), handshake=\(res.handshakeCompleted ? "succeeded" : "failed"), duration=\(res.durationMs)ms, root CA=\(res.caSubjects.last ?? (res.caSubjects.first ?? "None")), ExtraAnchor=\(res.isExtraAnchor ? "yes [\(res.extraAnchorSubject ?? "")]" : "no"), PublicPKIX=\(res.publicPkixPassed ? "passed" : "failed"), NativeSecTrust=\(res.nativeAccepted ? "trusted" : "untrusted")")
        return res
    }
    
    /// Terminate the persistent CoreWorker process gracefully.
    public func terminate() {
        lock.lock()
        defer { lock.unlock() }
        process?.terminate()
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
    }
    
    deinit {
        terminate()
    }
    
}

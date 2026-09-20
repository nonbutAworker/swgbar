import XCTest
@testable import SWGBarFilter

final class HTTPFlowInspectorTests: XCTestCase {
    func testLooksLikeTLSRecordIsPortAgnostic() {
        let hello = makeClientHello(sni: "chat.deepseek.com")
        XCTAssertTrue(HTTPFlowInspector.looksLikeTLSRecord(hello))
        XCTAssertTrue(HTTPFlowInspector.looksLikeTLSRecord(Data([0x17, 0x03, 0x03, 0x00, 0x10])))
        XCTAssertFalse(HTTPFlowInspector.looksLikeTLSRecord(Data("GET / HTTP/1.1\r\nHost: x\r\n\r\n".utf8)))
        XCTAssertFalse(HTTPFlowInspector.looksLikeQUIC(Data([0x00, 0x00, 0x00, 0x00, 0x00])))
        XCTAssertTrue(HTTPFlowInspector.looksLikeQUIC(Data([0xC0, 0x00, 0x00, 0x00, 0x01])))
    }
    
    func testParseTLSServerNameFromClientHello() {
        let hello = makeClientHello(sni: "chat.deepseek.com")
        XCTAssertEqual(HTTPFlowInspector.parseTLSServerName(from: hello), "chat.deepseek.com")
        XCTAssertNil(HTTPFlowInspector.parseTLSServerName(from: Data([0x17, 0x03, 0x03, 0x00, 0x10])))
    }
    
    func testReusedConnectionResolvesFromFlowCache() {
        let cache = FlowHostnameCache()
        cache.rememberFlow(
            srcIP: "192.168.1.8", srcPort: 51234,
            dstIP: "1.2.3.4", dstPort: 443,
            hostname: "chat.deepseek.com"
        )
        XCTAssertEqual(
            cache.hostname(srcIP: "192.168.1.8", srcPort: 51234, dstIP: "1.2.3.4", dstPort: 443),
            "chat.deepseek.com"
        )
        cache.rememberDNS(ip: "1.2.3.4", hostname: "chat.deepseek.com")
        XCTAssertEqual(cache.hostname(forIP: "1.2.3.4"), "chat.deepseek.com")
        XCTAssertEqual(
            cache.hostname(srcIP: "192.168.1.8", srcPort: 60001, dstIP: "1.2.3.4", dstPort: 443),
            "chat.deepseek.com"
        )
    }
    
    func testParseDNSAddressRecords() {
        // 手工构造最小 DNS 应答：question chat.deepseek.com A，answer 1.2.3.4
        var dns = Data()
        dns.append(contentsOf: [0x12, 0x34]) // id
        dns.append(contentsOf: [0x81, 0x80]) // response
        dns.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
        for label in ["chat", "deepseek", "com"] {
            dns.append(UInt8(label.utf8.count))
            dns.append(contentsOf: label.utf8)
        }
        dns.append(0x00)
        dns.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A IN
        dns.append(contentsOf: [0xC0, 0x0C]) // pointer to question name
        dns.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        dns.append(contentsOf: [0x00, 0x00, 0x00, 0x3C])
        dns.append(contentsOf: [0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        
        let records = HTTPFlowInspector.parseDNSAddressRecords(from: dns)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?.ip, "1.2.3.4")
        XCTAssertEqual(records.first?.hostname, "chat.deepseek.com")
    }
    
    private func makeClientHello(sni: String) -> Data {
        let sniBytes = Array(sni.utf8)
        var extBody: [UInt8] = []
        extBody += [0x00, 0x00] // SNI ext type
        let listLen = 3 + sniBytes.count
        let extLen = 2 + listLen
        extBody += [UInt8(extLen >> 8), UInt8(extLen & 0xFF)]
        extBody += [UInt8(listLen >> 8), UInt8(listLen & 0xFF)]
        extBody += [0x00]
        extBody += [UInt8(sniBytes.count >> 8), UInt8(sniBytes.count & 0xFF)]
        extBody += sniBytes
        
        var body: [UInt8] = []
        body += [0x03, 0x03] + Array(repeating: 0x11, count: 32) // ver + random
        body += [0x00] // session
        body += [0x00, 0x02, 0x00, 0x2F] // cipher
        body += [0x01, 0x00] // compression
        body += [UInt8(extBody.count >> 8), UInt8(extBody.count & 0xFF)]
        body += extBody
        
        var hs: [UInt8] = [0x01]
        let hsLen = body.count
        hs += [UInt8((hsLen >> 16) & 0xFF), UInt8((hsLen >> 8) & 0xFF), UInt8(hsLen & 0xFF)]
        hs += body
        
        var rec: [UInt8] = [0x16, 0x03, 0x01]
        rec += [UInt8(hs.count >> 8), UInt8(hs.count & 0xFF)]
        rec += hs
        return Data(rec)
    }
}

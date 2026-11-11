import Foundation
import Network

// Checking a relay server from this Mac: DNS, HTTPS, STUN. Parsing and
// linting the DERP map are in DERP.swift.

// MARK: - Live check

struct DERPCheckStep: Identifiable {
    var name: String
    var ok: Bool
    var detail: String
    var id: String { name }
}

/// DNS, HTTPS (/derp/probe, which also checks the certificate) and STUN.
func checkDERPNode(_ n: DERPNode) async -> [DERPCheckStep] {
    var steps: [DERPCheckStep] = []
    let resolved = await resolveIPv4(n.hostName)
    if resolved.isEmpty {
        steps.append(.init(name: "DNS", ok: n.fixedIPv4 != nil,
                           detail: n.fixedIPv4 == nil ? "\(n.hostName) doesn't resolve." : "\(n.hostName) doesn't resolve; clients use \(n.fixedIPv4!) from the policy."))
    } else if let fixed = n.fixedIPv4, !resolved.contains(fixed) {
        steps.append(.init(name: "DNS", ok: false,
                           detail: "\(n.hostName) resolves to \(resolved.joined(separator: ", ")), but the policy says \(fixed)."))
    } else {
        steps.append(.init(name: "DNS", ok: true, detail: "\(n.hostName) → \(resolved.joined(separator: ", "))"))
    }

    if !n.stunOnly {
        let url = URL(string: "https://\(n.hostName)\(n.httpsPort == 443 ? "" : ":\(n.httpsPort)")/derp/probe")
        var req = url.map { URLRequest(url: $0, timeoutInterval: 8) }
        req?.httpMethod = "GET"
        do {
            guard let req else { throw URLError(.badURL) }
            let (_, response) = try await URLSession(configuration: .ephemeral).data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            steps.append(.init(name: "HTTPS", ok: status == 200,
                               detail: status == 200 ? "DERP answers on port \(n.httpsPort), certificate valid." : "Port \(n.httpsPort) answered HTTP \(status), not a DERP server."))
        } catch {
            steps.append(.init(name: "HTTPS", ok: false, detail: "Port \(n.httpsPort): \(error.localizedDescription)"))
        }
    }

    if let port = n.stunPortUsed {
        let host = n.fixedIPv4 ?? n.hostName
        let ok = await stunProbe(host: host, port: port)
        steps.append(.init(name: "STUN", ok: ok,
                           detail: ok ? "UDP \(port) answers." : "No STUN answer on UDP \(port) within 3 s (blocked by a firewall?)."))
    }
    return steps
}

private func resolveIPv4(_ host: String) async -> [String] {
    await Task.detached {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard !host.isEmpty, getaddrinfo(host, nil, &hints, &result) == 0 else { return [String]() }
        defer { freeaddrinfo(result) }
        var out: [String] = []
        var p = result
        while let info = p {
            if let addr = info.pointee.ai_addr {
                var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
                out.append(String(cString: buf))
            }
            p = info.pointee.ai_next
        }
        return out.uniqued()
    }.value
}

/// A STUN binding request (RFC 5389) the way Tailscale sends it: DERP
/// servers ignore requests without SOFTWARE "tailnode" and a FINGERPRINT.
func stunBindingRequest(transactionID: [UInt8]) -> Data {
    var b: [UInt8] = [0x00, 0x01, 0x00, 20, 0x21, 0x12, 0xA4, 0x42] + transactionID
    b += [0x80, 0x22, 0x00, 0x08] + Array("tailnode".utf8)
    let fp = crc32(b) ^ 0x5354_554E
    b += [0x80, 0x28, 0x00, 0x04, UInt8(fp >> 24), UInt8(fp >> 16 & 0xFF), UInt8(fp >> 8 & 0xFF), UInt8(fp & 0xFF)]
    return Data(b)
}

/// CRC-32 (IEEE), as STUN fingerprints use.
func crc32(_ bytes: [UInt8]) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in bytes {
        crc ^= UInt32(byte)
        for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
    }
    return ~crc
}

/// A binding success response (0x0101) to our transaction.
func isSTUNBindingSuccess(_ data: Data, transactionID: [UInt8]) -> Bool {
    let b = [UInt8](data)
    return b.count >= 20 && b[0] == 0x01 && b[1] == 0x01
        && b[4...7].elementsEqual([0x21, 0x12, 0xA4, 0x42]) && b[8..<20].elementsEqual(transactionID)
}

private func stunProbe(host: String, port: Int) async -> Bool {
    guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return false }
    let txID = (0..<12).map { _ in UInt8.random(in: 0...255) }
    let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
    let queue = DispatchQueue(label: "stun-probe")
    return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
        var done = false
        func finish(_ ok: Bool) {   // always on `queue`
            guard !done else { return }
            done = true
            conn.cancel()
            cont.resume(returning: ok)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: stunBindingRequest(transactionID: txID), completion: .contentProcessed { _ in })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.map { isSTUNBindingSuccess($0, transactionID: txID) } ?? false)
                }
            case .failed, .cancelled:
                finish(false)
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3) { finish(false) }
    }
}

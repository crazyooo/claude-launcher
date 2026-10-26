import Foundation

enum RouterTCPEchoError: String, Error {
    case malformed, wrongNonce, ioFailed, eof
}

/// Small fixture protocol. A peer's address claim is not authenticated egress evidence.
enum RouterTCPEchoWire {
    static let maximumBody = 512

    struct Reply {
        let nonce: UUID
        let serverReportedPeerIP: String
    }
    private struct Request: Codable {
        let version: Int
        let nonce: String
    }
    private struct Response: Codable {
        let version: Int
        let nonce: String
        let peerIP: String
    }

    static func framed(_ body: Data) throws -> Data {
        guard (1...maximumBody).contains(body.count) else { throw RouterTCPEchoError.malformed }
        let length = UInt32(body.count)
        let prefix = (0..<4).reversed().map { UInt8(truncatingIfNeeded: length >> ($0 * 8)) }
        return Data(prefix) + body
    }

    static func bodyLength(_ prefix: Data) throws -> Int {
        guard prefix.count == 4 else { throw RouterTCPEchoError.malformed }
        let length = prefix.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard (1...UInt32(maximumBody)).contains(length) else { throw RouterTCPEchoError.malformed }
        return Int(length)
    }

    static func request(_ nonce: UUID) throws -> Data {
        try framed(JSONEncoder().encode(Request(version: 1, nonce: nonce.uuidString.lowercased())))
    }

    /// The fixture server supplies the address observed on its accepted socket.
    static func response(_ nonce: UUID, actualPeerIP: String) throws -> Data {
        guard validPeerIP(actualPeerIP) else { throw RouterTCPEchoError.malformed }
        return try framed(JSONEncoder().encode(Response(version: 1, nonce: nonce.uuidString.lowercased(),
                                                        peerIP: actualPeerIP)))
    }

    static func parseRequest(_ body: Data) throws -> UUID {
        do {
            try requireKeys(body, ["version", "nonce"])
            let request = try JSONDecoder().decode(Request.self, from: body)
            guard request.version == 1 else { throw RouterTCPEchoError.malformed }
            return try canonicalNonce(request.nonce)
        } catch { throw RouterTCPEchoError.malformed }
    }

    static func parseResponse(_ body: Data, expected: UUID) throws -> Reply {
        let response: Response
        let nonce: UUID
        do {
            try requireKeys(body, ["version", "nonce", "peerIP"])
            response = try JSONDecoder().decode(Response.self, from: body)
            guard response.version == 1, validPeerIP(response.peerIP) else {
                throw RouterTCPEchoError.malformed
            }
            nonce = try canonicalNonce(response.nonce)
        } catch { throw RouterTCPEchoError.malformed }
        guard nonce == expected else { throw RouterTCPEchoError.wrongNonce }
        return .init(nonce: nonce, serverReportedPeerIP: response.peerIP)
    }

    private static func requireKeys(_ body: Data, _ keys: Set<String>) throws {
        let object = try RouterStrictJSON.object(body, maximumBytes: maximumBody, maximumValues: 10)
        guard Set(object.keys) == keys else { throw RouterTCPEchoError.malformed }
        // JSON numeric 1.0 is accepted as the integer value 1; booleans and strings are not.
    }
    private static func canonicalNonce(_ value: String) throws -> UUID {
        guard let nonce = UUID(uuidString: value), nonce.uuidString.lowercased() == value else {
            throw RouterTCPEchoError.malformed
        }
        return nonce
    }
    private static func validPeerIP(_ value: String) -> Bool {
        // Darwin inet_pton can accept a scope suffix; the wire protocol has no scope field.
        !value.contains("%") && RouterTrafficAddress.bytes(value) != nil
    }
}

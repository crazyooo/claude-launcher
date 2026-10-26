import Foundation
import CoreFoundation

/// Pinned v1.19.32 effective declaration, not a certificate of OS routing or traffic.
struct RouterSystemControllerDeclaration: Equatable {
    let device: String?
    let generalIPv6Enabled: Bool
    let tunIPv6Configured: Bool
    let addresses: [String]
    let effectiveMTU: Int

    static func version(_ data: Data) throws {
        let fields = Fields(try RouterStrictJSON.object(data, maximumBytes: 65_536))
        guard try fields.bool("meta"), try fields.string("version") == "v" + RouterCoreRelease.version else {
            throw RouterSystemError.configurationRejected
        }
    }

    static func parse(_ data: Data) throws -> Self {
        let object = try RouterStrictJSON.object(data, maximumBytes: 65_536)
        let general = Fields(object)
        for key in ["port", "socks-port", "mixed-port", "redir-port", "tproxy-port", "routing-mark"] {
            guard try general.number(key) == 0 else { throw RouterSystemError.configurationRejected }
        }
        guard try general.string("mode") == "rule", try general.string("find-process-mode") == "strict",
              try !general.bool("allow-lan"), try general.string("bind-address") == "127.0.0.1",
              try general.string("interface-name").isEmpty,
              let tunObject = object["tun"] as? [String: Any] else { throw RouterSystemError.configurationRejected }
        let tun = Fields(tunObject), generalIPv6 = try general.bool("ipv6")
        // The pinned core's system check clears TUN addresses, never General.IPv6.
        guard generalIPv6 else { throw RouterSystemError.configurationRejected }
        let enabled = try tun.bool("enable"), device = try tun.string("device")
        guard try tun.string("stack") == "Mixed", try tun.bool("auto-route"), try tun.bool("auto-detect-interface"),
              try tun.number("file-descriptor") == 0,
              try tun.strings("dns-hijack").sorted() == ["any:53", "tcp://any:53"] else {
            throw RouterSystemError.configurationRejected
        }
        for key in ["auto-redirect", "strict-route", "gso", "endpoint-independent-nat", "disable-icmp-forwarding"] {
            guard try !tun.bool(key, default: false) else { throw RouterSystemError.configurationRejected }
        }
        // The compiler does not emit restrictions. A nonempty one changes capture scope.
        for key in ["loopback-address", "route-address", "route-address-set", "route-exclude-address",
                    "route-exclude-address-set", "include-interface", "exclude-interface", "include-uid-range",
                    "exclude-uid-range", "exclude-src-port-range", "exclude-dst-port-range", "include-package",
                    "exclude-package", "include-mac-address", "exclude-mac-address", "inet4-route-address",
                    "inet6-route-address", "inet4-route-exclude-address", "inet6-route-exclude-address",
                    "include-uid", "exclude-uid", "exclude-src-port", "exclude-dst-port", "include-android-user"] {
            if let raw = tunObject[key] {
                guard let array = raw as? [Any], array.isEmpty else { throw RouterSystemError.configurationRejected }
            }
        }
        let ipv4 = try tun.strings("inet4-address", default: [])
        let ipv6 = try tun.strings("inet6-address", default: [])
        guard ipv4 == ["198.18.0.1/30"], ipv6.isEmpty || ipv6 == [RouterSystemCompiler.tunIPv6],
              generalIPv6 || ipv6.isEmpty else { throw RouterSystemError.configurationRejected }
        let mtu = try tun.number("mtu", default: 0)
        guard mtu == 0 || mtu == 9000 else { throw RouterSystemError.configurationRejected }
        if !device.isEmpty {
            guard device.hasPrefix("utun"), RouterSystemInterfaceSnapshot.validName(device) else {
                throw RouterSystemError.configurationRejected
            }
            let suffix = String(device.dropFirst(4))
            guard let number = UInt16(suffix), number <= 32767, String(number) == suffix else {
                throw RouterSystemError.configurationRejected
            }
        }
        // With empty source device and FD=0, LastTunConf has no assigned device.
        // General IPv6 can stay true even when the system check clears TUN IPv6.
        return .init(device: enabled && !device.isEmpty ? device : nil, generalIPv6Enabled: generalIPv6,
                     tunIPv6Configured: !ipv6.isEmpty, addresses: ipv4 + ipv6, effectiveMTU: 9000)
    }

    private struct Fields {
        let values: [String: Any]
        init(_ values: [String: Any]) { self.values = values }
        func string(_ key: String) throws -> String {
            guard let text = values[key] as? String else { throw RouterSystemError.configurationRejected }
            return text
        }
        func strings(_ key: String, default fallback: [String]? = nil) throws -> [String] {
            guard let raw = values[key] else {
                guard let fallback else { throw RouterSystemError.configurationRejected }; return fallback
            }
            guard let values = raw as? [String] else { throw RouterSystemError.configurationRejected }
            return values
        }
        func bool(_ key: String, default fallback: Bool? = nil) throws -> Bool {
            guard let raw = values[key] else {
                guard let fallback else { throw RouterSystemError.configurationRejected }; return fallback
            }
            guard let value = raw as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else {
                throw RouterSystemError.configurationRejected
            }
            return value.boolValue
        }
        func number(_ key: String, default fallback: UInt32? = nil) throws -> UInt32 {
            guard let raw = values[key] else {
                guard let fallback else { throw RouterSystemError.configurationRejected }; return fallback
            }
            guard let value = raw as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
                  value.doubleValue.isFinite, value.doubleValue >= 0, value.doubleValue <= Double(UInt32.max),
                  value.doubleValue.rounded(.towardZero) == value.doubleValue else {
                throw RouterSystemError.configurationRejected
            }
            return value.uint32Value
        }
    }
}

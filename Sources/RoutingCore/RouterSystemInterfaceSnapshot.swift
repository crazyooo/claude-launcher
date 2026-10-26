import Foundation
import Darwin

enum RouterSystemInterfaceSnapshot {
    struct Address: Codable, Equatable {
        let family: Int32
        let address: String
        let netmask: String?
        let destination: String?
        var sortKey: String { "\(family)|\(address)|\(netmask ?? "")|\(destination ?? "")" }
    }
    struct Interface: Codable, Equatable {
        let name: String
        let index: UInt32
        let flags: UInt32
        let mtu: Int
        let addresses: [Address]
        func validate() throws {
            guard validName(name), index > 0, mtu > 0, mtu <= Int32.max, addresses.count <= 256,
                  addresses.map(\.sortKey) == addresses.map(\.sortKey).sorted(),
                  Set(addresses.map(\.sortKey)).count == addresses.count else { throw RouterSystemError.ownershipUnknown }
            for item in addresses {
                guard [AF_INET, AF_INET6].contains(item.family),
                      [item.address, item.netmask, item.destination].compactMap({ $0 }).allSatisfy({ numericText($0, family: item.family) }) else {
                    throw RouterSystemError.ownershipUnknown
                }
            }
        }
    }
    private struct Partial {
        let index: UInt32
        let flags: UInt32
        var addresses: [Address]
    }
    static func validName(_ name: String) -> Bool {
        !name.isEmpty && name.utf8.count < Int(IFNAMSIZ) && name.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 95].contains($0)
        }
    }
    static func numericText(_ text: String, family: Int32) -> Bool {
        guard !text.isEmpty, text.utf8.count < Int(NI_MAXHOST),
              !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return false }
        let parts = text.split(separator: "%", omittingEmptySubsequences: false)
        guard parts.count == 1 || (family == AF_INET6 && parts.count == 2 && validName(String(parts[1]))) else { return false }
        var storage = in6_addr()
        return String(parts[0]).withCString { inet_pton(family, $0, &storage) } == 1
    }

    static func collect() throws -> [Interface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { throw RouterSystemError.operationUnsettled }
        defer { freeifaddrs(head) }
        let fd = socket(AF_INET, SOCK_DGRAM, 0) // ioctl only; never connects or sends traffic.
        guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
        defer { close(fd) }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw RouterSystemError.operationUnsettled }
        var items: [String: Partial] = [:], cursor: UnsafeMutablePointer<ifaddrs>? = first
        var count = 0
        while let pointer = cursor {
            count += 1
            guard count <= 4096 else { throw RouterSystemError.operationUnsettled }
            let item = pointer.pointee; cursor = item.ifa_next
            guard let rawName = item.ifa_name else { throw RouterSystemError.operationUnsettled }
            let name = String(cString: rawName), index = if_nametoindex(rawName)
            guard validName(name), index > 0 else { throw RouterSystemError.operationUnsettled }
            var partial = items[name] ?? Partial(index: index, flags: item.ifa_flags, addresses: [])
            guard partial.index == index, partial.flags == item.ifa_flags else { throw RouterSystemError.networkConflict }
            if let address = item.ifa_addr {
                let family = Int32(address.pointee.sa_family)
                if family == AF_INET || family == AF_INET6 {
                    let destination = item.ifa_flags & UInt32(IFF_POINTOPOINT | IFF_BROADCAST) != 0 ? item.ifa_dstaddr : nil
                    let entry = Address(family: family, address: try numeric(address, family: family, mask: false),
                        netmask: try item.ifa_netmask.map { try numeric($0, family: family, mask: true) },
                        destination: try optionalDestination(destination, family: family))
                    if !partial.addresses.contains(entry) { partial.addresses.append(entry) }
                }
            }
            items[name] = partial // Includes interfaces with AF_LINK and no IP addresses.
        }
        guard !items.isEmpty, items.count <= 256 else { throw RouterSystemError.operationUnsettled }
        return try items.keys.sorted().map { name in
            let item = items[name]!
            guard if_nametoindex(name) == item.index else { throw RouterSystemError.networkConflict }
            var request = ifreq()
            withUnsafeMutableBytes(of: &request.ifr_name) { $0.copyBytes(from: Array(name.utf8)) }
            // Darwin SDK SIOCGIFMTU = _IOWR('i', 51, struct ifreq); the macro is not imported by Swift.
            let command = UInt(IOC_INOUT) | ((UInt(MemoryLayout<ifreq>.size) & UInt(IOCPARM_MASK)) << 16) | (105 << 8) | 51
            guard ioctl(fd, command, &request) == 0, if_nametoindex(name) == item.index else { throw RouterSystemError.operationUnsettled }
            let value = Interface(name: name, index: item.index, flags: item.flags, mtu: Int(request.ifr_ifru.ifru_mtu),
                                  addresses: item.addresses.sorted { $0.sortKey < $1.sortKey })
            try value.validate()
            return value
        }
    }

    /// A Darwin point-to-point row may have a nonnil, empty destination sockaddr.
    /// Accept that sentinel only here; required addresses and masks stay strict.
    static func optionalDestination(_ pointer: UnsafePointer<sockaddr>?, family: Int32) throws -> String? {
        guard let pointer else { return nil }
        if pointer.pointee.sa_len == 0 && pointer.pointee.sa_family == 0 { return nil }
        return try numeric(pointer, family: family, mask: false)
    }

    /// getifaddrs may use truncated zero-tailed netmasks. Copy only sa_len, then format numerically without DNS.
    static func numeric(_ pointer: UnsafePointer<sockaddr>, family: Int32, mask: Bool) throws -> String {
        guard family == AF_INET || family == AF_INET6 else { throw RouterSystemError.operationUnsettled }
        let size = family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size
        let count = Int(pointer.pointee.sa_len), actual = Int32(pointer.pointee.sa_family)
        guard count >= 2, count <= size, mask ? (actual == 0 || actual == family) : (actual == family && count == size) else {
            throw RouterSystemError.operationUnsettled
        }
        var storage = sockaddr_storage()
        withUnsafeMutableBytes(of: &storage) { $0.baseAddress!.copyMemory(from: UnsafeRawPointer(pointer), byteCount: count) }
        storage.ss_len = UInt8(size); storage.ss_family = sa_family_t(family)
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t(size), &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard result == 0 else { throw RouterSystemError.operationUnsettled }
        return String(cString: buffer)
    }
}

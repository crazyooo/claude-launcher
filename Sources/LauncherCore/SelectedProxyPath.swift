import Foundation
import Darwin

/// Read-only route classification and an explicit physical-interface comparison.
/// The default diagnostic stays on the system route. Nothing here changes routes, proxies, or TUN.
public enum SelectedProxyPath {
    public struct Candidate: Equatable, Identifiable, Sendable {
        public let name: String
        public let index: UInt32
        public let address: String
        public var id: String { name }
        public init(name: String, index: UInt32, address: String) {
            self.name = name; self.index = index; self.address = address
        }
    }
    public struct Report: Equatable, Sendable {
        public let summary: String
        public let candidates: [Candidate]
        public let routeKind: String
        public let defaultDiagnostic: String
        public let ownTunEnablement: String
        public let comparisonIsAcceptance: Bool
        public init(summary: String, candidates: [Candidate], routeKind: String,
                    defaultDiagnostic: String = "systemRoute", ownTunEnablement: String,
                    comparisonIsAcceptance: Bool = false) {
            self.summary = summary; self.candidates = candidates; self.routeKind = routeKind
            self.defaultDiagnostic = defaultDiagnostic; self.ownTunEnablement = ownTunEnablement
            self.comparisonIsAcceptance = comparisonIsAcceptance
        }
    }
    public struct Handshake: Equatable, Sendable {
        public let summary: String
        public let systemCode: String
        public let physicalCode: String
        public let interfaceName: String
        public init(summary: String, systemCode: String, physicalCode: String, interfaceName: String) {
            self.summary = summary; self.systemCode = systemCode
            self.physicalCode = physicalCode; self.interfaceName = interfaceName
        }
    }
    struct Device: Equatable {
        var name: String
        var index: UInt32
        var flags: UInt32
        var addresses: [String]
    }
    struct Route: Equatable {
        let interface: String
        let gateway: String?
        let flags: Set<String>
        var kind: String { Self.kind(interface) }
        static func kind(_ name: String) -> String {
            if name == "lo0" || (name.hasPrefix("lo") && name.dropFirst(2).allSatisfy(\.isNumber)) { return "loopback" }
            if ["utun", "ppp", "ipsec", "gif", "stf"].contains(where: { name.hasPrefix($0) }) { return "tunnel" }
            if physicalName(name) { return "physical" }
            return "other"
        }
    }

    static let greeting = Data([0x05, 0x02, 0x00, 0x02])

    static func physicalName(_ name: String) -> Bool {
        guard name.hasPrefix("en"), name.count > 2, name.count < Int(IFNAMSIZ),
              name.dropFirst(2).allSatisfy(\.isNumber), !name.dropFirst(2).isEmpty else { return false }
        return true
    }
    static func globalIPv4(_ value: String) -> String? {
        guard let text = normalizedIPv4(value), text != "0.0.0.0", !text.hasPrefix("169.254.") else { return nil }
        return text
    }
    /// Binding may proceed only when the kernel echoes the same nonzero index.
    static func confirmed(requested: UInt32, observed: UInt32?) -> Bool {
        requested > 0 && observed == requested
    }
    static func classifyGreeting(_ data: Data?) -> String {
        guard let data, !data.isEmpty else { return "no_reply" }
        guard data.count >= 2, data[0] == 5 else { return "unrecognized" }
        switch data[1] {
        case 2: return "method_username"
        case 0: return "method_none"
        case 255: return "method_rejected"
        default: return "unrecognized"
        }
    }
    static func coexistence(routeKind: String?) -> (defaultDiagnostic: String, ownTun: String, acceptance: Bool) {
        let tun: String
        switch routeKind {
        case "tunnel": tun = "blockedWhileForeignCapture"
        case nil: tun = "unknown"
        default: tun = "requireClearUnchanged"
        }
        return ("systemRoute", tun, false)
    }

    static func parseRoute(_ text: String, expecting target: String) -> Route? {
        guard text.utf8.count <= 16_384, target == "default" || normalizedIPv4(target) != nil,
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\t" }) else { return nil }
        let known: Set<String> = ["route to", "destination", "mask", "gateway", "interface", "flags"]
        var fields: [String: String] = [:], metricsHeader = false, metricsRow = false
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            let columns = line.split(whereSeparator: \.isWhitespace).map(String.init)
            if columns == ["recvpipe", "sendpipe", "ssthresh", "rtt,msec", "rttvar", "hopcount", "mtu", "expire"] {
                if metricsHeader { return nil }
                metricsHeader = true; continue
            }
            if metricsHeader {
                if metricsRow || columns.count != 8 || columns.contains(where: { Int64($0) == nil }) { return nil }
                metricsRow = true; continue
            }
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let key = String(line[..<colon])
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard known.contains(key), fields[key] == nil, !value.isEmpty else { return nil }
            fields[key] = value
        }
        guard metricsHeader == metricsRow, fields["route to"] == target,
              let destination = fields["destination"], destination == "default" || normalizedIPv4(destination) != nil,
              let interface = fields["interface"], validInterface(interface),
              let flags = fields["flags"], flags.hasPrefix("<"), flags.hasSuffix(">") else { return nil }
        if target == "default" && destination != "default" { return nil }
        if let mask = fields["mask"], normalizedIPv4(mask) == nil { return nil }
        if let gateway = fields["gateway"], normalizedIPv4(gateway) == nil { return nil }
        let entries = flags.dropFirst().dropLast().split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard !entries.isEmpty, Set(entries).count == entries.count,
              entries.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { (65...90).contains($0) || (48...57).contains($0) || $0 == 95 } }) else { return nil }
        return .init(interface: interface, gateway: fields["gateway"], flags: Set(entries))
    }
    private static func validInterface(_ name: String) -> Bool {
        !name.isEmpty && name.utf8.count < Int(IFNAMSIZ) && name.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        }
    }

    static func candidates(_ devices: [Device], scoped: (String) -> String?) -> [Candidate] {
        var selected: [Candidate] = []
        for device in devices.sorted(by: { $0.name < $1.name }) {
            guard selected.count < 32, physicalName(device.name), device.index > 0,
                  device.flags & UInt32(IFF_UP) != 0,
                  let address = device.addresses.compactMap(globalIPv4).sorted().first,
                  let text = scoped(device.name), let route = parseRoute(text, expecting: "default"),
                  route.interface == device.name, route.gateway != nil,
                  route.flags.isSuperset(of: ["UP", "GATEWAY"]),
                  route.flags.isDisjoint(with: ["REJECT", "BLACKHOLE"]) else { continue }
            selected.append(.init(name: device.name, index: device.index, address: address))
        }
        return selected
    }

    static func explain(route: Route?) -> String {
        let base: String
        if let route, route.kind == "tunnel" {
            let gateway = route.gateway.map { "，网关 \($0)" } ?? ""
            base = "到该入口的当前系统路由接口是 \(route.interface)（隧道\(gateway)）。默认“测试这条线路”仍走这条路由。外部隧道仍占用该入口时，本工具自己的 TUN 保持拒绝启用。"
        } else if let route {
            base = "到该入口的当前系统路由接口是 \(route.interface)。默认“测试这条线路”仍走系统路由。"
        } else {
            base = "未能读取到该入口的系统路由，不能据此认为没有隧道。默认“测试这条线路”仍走系统当前路由。"
        }
        return base + " 物理接口对照需要单独选择，只约束本次检测连接，不修改路由或现有隧道；对照通过也不代表 Desktop、CLI 或实际分流。"
    }

    public static func report(_ host: String) -> Report {
        let target = normalizedIPv4(host)
        let route = target.flatMap { value -> Route? in
            let output = ReadCommand.run("/sbin/route", ["-n", "get", value], timeout: 2, environment: cleanEnvironment)
            guard output.code == 0 else { return nil }
            return parseRoute(output.text, expecting: value)
        }
        let devices = interfaces()
        let selected = candidates(devices) { name in
            let output = ReadCommand.run("/sbin/route", ["-n", "get", "-ifscope", name, "default"], timeout: 2, environment: cleanEnvironment)
            return output.code == 0 ? output.text : nil
        }
        let fresh = selected.compactMap { candidate -> Candidate? in
            guard currentIndex(candidate.name) == candidate.index else { return nil }
            return candidate
        }
        let policy = coexistence(routeKind: route?.kind)
        let summary = (target == nil ? "物理接口对照只接受 IPv4 数字入口，避免通过隧道解析域名。这次没有查询该入口的路由，也没有连接。" : explain(route: route))
        return .init(summary: summary, candidates: fresh, routeKind: route?.kind ?? "unknown",
                     defaultDiagnostic: policy.defaultDiagnostic, ownTunEnablement: policy.ownTun, comparisonIsAcceptance: policy.acceptance)
    }

    public static func handshake(host: String, port: Int, name: String, index: UInt32, timeout: TimeInterval) -> Handshake {
        let refused = Handshake(summary: "所选接口未通过现场复核，没有发起连接。这不是出口检测，也不是实际分流。",
                               systemCode: "interface_unavailable", physicalCode: "interface_unavailable", interfaceName: name)
        guard normalizedIPv4(host) != nil, (1...65535).contains(port), timeout.isFinite, timeout > 0,
              physicalName(name), currentIndex(name) == index else { return refused }
        let system = exchange(host: host, port: port, index: nil, timeout: timeout)
        let physical = currentIndex(name) == index ? exchange(host: host, port: port, index: index, timeout: timeout) : "interface_bind_unconfirmed"
        return .init(summary: "接口 \(name) 的无账号握手：系统路由\(phrase(system))，物理接口\(phrase(physical))。没有发送账号或目标请求。这不是 Desktop/CLI 结果，也不是实际分流通过。",
                     systemCode: system, physicalCode: physical, interfaceName: name)
    }

    static func phrase(_ code: String) -> String {
        switch code {
        case "method_username": return "收到用户名密码认证方式"
        case "method_none": return "收到无需认证"
        case "method_rejected": return "拒绝了本次认证方式"
        case "no_reply": return "没有 SOCKS 回复"
        case "unrecognized": return "回复无法归类"
        case "interface_bind_unconfirmed": return "绑定未确认，已停止连接"
        case "connect_failed": return "未能连接入口"
        default: return "没有取得结果"
        }
    }

    static func exchange(host: String, port: Int, index: UInt32?, timeout: TimeInterval) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "unavailable" }
        defer { close(fd) }
        guard prepare(fd) else { return "unavailable" }
        if let index {
            guard confirmed(requested: index, observed: bind(fd, index)) else { return "interface_bind_unconfirmed" }
        }
        guard connect(fd, host: host, port: UInt16(port), timeout: timeout) else { return "connect_failed" }
        guard writeAll(fd, greeting, timeout: timeout) else { return "no_reply" }
        return classifyGreeting(readAtMost(fd, 2, timeout: min(timeout, 2)))
    }

    /// Accepts one loopback client and forwards it only after interface binding is confirmed.
    static func forward(index: UInt32, name: String? = nil, proxyHost: String, proxyPort: Int, timeout: TimeInterval, body: (UInt16) -> Void) -> String {
        guard index > 0, index <= UInt32(Int32.max), normalizedIPv4(proxyHost) != nil, (1...65535).contains(proxyPort) else {
            return "interface_bind_unconfirmed"
        }
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0, prepare(listener), bindLoopback(listener), Darwin.listen(listener, 1) == 0,
              let port = localPort(listener) else { close(listener); return "unavailable" }
        let box = RelayBox()
        let thread = Thread {
            box.finish(listener: listener, index: index, name: name, host: proxyHost, port: UInt16(proxyPort), timeout: timeout)
        }
        thread.start()
        body(port)
        let deadline = Date().addingTimeInterval(timeout + 1)
        while !box.done, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        return box.code
    }

    private final class RelayBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = "unavailable"
        private var finished = false
        var code: String { lock.lock(); defer { lock.unlock() }; return stored }
        var done: Bool { lock.lock(); defer { lock.unlock() }; return finished }
        func finish(listener: Int32, index: UInt32, name: String?, host: String, port: UInt16, timeout: TimeInterval) {
            let value = SelectedProxyPath.acceptAndForward(listener: listener, index: index, name: name, host: host, port: port, timeout: timeout)
            lock.lock(); stored = value; finished = true; lock.unlock()
        }
    }

    private static func acceptAndForward(listener: Int32, index: UInt32, name: String?, host: String, port: UInt16, timeout: TimeInterval) -> String {
        defer { close(listener) }
        guard let client = acceptLoopback(listener, timeout: timeout) else { return "unavailable" }
        defer { close(client) }
        if let name, currentIndex(name) != index { return "interface_bind_unconfirmed" }
        let outbound = socket(AF_INET, SOCK_STREAM, 0)
        guard outbound >= 0 else { return "unavailable" }
        defer { close(outbound) }
        guard prepare(outbound), confirmed(requested: index, observed: bind(outbound, index)) else { return "interface_bind_unconfirmed" }
        guard connect(outbound, host: host, port: port, timeout: timeout) else { return "connect_failed" }
        splice(client, outbound, timeout: timeout)
        return "ok"
    }

    private static let cleanEnvironment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]

    static func currentIndex(_ name: String) -> UInt32? {
        guard physicalName(name) else { return nil }
        let index = name.withCString { if_nametoindex($0) }
        return index > 0 ? index : nil
    }
    private static func interfaces() -> [Device] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var items: [String: Device] = [:], cursor: UnsafeMutablePointer<ifaddrs>? = first, count = 0
        while let pointer = cursor {
            count += 1
            if count > 4096 { return [] }
            let item = pointer.pointee; cursor = item.ifa_next
            guard let raw = item.ifa_name else { continue }
            let name = String(cString: raw), index = if_nametoindex(raw)
            guard index > 0 else { continue }
            var device = items[name] ?? Device(name: name, index: index, flags: item.ifa_flags, addresses: [])
            guard device.index == index, device.flags == item.ifa_flags else { return [] }
            if let address = item.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET),
               address.pointee.sa_len >= MemoryLayout<sockaddr_in>.size {
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                var value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                if inet_ntop(AF_INET, &value, &buffer, socklen_t(buffer.count)) != nil,
                   let text = normalizedIPv4(String(cString: buffer)), !device.addresses.contains(text) {
                    device.addresses.append(text)
                }
            }
            items[name] = device
        }
        return items.values.sorted { $0.name < $1.name }
    }
    private static func prepare(_ fd: Int32) -> Bool {
        var one: Int32 = 1
        return fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0
    }
    private static func bind(_ fd: Int32, _ index: UInt32) -> UInt32? {
        guard index > 0, index <= UInt32(Int32.max) else { return nil }
        var value = Int32(index)
        guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &value, socklen_t(MemoryLayout<Int32>.size)) == 0 else { return nil }
        var observed: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &observed, &length) == 0, length == MemoryLayout<Int32>.size else { return nil }
        return UInt32(observed)
    }
    private static func bindLoopback(_ fd: Int32) -> Bool {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else { return false }
        return withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } == 0
        }
    }
    private static func localPort(_ fd: Int32) -> UInt16? {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } == 0
        }
        guard ok, length >= MemoryLayout<sockaddr_in>.size else { return nil }
        return UInt16(bigEndian: address.sin_port)
    }
    private static func acceptLoopback(_ fd: Int32, timeout: TimeInterval) -> Int32? {
        var pollfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard wait(&pollfd, timeout: timeout), pollfd.revents & Int16(POLLIN) != 0 else { return nil }
        var peer = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let client = withUnsafeMutablePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(fd, $0, &length) }
        }
        var loopback = in_addr()
        guard client >= 0, inet_pton(AF_INET, "127.0.0.1", &loopback) == 1, peer.sin_addr.s_addr == loopback.s_addr,
              prepare(client) else { if client >= 0 { close(client) }; return nil }
        return client
    }
    private static func connect(_ fd: Int32, host: String, port: UInt16, timeout: TimeInterval) -> Bool {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return false }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { return false }
        let started = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if started == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pollfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard wait(&pollfd, timeout: timeout) else { return false }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        return getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0
    }
    private static func writeAll(_ fd: Int32, _ data: Data, timeout: TimeInterval) -> Bool {
        var offset = 0
        let deadline = Date().addingTimeInterval(timeout)
        while offset < data.count, Date() < deadline {
            let count = data[offset...].withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return Darwin.write(fd, base, buffer.count)
            }
            if count > 0 { offset += count; continue }
            if count < 0 && errno == EAGAIN { if !wait(fd, events: POLLOUT, deadline: deadline) { return false }; continue }
            if count < 0 && errno == EINTR { continue }
            return false
        }
        return offset == data.count
    }
    private static func readAtMost(_ fd: Int32, _ limit: Int, timeout: TimeInterval) -> Data? {
        guard wait(fd, events: POLLIN, deadline: Date().addingTimeInterval(timeout)) else { return nil }
        var buffer = [UInt8](repeating: 0, count: limit)
        let count = Darwin.read(fd, &buffer, limit)
        if count == 0 { return Data() }
        guard count > 0 else { return errno == EAGAIN ? Data() : nil }
        return Data(buffer.prefix(count))
    }
    private static func splice(_ left: Int32, _ right: Int32, timeout: TimeInterval) {
        for fd in [left, right] {
            let flags = fcntl(fd, F_GETFL)
            if flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 { return }
        }
        var toRight = Data(), toLeft = Data(), leftOpen = true, rightOpen = true
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline && ((leftOpen && toRight.count < 16_384) || (rightOpen && toLeft.count < 16_384) || !toRight.isEmpty || !toLeft.isEmpty) {
            var polls = [
                pollfd(fd: left, events: Int16((leftOpen && toRight.count < 16_384 ? POLLIN : 0) | (!toLeft.isEmpty ? POLLOUT : 0)), revents: 0),
                pollfd(fd: right, events: Int16((rightOpen && toLeft.count < 16_384 ? POLLIN : 0) | (!toRight.isEmpty ? POLLOUT : 0)), revents: 0)
            ]
            if polls.allSatisfy({ $0.events == 0 }) { break }
            var first = polls[0], second = polls[1]
            guard wait(&first, extra: &second, deadline: deadline) else { break }
            polls[0] = first; polls[1] = second
            if polls[0].revents & Int16(POLLIN) != 0 { leftOpen = readInto(left, &toRight) && leftOpen }
            if polls[1].revents & Int16(POLLIN) != 0 { rightOpen = readInto(right, &toLeft) && rightOpen }
            if polls[0].revents & Int16(POLLOUT) != 0 { _ = writeFrom(left, &toLeft) }
            if polls[1].revents & Int16(POLLOUT) != 0 { _ = writeFrom(right, &toRight) }
            if polls[0].revents & Int16(POLLERR | POLLHUP) != 0 { leftOpen = false }
            if polls[1].revents & Int16(POLLERR | POLLHUP) != 0 { rightOpen = false }
            if !leftOpen && toLeft.isEmpty && !rightOpen && toRight.isEmpty { break }
        }
    }
    private static func readInto(_ fd: Int32, _ destination: inout Data) -> Bool {
        var buffer = [UInt8](repeating: 0, count: 16_384 - destination.count)
        guard !buffer.isEmpty else { return true }
        let count = Darwin.read(fd, &buffer, buffer.count)
        if count > 0 { destination.append(contentsOf: buffer.prefix(count)); return true }
        if count < 0 && (errno == EAGAIN || errno == EINTR) { return true }
        return false
    }
    private static func writeFrom(_ fd: Int32, _ source: inout Data) -> Bool {
        guard !source.isEmpty else { return true }
        let count = source.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return -1 }
            return Darwin.write(fd, base, buffer.count)
        }
        if count > 0 { source.removeFirst(count); return true }
        return count < 0 && (errno == EAGAIN || errno == EINTR)
    }
    private static func wait(_ pollfd: inout pollfd, timeout: TimeInterval) -> Bool {
        wait(&pollfd, extra: nil, deadline: Date().addingTimeInterval(timeout))
    }
    private static func wait(_ fd: Int32, events: Int32, deadline: Date) -> Bool {
        var pollfd = pollfd(fd: fd, events: Int16(events), revents: 0)
        return wait(&pollfd, extra: nil, deadline: deadline)
    }
    private static func wait(_ first: inout pollfd, extra: UnsafeMutablePointer<pollfd>?, deadline: Date) -> Bool {
        while Date() < deadline {
            let milliseconds = Int32(min(1_000, max(1, deadline.timeIntervalSinceNow * 1_000)))
            let result: Int32
            if let extra {
                var pair = [first, extra.pointee]
                result = poll(&pair, 2, milliseconds)
                first = pair[0]; extra.pointee = pair[1]
            } else {
                result = poll(&first, 1, milliseconds)
            }
            if result > 0 { return true }
            if result == 0 { continue }
            if errno != EINTR { return false }
        }
        return false
    }
}

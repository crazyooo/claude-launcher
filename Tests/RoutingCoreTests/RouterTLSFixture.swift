import Foundation
import XCTest
import Darwin
@testable import RoutingCore

/// One child, one loopback accept, ephemeral credentials. Nothing is installed in Keychain.
final class RouterTLSFixture {
    struct Ready: Decodable { let host: String; let port: UInt16; let anchor: String }
    struct Report: Decodable {
        let sni: String?
        let version: String?
        let peer: String?
        let nonce: String?
        let eof: Bool
        let error_kind: String?
        let ssl_library: String?
        let ssl_reason: String?
    }
    let directory: URL
    private let process = Process()
    private var output: FileHandle?
    private var stopped = false
    private(set) var ready: Ready!
    var target: RouterOwnedTCPProbe.Endpoint {
        get throws { try .init(address: ready.host, port: ready.port) }
    }
    var anchor: Data {
        get throws { try XCTUnwrap(Data(base64Encoded: ready.anchor)) }
    }

    init(mode: String = "normal", family: Int = 4) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterTLSConnection.Failure.unavailable }
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("router-tls-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        do {
            let log = directory.appendingPathComponent("fixture.log")
            guard FileManager.default.createFile(atPath: log.path, contents: nil,
                                                 attributes: [.posixPermissions: 0o600]) else {
                throw RouterTLSConnection.Failure.unavailable
            }
            output = try FileHandle(forWritingTo: log)
            let python = ProcessInfo.processInfo.environment["ROUTER_TEST_PYTHON"]
                ?? "/opt/homebrew/opt/python@3.13/bin/python3.13"
            guard python.hasPrefix("/") else { throw RouterTLSConnection.Failure.invalidTarget }
            let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent()
            process.executableURL = URL(fileURLWithPath: python)
            process.arguments = [repository.appendingPathComponent("tools/fixtures/router_tls_loopback.py").path,
                                 directory.path, mode, String(family)]
            process.standardOutput = output
            process.standardError = output
            try process.run()
            let deadline = ProcessInfo.processInfo.systemUptime + 4
            while ready == nil {
                ready = try read("ready.json", as: Ready.self)
                if ready != nil { break }
                guard process.isRunning else { throw RouterTLSConnection.Failure.unavailable }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterTLSConnection.Failure.timedOut }
                Thread.sleep(forTimeInterval: 0.01)
            }
        } catch { stop(); throw error }
    }

    private func read<T: Decodable>(_ name: String, as type: T.Type) throws -> T? {
        let url = directory.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let data = try Data(contentsOf: url)
        guard data.count <= 16_384 else { throw RouterTLSConnection.Failure.unavailable }
        return try JSONDecoder().decode(type, from: data)
    }

    func awaitEvent(_ name: String = "accepted.json") async throws {
        let event = try await awaitFile(name, as: [String: Bool].self, seconds: 2)
        guard event == (name == "request.json" ? ["received": true] : ["accepted": true]) else {
            throw RouterTLSConnection.Failure.unavailable
        }
    }

    private func awaitFile<T: Decodable>(_ name: String, as type: T.Type, seconds: Double) async throws -> T {
        let deadline = ProcessInfo.processInfo.systemUptime + seconds
        while true {
            if let result = try read(name, as: type) { return result }
            guard process.isRunning else { throw RouterTLSConnection.Failure.unavailable }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterTLSConnection.Failure.timedOut }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    func finish() async throws -> Report {
        let report = try await awaitFile("report.json", as: Report.self, seconds: 8)
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        guard !process.isRunning else { throw RouterTLSConnection.Failure.timedOut }
        XCTAssertEqual(process.terminationStatus, 0)
        return report
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        if process.isRunning { process.terminate() }
        let deadline = ProcessInfo.processInfo.systemUptime + 2
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard !process.isRunning else {
            XCTFail("TLS fixture child did not exit; private directory preserved at \(directory.path)")
            return
        }
        try? output?.close()
        output = nil
        do { try FileManager.default.trashItem(at: directory, resultingItemURL: nil) }
        catch { XCTFail("Cannot move private TLS fixture directory to Trash: \(directory.path)") }
    }

    deinit { stop() }
}

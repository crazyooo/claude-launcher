import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemRuntimeEffectsTests: XCTestCase {
    private typealias C = RouterSystemRuntimeCorrelation
    private final class Fixture {
        let base = try! RouterSystemDispatchFixture()
        var v6 = true, stopped = false, groupBusy = false, historical = false
        var controllerReads = 0, snapshots = 0, stops = 0, validationCount = 0
        var controllerHook: ((Int, C.Controller) -> C.Controller)?
        var snapshotHook: ((Int, RouterSystemBaselineSnapshot) -> RouterSystemBaselineSnapshot)?
        var routeOutside = false, expired = false, controllerFails = false
        var claimValid = true, claimReads = 0, sourceValid = true
        /// Fresh stop-time clear observation: default clear (true); tests flip to
        /// simulate a proxy/VPN that reappears while cleanup samples.
        var cleanEnvironment = true
        var cleanEnvironmentReads = 0
        /// When set, each sample returns the next value (last value repeats).
        var cleanEnvironmentSequence: [Bool]?
        var fence: RouterSystemDispatchFence {
            .init(instance: base.intent.id, host: base.host, processGroup: base.host.pid,
                  gateDeadlineUptime: base.intent.deadlineUptime, gateExpiresAt: base.intent.expiresAt,
                  baselineID: UUID(), baselineDigest: String(repeating: "c", count: 64),
                  networkFingerprint: base.intent.networkFingerprint, configurationDigest: base.digest)
        }
        var state: RouterSystemJournal
        init() {
            state = .empty()
            state.installation = base.identity; state.intent = base.intent
            state.configurationDigest = base.digest; state.work = base.work
            state.phase = .applying; state.reason = "execution_pending"; state.dispatch = fence
        }
        var controller: C.Controller {
            .init(process: .init(work: base.work, uid: 0, realUID: 0, parentPID: base.host.pid, processGroup: base.host.pid),
                  listeners: [.init(descriptor: 10, generation: 900)],
                  declaration: .init(device: "utun5", generalIPv6Enabled: true, tunIPv6Configured: v6,
                      addresses: ["198.18.0.1/30"] + (v6 ? [RouterSystemCompiler.tunIPv6] : []), effectiveMTU: 9000))
        }
        var tun: RouterSystemInterfaceSnapshot.Interface {
            var addresses: [RouterSystemInterfaceSnapshot.Address] = [
                .init(family: AF_INET, address: "198.18.0.1", netmask: "255.255.255.252", destination: "198.18.0.1"),
                .init(family: AF_INET6, address: "fe80::1234%utun5", netmask: "ffff:ffff:ffff:ffff::", destination: nil)]
            if v6 { addresses.append(.init(family: AF_INET6, address: "fdfe:dcba:9876::1", netmask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", destination: nil)) }
            return .init(name: "utun5", index: 17, flags: UInt32(IFF_UP | IFF_POINTOPOINT), mtu: 9000, addresses: addresses.sorted { $0.sortKey < $1.sortKey })
        }
        var active: RouterSystemBaselineSnapshot {
            .init(captured: base.clock, networkFingerprint: String(repeating: "d", count: 64), interfaces: base.devices + [tun],
                  routesIPv4: base.v4 + "0/1 198.18.0.1 UGSc utun5\n",
                  routesIPv6: base.v6 + (v6 ? "::/1 fdfe:dcba:9876::1 UGSc utun5\n" : ""), dns: base.dns)
        }
        func route(_ family: RouterSystemSelectedRoute.Family) -> RouterSystemSelectedRoute {
            .init(family: family, destination: "default", mask: nil, gateway: family == .ipv4 ? "198.18.0.1" : "fdfe:dcba:9876::1",
                  interface: routeOutside ? "en0" : "utun5", flags: ["UP", "GATEWAY"])
        }
        func effect() throws -> RouterSystemRuntimeEffects {
            try .fixture(readers: .init(validate: { _ in
                self.validationCount += 1
                guard self.sourceValid else { throw RouterSystemError.ownershipUnknown }
                return self.base.snapshot()
            },
                host: { self.historical ? .init(bootID: self.base.boot, pid: 800, birthSeconds: 1002, birthMicroseconds: 0) : self.base.host },
                local: { _ in self.stopped ? .exited : .running }, stop: { _ in self.stops += 1; self.stopped = true },
                former: { _ in self.stopped && !self.groupBusy ? .formerHostGroupEmpty : .unsettled },
                exited: { _ in self.stopped ? .exited : .sameProcess }, group: { _ in self.groupBusy ? [700, 705] : [700] },
                controller: { _, _ in self.controllerReads += 1; if self.controllerFails { throw RouterSystemError.operationUnsettled }; return self.controllerHook?(self.controllerReads, self.controller) ?? self.controller },
                snapshot: {
                    self.snapshots += 1
                    let value = self.stopped ? self.base.snapshot() : self.active
                    return self.snapshotHook?(self.snapshots, value) ?? value
                }, route: self.route, clock: {
                    self.expired && self.snapshots > 0 ? .init(bootID: self.base.boot, uptime: 100, date: Date(timeIntervalSince1970: 1100)) : self.base.clock
                }, verifyClaim: { _ in
                    self.claimReads += 1
                    guard self.claimValid else { throw RouterSystemError.ownershipUnknown }
                }, cleanEnvironment: {
                    self.cleanEnvironmentReads += 1
                    if let sequence = self.cleanEnvironmentSequence, !sequence.isEmpty {
                        let index = min(self.cleanEnvironmentReads - 1, sequence.count - 1)
                        return sequence[index]
                    }
                    return self.cleanEnvironment
                }))
        }
        func footprint(_ current: RouterSystemBaselineSnapshot? = nil, second: C.Controller? = nil) throws -> RouterSystemFootprint {
            try C.capture(instance: base.intent.id, work: base.work, digest: base.digest,
                baseline: base.snapshot(), current: current ?? active, first: controller, second: second ?? controller,
                ipv4: route(.ipv4), ipv6: v6 ? route(.ipv6) : nil)
        }
        func proof(current: RouterSystemBaselineSnapshot, footprint: RouterSystemFootprint?, group: Bool = true,
                   cleanEnvironment: Bool = true) throws -> RouterSystemCleanupProof {
            let settled = C.Settlement(dispatchSettled: true, processExited: true, groupDrained: group)
            return try C.cleanup(instance: base.intent.id, dispatch: state.dispatch!, footprint: footprint,
                baseline: base.snapshot(), current: current, first: settled, second: settled,
                cleanEnvironment: cleanEnvironment)
        }
        func changed(_ original: RouterSystemBaselineSnapshot, interfaces: [RouterSystemInterfaceSnapshot.Interface]? = nil,
                     dns: String? = nil, v4: String? = nil, v6: String? = nil, fingerprint: String? = nil) -> RouterSystemBaselineSnapshot {
            .init(captured: original.captured, networkFingerprint: fingerprint ?? original.networkFingerprint,
                  interfaces: interfaces ?? original.interfaces, routesIPv4: v4 ?? original.routesIPv4,
                  routesIPv6: v6 ?? original.routesIPv6, dns: dns ?? original.dns)
        }
    }

    func testLiveCorrelationAndEffectiveIPv6RemainSeparateFromAcceptance() throws {
        let f = Fixture(), effects = try f.effect()
        let result = try effects.observe(f.state)
        XCTAssertTrue(result.processAlive); XCTAssertTrue(result.capturePresent); XCTAssertEqual(result.ipv6CaptureObserved, true)
        XCTAssertEqual(result.footprint?.interfaceIndex, 17)
        XCTAssertEqual(f.controllerReads, 3); XCTAssertEqual(f.snapshots, 2); XCTAssertEqual(f.stops, 0)
        let status = RouterSystemStatus(f.state, observation: result)
        XCTAssertFalse(status.routingVerified); XCTAssertFalse(status.protectionVerified); XCTAssertFalse(status.launchAuthorized)
        f.v6 = false
        let ipv4 = try effects.observe(f.state)
        XCTAssertTrue(ipv4.capturePresent); XCTAssertEqual(ipv4.ipv6CaptureObserved, false)
    }
    func testRealRuntimeProbeFailureRemainsManageableThroughProvider() throws {
        let f = Fixture(), runtime = try f.effect()
        f.state.footprint = try f.footprint(); f.state.phase = .active
        f.state.reason = "capture_observed_traffic_acceptance_pending"
        f.controllerFails = true
        var journal = f.state
        let provider = RouterSystemProvider(effects: .init(clock: { f.base.clock }, load: { journal },
            save: { next, previous in
                XCTAssertEqual(journal.revision, previous); journal = next
            }, network: { throw RouterSystemError.networkConflict }, stage: { _, _ in throw RouterSystemError.invalidRequest },
            prepareDispatch: { _, _ in throw RouterSystemError.invalidRequest }, start: { _, _, _, _ in XCTFail("unexpected start") },
            observe: runtime.observe, stop: runtime.stop, cleanup: runtime.cleanup))
        let before = journal.revision
        let failed = try provider.handle(.status(id: f.base.intent.id))
        XCTAssertEqual(failed.reason, "runtime_observation_unavailable"); XCTAssertFalse(failed.captureObserved)
        XCTAssertEqual(journal.revision, before); XCTAssertEqual(f.controllerReads, 1); XCTAssertEqual(f.stops, 0)
        let stopped = try provider.handle(.stop(id: f.base.intent.id))
        XCTAssertTrue(stopped.cleanupConfirmed); XCTAssertEqual(journal.phase, .stopped)
        XCTAssertEqual(f.controllerReads, 1); XCTAssertGreaterThan(f.stops, 0)
    }

    func testListenerGenerationAndRouteChangeRejectObservation() throws {
        let f = Fixture()
        f.controllerHook = { round, value in
            .init(process: value.process, listeners: [.init(descriptor: 10, generation: round == 1 ? 900 : 901)], declaration: value.declaration)
        }
        XCTAssertThrowsError(try f.effect().observe(f.state))
        f.controllerHook = nil; f.routeOutside = true
        XCTAssertThrowsError(try f.effect().observe(f.state))
        f.routeOutside = false; f.expired = true
        XCTAssertThrowsError(try f.effect().observe(f.state))
    }
    func testSnapshotChangeAndInterfaceReuseCannotBecomeOwnership() throws {
        let f = Fixture()
        f.snapshotHook = { count, value in count == 1 ? value : f.changed(value, fingerprint: String(repeating: "e", count: 64)) }
        XCTAssertThrowsError(try f.effect().observe(f.state))
        f.snapshotHook = nil
        for (name, index) in [("utun5", UInt32(17)), ("en9", UInt32(17))] {
            f.base.devices.append(.init(name: name, index: index, flags: 1, mtu: 1500, addresses: []))
            XCTAssertThrowsError(try f.footprint())
            f.base.devices.removeLast()
        }
        let wrong = RouterSystemInterfaceSnapshot.Interface(name: "utun5", index: 17, flags: UInt32(IFF_UP | IFF_POINTOPOINT), mtu: 1500, addresses: f.tun.addresses)
        XCTAssertThrowsError(try f.footprint(f.changed(f.active, interfaces: f.base.devices + [wrong])))
    }
    func testMaskAndExtraGlobalAddressRejectCapture() throws {
        let f = Fixture()
        var values = f.tun.addresses
        values.append(.init(family: AF_INET6, address: "2001:db8::1", netmask: "ffff:ffff:ffff:ffff::", destination: nil))
        var bad = RouterSystemInterfaceSnapshot.Interface(name: "utun5", index: 17, flags: f.tun.flags, mtu: 9000, addresses: values.sorted { $0.sortKey < $1.sortKey })
        XCTAssertThrowsError(try f.footprint(f.changed(f.active, interfaces: f.base.devices + [bad])))
        values = f.tun.addresses.map { $0.family == AF_INET ? .init(family: AF_INET, address: $0.address, netmask: "255.255.0.0", destination: nil) : $0 }
        bad = .init(name: "utun5", index: 17, flags: f.tun.flags, mtu: 9000, addresses: values.sorted { $0.sortKey < $1.sortKey })
        XCTAssertThrowsError(try f.footprint(f.changed(f.active, interfaces: f.base.devices + [bad])))
    }
    func testCleanupStopsOnlyLocalOwnerAndWaitsForAsyncGroupMembers() throws {
        let f = Fixture(), effects = try f.effect()
        f.state.footprint = try f.footprint(); f.groupBusy = true
        let pending = try effects.cleanup(f.state)
        XCTAssertTrue(pending.processExited); XCTAssertFalse(pending.complete); XCTAssertFalse(pending.startWorkSettled)
        f.groupBusy = false
        XCTAssertTrue(try effects.cleanup(f.state).complete); XCTAssertEqual(f.stops, 2)
        f.historical = true
        XCTAssertNoThrow(try effects.stop(f.state)); XCTAssertEqual(f.stops, 2)
        f.stopped = false
        XCTAssertThrowsError(try effects.stop(f.state)); XCTAssertEqual(f.stops, 2)
    }
    func testCleanupNeedsResourceAbsenceAndIndependentExternalEvidence() throws {
        let f = Fixture(), footprint = try f.footprint(), base = f.base.snapshot()
        XCTAssertTrue(try f.proof(current: base, footprint: footprint).complete)
        XCTAssertFalse(try f.proof(current: f.active, footprint: footprint).complete)
        let reused = RouterSystemInterfaceSnapshot.Interface(name: "utun99", index: 17, flags: 1, mtu: 1500, addresses: [])
        XCTAssertFalse(try f.proof(current: f.changed(base, interfaces: base.interfaces + [reused]), footprint: footprint).interfaceAbsent)
        let leftover = f.changed(base, v4: base.routesIPv4 + "198.18.0.2 link#17 UHLWI utun5 1\n")
        XCTAssertFalse(try f.proof(current: leftover, footprint: footprint).routesAbsent)
        let changedDNS = f.changed(base, dns: base.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54"))
        let proof = try f.proof(current: changedDNS, footprint: footprint)
        XCTAssertTrue(proof.interfaceAbsent); XCTAssertTrue(proof.routesAbsent); XCTAssertFalse(proof.externalStatePreserved)
        // Route-table drift alone (fingerprint differs, no new rows) no longer deadlocks
        // stop: the proxy/VPN surface is covered by the fresh clear observation instead.
        XCTAssertTrue(try f.proof(current: f.changed(base, fingerprint: String(repeating: "e", count: 64)),
                                  footprint: footprint).complete)
        XCTAssertFalse(try f.proof(current: f.changed(base, fingerprint: String(repeating: "e", count: 64)),
                                   footprint: footprint, cleanEnvironment: false).complete)
    }

    func testCleanupRejectsNewForeignRoutesButAcceptsOwnedAndDisappearedRows() throws {
        let f = Fixture(), footprint = try f.footprint(), base = f.base.snapshot()
        // A brand-new route on a foreign interface is evidence of a foreign takeover.
        let foreignRow = f.changed(base, v4: base.routesIPv4 + "10.99.0.0/16 10.99.0.1 UGSc utun9\n")
        XCTAssertFalse(try f.proof(current: foreignRow, footprint: footprint).externalStatePreserved)
        // New rows bound to the owned interface (leftover own-route churn) are not foreign.
        // Non-transient flags so stableRows keeps the row in the diff.
        let ownRow = f.changed(base, v4: base.routesIPv4 + "198.18.0.2 198.18.0.1 UGSc utun5\n")
        XCTAssertTrue(try f.proof(current: ownRow, footprint: footprint).externalStatePreserved)
        // Disappeared rows can never inject a tunnel; they must not block cleanup.
        let vanished = base.routesIPv4.split(separator: "\n").dropLast().joined(separator: "\n") + "\n"
        XCTAssertTrue(try f.proof(current: f.changed(base, v4: vanished), footprint: footprint).externalStatePreserved)
        // Without a footprint, every new row is foreign (execution may have created
        // resources that were never recorded).
        XCTAssertFalse(try f.proof(current: ownRow, footprint: nil).externalStatePreserved)
    }
    func testCleanupExemptsLinkLocalMulticastAndInterfaceAddressDrift() throws {
        let f = Fixture(), footprint = try f.footprint(), base = f.base.snapshot()
        // AWDL peer churn (UHLSI flags, live 2026-10-24) cannot carry unicast traffic.
        let awdlPeer = f.changed(base, v6: base.routesIPv6
            + "fe80::a8b5:b3ff:fee6:63c2%awdl0 2:0:0:0:0:0 UHLSI awdl0\n")
        XCTAssertTrue(try f.proof(current: awdlPeer, footprint: footprint).externalStatePreserved)
        // mDNS multicast rows reappearing (UHmLWI) and the local broadcast entry are
        // natural drift; a subnet-directed 192.168.3.255 row stays foreign (unicast class).
        let multicast = f.changed(base, v4: base.routesIPv4
            + "224.0.0.251 1:0:5e:0:0:fb UHmLWI en0\n255.255.255.255/32 ff:ff:ff:ff:ff:ff UHLWbI en0\n")
        XCTAssertTrue(try f.proof(current: multicast, footprint: footprint).externalStatePreserved)
        XCTAssertFalse(try f.proof(current: f.changed(base, v4: base.routesIPv4
            + "192.168.3.255 ff:ff:ff:ff:ff:ff UHLWbI en0\n"), footprint: footprint).externalStatePreserved)
        // Per-interface address rotation (nan0 link-local renewal, live 2026-10-24) keeps
        // the name+index slot; only a new interface name is takeover evidence.
        var rotated = f.base.devices
        rotated[0] = .init(name: rotated[0].name, index: rotated[0].index, flags: rotated[0].flags,
                           mtu: rotated[0].mtu,
                           addresses: [.init(family: AF_INET6, address: "fe80::2c10:5fff:fe5d:1132%\(rotated[0].name)",
                                             netmask: "ffff:ffff:ffff:ffff::", destination: nil)])
        XCTAssertTrue(try f.proof(current: f.changed(base, interfaces: rotated), footprint: footprint).externalStatePreserved)
        // A new interface name remains takeover evidence even with unicast routes absent.
        let newInterface = f.changed(base, interfaces: f.base.devices + [.init(name: "utun9", index: 40, flags: 1, mtu: 1500, addresses: [])])
        XCTAssertFalse(try f.proof(current: newInterface, footprint: footprint).externalStatePreserved)
        // IPv6 unicast aggregates remain foreign when they appear on a foreign interface.
        let unicast6 = f.changed(base, v6: base.routesIPv6 + "2000::/3 2001:db8::1 UGSc utun9\n")
        XCTAssertFalse(try f.proof(current: unicast6, footprint: footprint).externalStatePreserved)
    }
    func testMissingFootprintNeverMeansNoResourcesWereCreated() throws {
        let f = Fixture()
        XCTAssertTrue(try f.proof(current: f.base.snapshot(), footprint: nil).complete)
        XCTAssertFalse(try f.proof(current: f.active, footprint: nil).complete)
        XCTAssertFalse(try f.proof(current: f.base.snapshot(), footprint: nil, group: false).complete)
    }
    func testNewEnvironmentCandidateIsReadOnlyAndRequiresIndependentOwnedProof() throws {
        for failure in 0..<7 {
            let f = Fixture()
            f.state.footprint = try f.footprint(); f.state.phase = .stopping; f.state.reason = "external_environment_changed"
            f.stopped = true
            f.snapshotHook = { count, value in
                var result = f.changed(value, dns: value.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54"))
                if failure == 3 { result = f.changed(result, interfaces: result.interfaces + [f.tun]) }
                if failure == 4 && count == 2 { result = f.changed(result, fingerprint: String(repeating: "e", count: 64)) }
                if failure == 5 && count == 1 {
                    result = .init(captured: .init(bootID: value.captured.bootID, uptime: value.captured.uptime - 1,
                        date: value.captured.date.addingTimeInterval(-1)), networkFingerprint: result.networkFingerprint,
                        interfaces: result.interfaces, routesIPv4: result.routesIPv4, routesIPv6: result.routesIPv6, dns: result.dns)
                }
                return result
            }
            if failure == 1 { f.groupBusy = true }
            if failure == 2 { f.state.footprint = nil }
            if failure == 6 { f.claimValid = false }
            if failure == 0 {
                let value = try f.effect().baselineCandidate(f.state)
                XCTAssertEqual(value.changes, ["dns"]); XCTAssertTrue(value.proof.ownedResourcesAbsent)
                XCTAssertFalse(value.proof.externalStatePreserved); XCTAssertEqual(f.claimReads, 2)
                XCTAssertEqual(f.snapshots, 2)
            } else { XCTAssertThrowsError(try f.effect().baselineCandidate(f.state)) }
            XCTAssertEqual(f.stops, 0); XCTAssertEqual(f.controllerReads, 0)
        }
    }
    func testAwaitCleanEnvironmentRetriesThenSucceeds() throws {
        var reads = 0
        let ok = try RouterSystemRuntimeEffects.awaitCleanEnvironment(attempts: 4, interval: 0) {
            reads += 1
            return reads >= 3
        }
        XCTAssertTrue(ok)
        XCTAssertEqual(reads, 3)
    }

    func testAwaitCleanEnvironmentExhaustsAttempts() throws {
        var reads = 0
        let ok = try RouterSystemRuntimeEffects.awaitCleanEnvironment(attempts: 3, interval: 0) {
            reads += 1
            return false
        }
        XCTAssertFalse(ok)
        XCTAssertEqual(reads, 3)
        XCTAssertThrowsError(try RouterSystemRuntimeEffects.awaitCleanEnvironment(attempts: 0, interval: 0) { true })
        XCTAssertThrowsError(try RouterSystemRuntimeEffects.awaitCleanEnvironment(attempts: 5, interval: -1) { true })
    }

    func testCleanupRetriesTransientCleanEnvironmentFailure() throws {
        let f = Fixture()
        f.state.footprint = try f.footprint()
        f.stopped = true
        f.cleanEnvironmentSequence = [false, false, true]
        let proof = try f.effect().cleanup(f.state)
        XCTAssertTrue(proof.complete)
        XCTAssertTrue(proof.externalStatePreserved)
        XCTAssertEqual(f.cleanEnvironmentReads, 3)
    }

    func testCleanupExhaustsCleanEnvironmentRetriesWithoutInventingClear() throws {
        let f = Fixture()
        f.state.footprint = try f.footprint()
        f.stopped = true
        f.cleanEnvironmentSequence = Array(repeating: false, count: 8)
        let proof = try f.effect().cleanup(f.state)
        XCTAssertFalse(proof.complete)
        XCTAssertFalse(proof.externalStatePreserved)
        XCTAssertEqual(f.cleanEnvironmentReads, RouterSystemRuntimeEffects.cleanEnvironmentAttempts)
    }

    func testArchiveVerifiesImmutableSourceAndClaimOnBothSides() throws {
        for failure in 0..<5 {
            let f = Fixture(), runtime = try f.effect()
            var writes = 0
            if failure == 1 { f.sourceValid = false }
            if failure == 2 { f.claimValid = false }
            let archive = {
                try runtime.archiveEnvironment(f.state) { _ in
                    writes += 1
                    if failure == 3 { f.sourceValid = false }
                    if failure == 4 { f.claimValid = false }
                }
            }
            if failure == 0 {
                XCTAssertNoThrow(try archive())
                XCTAssertEqual(f.validationCount, 2); XCTAssertEqual(f.claimReads, 2)
            } else { XCTAssertThrowsError(try archive()) }
            XCTAssertEqual(writes, [1, 2].contains(failure) ? 0 : 1)
            XCTAssertEqual(f.stops, 0); XCTAssertEqual(f.snapshots, 0); XCTAssertEqual(f.controllerReads, 0)
        }
    }
}

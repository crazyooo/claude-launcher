import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemEnvironmentTests: XCTestCase {
    private final class Rig {
        let fixture = try! RouterSystemDispatchFixture()
        var state: RouterSystemJournal
        var samples = 0, saves = 0, archives = 0, stops = 0
        var failSave = false, writeBeforeFailure = false, failArchive = false, proxy = false
        var beforeSample: (() -> Void)?
        var afterSave: (() -> Void)?
        var missingProof: Int?
        var fingerprint = String(repeating: "e", count: 64)
        var externalPreserved = false
        var sampleBoot: UUID?
        init() throws {
            state = try fixture.journal.load()
            state.phase = .stopping; state.reason = "owned_stop_pending"
            state.configurationDigest = fixture.digest; state.work = fixture.work
            state.dispatch = .init(instance: fixture.intent.id, host: fixture.host, processGroup: fixture.host.pid,
                gateDeadlineUptime: fixture.intent.deadlineUptime, gateExpiresAt: fixture.intent.expiresAt,
                baselineID: UUID(), baselineDigest: String(repeating: "d", count: 64),
                networkFingerprint: fixture.intent.networkFingerprint, configurationDigest: fixture.digest)
            state.footprint = .init(instance: fixture.intent.id, work: fixture.work, configurationDigest: fixture.digest,
                interfaceName: "utun5", interfaceIndex: 17, addresses: ["198.18.0.1"], routeSignatures: ["inet|0/1|198.18.0.1|UGSc|utun5"])
        }
        var proof: RouterSystemCleanupProof {
            .init(instance: fixture.intent.id, dispatch: state.dispatch,
                startWorkSettled: missingProof != 0, processExited: missingProof != 1,
                interfaceAbsent: missingProof != 2, routesAbsent: missingProof != 3,
                externalStatePreserved: externalPreserved)
        }
        func effect() -> RouterSystemEffects {
            .init(clock: { self.fixture.clock }, load: { self.state }, save: { next, old in
                XCTAssertEqual(old, self.state.revision); self.saves += 1
                if !self.failSave || self.writeBeforeFailure { self.state = next }
                self.afterSave?()
                if self.failSave { throw RouterSystemError.journalUnknown }
            }, network: {
                .init(checkedAt: self.fixture.clock.date, fingerprint: self.fingerprint, complete: true,
                    defaultIPv4Interfaces: ["en0"], defaultIPv6Interfaces: [], tunnelCaptureInterfaces: [],
                    scopedTunnelInterfaces: [], applicationProxyEnabled: self.proxy, automaticProxyEnabled: false,
                    connectedVPN: false, userCoreJobPresent: false, unknowns: [])
            }, stage: { _, _ in XCTFail("stage"); throw RouterSystemError.conflict },
            prepareDispatch: { _, _ in XCTFail("dispatch"); throw RouterSystemError.conflict },
            start: { _, _, _, _ in XCTFail("start") }, observe: { _ in throw RouterSystemError.ownershipUnknown },
            stop: { _ in self.stops += 1 }, cleanup: { _ in self.proof },
            environmentCandidate: { _ in
                self.samples += 1; self.beforeSample?()
                let clock = self.fixture.clock
                return .init(sampled: .init(bootID: self.sampleBoot ?? clock.bootID, uptime: clock.uptime, date: clock.date),
                    fingerprint: self.fingerprint, changes: ["dns"], proof: self.proof)
            }, archiveEnvironment: { original in
                self.archives += 1
                XCTAssertEqual(original.phase, .stopped)
                if self.failArchive { throw RouterSystemError.journalUnknown }
            })
        }
        func preview(_ provider: RouterSystemProvider, id: UUID = UUID()) throws -> RouterSystemEnvironmentReview {
            _ = try provider.handle(.status(id: fixture.intent.id))
            let result = try provider.handle(.previewEnvironment(id: fixture.intent.id, review: id))
            return try XCTUnwrap(result.environmentReview)
        }
        func confirm(_ provider: RouterSystemProvider, _ review: RouterSystemEnvironmentReview) throws -> RouterSystemStatus {
            try provider.handle(.confirmEnvironment(id: review.instance, review: review.id, digest: review.digest))
        }
    }

    func testAcknowledgmentRetainsOriginalSourceAndNeverClaimsRestoration() throws {
        let r = try Rig(), provider = RouterSystemProvider(effects: r.effect()), original = r.state
        let view = try r.preview(provider)
        XCTAssertEqual(r.state.phase, .stopping); XCTAssertFalse(RouterSystemStatus(r.state).cleanupConfirmed)
        let status = try r.confirm(provider, view)
        XCTAssertEqual(status.reason, "external_environment_acknowledged")
        XCTAssertTrue(status.ownedResourcesReleased); XCTAssertFalse(status.cleanupConfirmed)
        XCTAssertFalse(status.routingVerified); XCTAssertFalse(status.protectionVerified); XCTAssertFalse(status.launchAuthorized)
        XCTAssertEqual(r.state.dispatch, original.dispatch); XCTAssertEqual(r.state.intent, original.intent)
        XCTAssertEqual(r.state.footprint, original.footprint); XCTAssertEqual(r.state.work, original.work)
        let calls = r.samples, saves = r.saves
        r.fixture.seconds += 100; r.fixture.uptime += 100
        _ = try r.confirm(provider, view) // Exact history replay is not a new permission.
        XCTAssertEqual(r.samples, calls); XCTAssertEqual(r.saves, saves)
        XCTAssertThrowsError(try provider.handle(.confirmEnvironment(id: view.instance, review: view.id, digest: String(repeating: "0", count: 64))))
        r.proxy = true
        XCTAssertThrowsError(try provider.handle(.prepare(id: UUID(), plan: original.intent!.plan, profile: original.intent!.profile)))
        XCTAssertEqual(r.archives, 1); XCTAssertEqual(r.state.reason, "external_environment_acknowledged")
        r.proxy = false
        _ = try provider.handle(.prepare(id: UUID(), plan: original.intent!.plan, profile: original.intent!.profile))
        XCTAssertEqual(r.archives, 2); XCTAssertNil(r.state.environmentReview); XCTAssertNil(r.state.usedEnvironmentReviewIDs)
    }
    func testNoFootprintAndEveryMissingOwnedProofRemainBlocked() throws {
        for failure in 0..<5 {
            let r = try Rig(); r.state.reason = "external_environment_changed"
            let provider = RouterSystemProvider(effects: r.effect())
            let view = try r.preview(provider)
            if failure == 4 { r.state.footprint = nil }
            else { r.missingProof = failure }
            XCTAssertThrowsError(try r.confirm(provider, view))
            XCTAssertNotEqual(r.state.phase, .stopped)
            XCTAssertThrowsError(try provider.handle(.previewEnvironment(id: view.instance, review: UUID())))
        }
    }
    func testPreviewIdentityCannotRenewThroughReplacementOrExpiry() throws {
        let r = try Rig(), provider = RouterSystemProvider(effects: r.effect())
        let a = try r.preview(provider)
        r.fixture.seconds += 10; r.fixture.uptime += 10
        let replay = try r.preview(provider, id: a.id)
        XCTAssertEqual(a, replay); XCTAssertEqual(r.samples, 1)
        let b = try r.preview(provider)
        XCTAssertNotEqual(a.id, b.id)
        XCTAssertThrowsError(try r.preview(provider, id: a.id))
        XCTAssertThrowsError(try r.confirm(provider, a))
        r.fixture.seconds += 60; r.fixture.uptime += 60
        XCTAssertThrowsError(try r.confirm(provider, b))
        XCTAssertEqual(r.state.usedEnvironmentReviewIDs, [a.id, b.id])
    }
    func testBothClocksAndLateSaveCannotCommitAsFresh() throws {
        for mutation in 0..<4 {
            let r = try Rig(), p = RouterSystemProvider(effects: r.effect())
            let v = try r.preview(p)
            if mutation == 0 { r.fixture.uptime += 60 }
            if mutation == 1 { r.fixture.seconds += 60 }
            if mutation == 2 { r.fixture.uptime -= 1 }
            if mutation == 3 {
                r.afterSave = { r.fixture.uptime += 60; r.fixture.seconds += 60 }
            }
            XCTAssertThrowsError(try r.confirm(p, v))
            if mutation == 3 {
                r.afterSave = nil
                XCTAssertThrowsError(try r.confirm(p, v)) // Unknown write may only be queried.
                let status = try p.handle(.status(id: v.instance))
                XCTAssertEqual(status.reason, "external_environment_acknowledged"); XCTAssertFalse(status.cleanupConfirmed)
            }
        }
    }
    func testReviewCapacityAndSamplingExpiryDoNotDiscardHistory() throws {
        let r = try Rig(), p = RouterSystemProvider(effects: r.effect())
        var last: RouterSystemEnvironmentReview?
        for _ in 0..<64 { last = try r.preview(p) }
        let revision = r.state.revision
        XCTAssertThrowsError(try r.preview(p))
        XCTAssertEqual(r.state.revision, revision)
        XCTAssertEqual(r.state.usedEnvironmentReviewIDs?.count, 64)
        XCTAssertEqual(try r.preview(p, id: last!.id), last)
        r.beforeSample = { r.fixture.uptime += 60; r.fixture.seconds += 60 }
        XCTAssertThrowsError(try r.confirm(p, last!))
        XCTAssertEqual(r.state.phase, .stopping); XCTAssertEqual(r.state.revision, revision)
    }
    func testBootChangeDuringConfirmationRejectsWithoutWriting() throws {
        let r = try Rig(), p = RouterSystemProvider(effects: r.effect()), v = try r.preview(p)
        let revision = r.state.revision
        r.beforeSample = { r.sampleBoot = UUID() }
        XCTAssertThrowsError(try r.confirm(p, v))
        XCTAssertEqual(r.state.revision, revision); XCTAssertEqual(r.state.phase, .stopping)
    }
    func testChangedEnvironmentAndSourceRejectConfirmation() throws {
        for mutate in 0..<4 {
            let r = try Rig(), p = RouterSystemProvider(effects: r.effect())
            let v = try r.preview(p)
            switch mutate {
            case 0: r.fingerprint = String(repeating: "f", count: 64)
            case 1: r.state.footprint = .init(instance: v.instance, work: r.fixture.work,
                configurationDigest: r.fixture.digest, interfaceName: "utun6", interfaceIndex: 18,
                addresses: ["198.18.0.1"], routeSignatures: ["new-route"])
            case 2: r.state.installation = .init(id: UUID(), ownerUID: 501)
            default: r.state.phase = .active; r.state.reason = "capture_observed_traffic_acceptance_pending"
            }
            XCTAssertThrowsError(try r.confirm(p, v)); XCTAssertNotEqual(r.state.phase, .stopped)
        }
    }
    func testUnknownPreviewAndConfirmOnlyQueryAcrossReopen() throws {
        for commit in [false, true] {
            for written in [false, true] {
                let r = try Rig(), p = RouterSystemProvider(effects: r.effect())
                let v = try r.preview(p)
                r.failSave = true; r.writeBeforeFailure = written
                if commit { XCTAssertThrowsError(try r.confirm(p, v)) }
                else { XCTAssertThrowsError(try r.preview(p)) }
                let samples = r.samples
                XCTAssertThrowsError(try r.confirm(p, v)); XCTAssertEqual(r.samples, samples)
                r.failSave = false
                _ = try p.handle(.status(id: v.instance))
                let reopened = RouterSystemProvider(effects: r.effect())
                _ = try reopened.handle(.status(id: v.instance))
                XCTAssertEqual(r.samples, samples)
                XCTAssertEqual(r.state.phase == .stopped, commit && written)
            }
        }
    }
    func testExplicitStopAndOrdinaryRestorationKeepReviewHistory() throws {
        let r = try Rig(), p = RouterSystemProvider(effects: r.effect()), v = try r.preview(p)
        _ = try p.handle(.stop(id: v.instance))
        XCTAssertNil(r.state.environmentReview); XCTAssertEqual(r.state.usedEnvironmentReviewIDs, [v.id])
        XCTAssertThrowsError(try r.preview(p, id: v.id))
        r.externalPreserved = true
        XCTAssertTrue(try p.handle(.status(id: v.instance)).cleanupConfirmed)
        r.failArchive = true
        XCTAssertThrowsError(try p.handle(.prepare(id: UUID(), plan: r.fixture.intent.plan, profile: r.fixture.intent.profile)))
        XCTAssertEqual(r.state.phase, .stopped); XCTAssertEqual(r.state.usedEnvironmentReviewIDs, [v.id])
    }
    func testJournalAndWireStrictnessAndNewRequestRoundtrip() throws {
        let r = try Rig(), p = RouterSystemProvider(effects: r.effect()), v = try r.preview(p)
        for request: RouterSystemRequest in [.previewEnvironment(id: v.instance, review: v.id),
            .confirmEnvironment(id: v.instance, review: v.id, digest: v.digest)] {
            let bytes = try RouterSystemClient.encode(request)
            XCTAssertEqual(try RouterSystemClient.encode(RouterSystemDecoder.decode(bytes)), bytes)
        }
        let current = try JSONEncoder().encode(r.state)
        XCTAssertNoThrow(try RouterSystemJournalDecoder.decode(current))
        for mutation in 0..<5 {
            var state = r.state
            if mutation == 0 { state.usedEnvironmentReviewIDs = [] }
            if mutation == 1 { state.usedEnvironmentReviewIDs = [v.id, v.id] }
            if mutation == 2 { state.usedEnvironmentReviewIDs = [UUID()] }
            if mutation == 3 { state.reason = "owned_stop_pending" }
            if mutation == 4 { state.phase = .stopped; state.reason = "external_environment_acknowledged" }
            XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONEncoder().encode(state)))
        }
        let status = try r.confirm(p, v)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(status)) as? [String: Any])
        XCTAssertFalse(try RouterSystemStatus.decodeWire(object).cleanupConfirmed)
        object["cleanupConfirmed"] = true; XCTAssertThrowsError(try RouterSystemStatus.decodeWire(object))
        object["cleanupConfirmed"] = false
        var review = try XCTUnwrap(object["environmentReview"] as? [String: Any])
        review["extra"] = "ignored?"; object["environmentReview"] = review
        XCTAssertThrowsError(try RouterSystemStatus.decodeWire(object))
        object.removeValue(forKey: "environmentReview")
        XCTAssertThrowsError(try RouterSystemStatus.decodeWire(object))
    }
    func testDurableArchivePreservesBytesAndRejectsPartialHistory() throws {
        for corrupt in [false, true] {
            let r = try Rig(), p = RouterSystemProvider(effects: r.effect()), v = try r.preview(p)
            _ = try r.confirm(p, v)
            var persisted = r.state; let old = try r.fixture.journal.load()
            persisted.revision = UUID(); try r.fixture.journal.save(persisted, expecting: old.revision)
            let before = try Data(contentsOf: r.fixture.url.appendingPathComponent("journal.json"))
            let dir = try r.fixture.directory.child("stage-" + v.instance.uuidString.lowercased())
            if corrupt { try dir.create("environment-history.json", data: Data("partial".utf8)) }
            let actual = try r.fixture.journal.load()
            if corrupt { XCTAssertThrowsError(try r.fixture.journal.archiveEnvironment(actual)) }
            else {
                try r.fixture.journal.archiveEnvironment(actual)
                let reopened = try RouterSystemJournalStore(directory: r.fixture.directory, installation: r.fixture.identity)
                try reopened.archiveEnvironment(reopened.load())
                XCTAssertEqual(try dir.read("environment-history.json", maximum: RouterSystemJournalDecoder.maximumBytes), before)
            }
            XCTAssertEqual(try Data(contentsOf: r.fixture.url.appendingPathComponent("journal.json")), before)
        }
    }
    func testArchiveSyncFailuresPreserveOldJournalAndRetrySameHistory() throws {
        for failAt in 1...3 {
            let r = try Rig(), p = RouterSystemProvider(effects: r.effect()), v = try r.preview(p)
            _ = try r.confirm(p, v)
            var persisted = r.state; let old = try r.fixture.journal.load()
            persisted.revision = UUID(); try r.fixture.journal.save(persisted, expecting: old.revision)
            let before = try Data(contentsOf: r.fixture.url.appendingPathComponent("journal.json"))
            var calls = 0, inject = true
            let store = try RouterSystemJournalStore(directory: r.fixture.directory, installation: r.fixture.identity,
                synchronize: { fd in
                    calls += 1
                    return inject && calls == failAt ? -1 : fsync(fd)
                })
            let state = try store.load()
            XCTAssertThrowsError(try store.archiveEnvironment(state))
            XCTAssertEqual(calls, failAt)
            XCTAssertEqual(try Data(contentsOf: r.fixture.url.appendingPathComponent("journal.json")), before)
            inject = false
            try store.archiveEnvironment(store.load())
            let directory = try r.fixture.directory.child("stage-" + v.instance.uuidString.lowercased())
            XCTAssertEqual(try directory.read("environment-history.json", maximum: RouterSystemJournalDecoder.maximumBytes), before)
        }
    }
    func testEnvironmentDigestIncludesDNSInterfacesBootButExcludesCaptureTime() throws {
        let f = try RouterSystemDispatchFixture(), original = f.snapshot()
        f.seconds += 10; f.uptime += 10
        XCTAssertEqual(try original.environmentDigest(), try f.snapshot().environmentDigest())
        f.dns = f.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54")
        XCTAssertNotEqual(try original.environmentDigest(), try f.snapshot().environmentDigest())
        XCTAssertEqual(try f.snapshot().changes(from: original), ["dns"])
        let newBoot = RouterSystemBaselineSnapshot(captured: .init(bootID: UUID(), uptime: 1, date: f.clock.date),
            networkFingerprint: original.networkFingerprint, interfaces: original.interfaces,
            routesIPv4: original.routesIPv4, routesIPv6: original.routesIPv6, dns: original.dns)
        XCTAssertEqual(try newBoot.changes(from: original), ["boot"])
        XCTAssertNotEqual(try newBoot.environmentDigest(), try original.environmentDigest())
        let changedInterface = RouterSystemBaselineSnapshot(captured: original.captured,
            networkFingerprint: original.networkFingerprint, interfaces: original.interfaces.map {
                .init(name: $0.name, index: $0.index, flags: $0.flags, mtu: $0.mtu + 1, addresses: $0.addresses)
            }, routesIPv4: original.routesIPv4, routesIPv6: original.routesIPv6, dns: original.dns)
        XCTAssertEqual(try changedInterface.changes(from: original), ["interfaces"])
        XCTAssertNotEqual(try changedInterface.environmentDigest(), try original.environmentDigest())
        let changedIPv6 = RouterSystemBaselineSnapshot(captured: original.captured,
            networkFingerprint: original.networkFingerprint, interfaces: original.interfaces,
            routesIPv4: original.routesIPv4, routesIPv6: original.routesIPv6 + "2001:db8:99::/64 fe80::1 UGS en0\n", dns: original.dns)
        XCTAssertEqual(try changedIPv6.changes(from: original), ["routes"])
        XCTAssertNotEqual(try changedIPv6.environmentDigest(), try original.environmentDigest())
    }
}

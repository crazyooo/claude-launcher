import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallPlanTests: XCTestCase {
    private func node(_ inode: UInt64) -> RouterSystemInstallNode {
        var value = stat(); value.st_dev = 1; value.st_ino = inode; value.st_birthtimespec.tv_sec = 1
        return .init(value)
    }
    private func candidate() -> RouterSystemInstallCandidate {
        let id = UUID(), helper = String(repeating: "a", count: 64)
        return .init(version: 1, transaction: id, packageID: UUID(), action: .install,
            installation: .init(id: id, ownerUID: 501), helperDigest: helper,
            destinationParent: node(1), launchDaemonsParent: node(2),
            files: RouterSystemInstallFile.allCases.map {
                .init(file: $0, before: nil, afterDigest: $0 == .core ? RouterCoreRelease.executableSHA256 : helper, afterCount: 1)
            }, preserved: nil, originalJob: .absent, retired: nil, retiredMarker: nil)
    }
    private func altered<T: Codable>(_ value: T, _ change: (inout [String: Any]) -> Void) throws -> T {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: RouterSystemInstallEncoding.encode(value)) as? [String: Any])
        change(&object)
        return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: object))
    }
    func testInitialJournalIsDerivedOnlyFromConfirmedIdentity() throws {
        let value = candidate(), bytes = try value.initialJournalBytes()
        XCTAssertEqual(bytes, try value.initialJournalBytes())
        let journal = try RouterSystemJournalDecoder.decode(bytes)
        XCTAssertEqual(journal.revision, value.transaction)
        XCTAssertEqual(journal.installation, value.installation)
        XCTAssertEqual(journal.phase, .idle)
        XCTAssertNil(journal.accepted)
    }
    func testCandidateRejectsChangedCorePinAndUnapprovedIdentity() throws {
        let original = candidate(); try original.validate()
        let invalid = try altered(original) { object in
            var files = object["files"] as! [[String: Any]]
            files[1]["afterDigest"] = String(repeating: "b", count: 64); object["files"] = files
        }
        XCTAssertThrowsError(try invalid.validate())
        let changed = try altered(original) { $0["transaction"] = UUID().uuidString }
        XCTAssertThrowsError(try changed.validate())
        XCTAssertNotEqual(try original.digest, try changed.digest)
    }
    func testCanonicalEvidenceRejectsUnknownFieldsAndNoncanonicalBytes() throws {
        let value = candidate(), data = try RouterSystemInstallEncoding.encode(value)
        XCTAssertEqual(try RouterSystemInstallEncoding.decode(RouterSystemInstallCandidate.self, data), value)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object["launchAuthorized"] = true
        XCTAssertThrowsError(try RouterSystemInstallEncoding.decode(RouterSystemInstallCandidate.self,
            JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])))
        XCTAssertThrowsError(try RouterSystemInstallEncoding.decode(RouterSystemInstallCandidate.self, data + Data("\n".utf8)))
    }
    func testJobRejectsWorkWithoutRegistrationAndInvalidBirth() throws {
        let work = RouterSystemWork(bootID: UUID(), pid: 12, birthSeconds: 10, birthMicroseconds: 0)
        XCTAssertThrowsError(try RouterSystemInstallJob(registered: false, work: work).validate())
        XCTAssertThrowsError(try RouterSystemInstallJob(registered: true,
            work: .init(bootID: work.bootID, pid: 1, birthSeconds: 10, birthMicroseconds: 0)).validate())
        try RouterSystemInstallJob(registered: true, work: work).validate()
    }
    func testPlanBindsEveryParentReceiptAndRootImage() throws {
        let candidate = candidate(), transaction = node(3)
        let treeNodes = (root: node(4), bin: node(5), core: node(6), run: node(7), state: node(8))
        let files = candidate.files.map { file -> RouterSystemInstallFileReceipt in
            let parent: RouterSystemInstallNode
            switch file.file { case .helper: parent = treeNodes.bin; case .core: parent = treeNodes.core
            case .launchd: parent = candidate.launchDaemonsParent; default: parent = treeNodes.root }
            return .init(version: 1, transaction: candidate.transaction, file: file.file, transactionDirectory: transaction,
                targetDirectory: parent, before: nil, after: .init(node: node(20 + UInt64(RouterSystemInstallFile.allCases.firstIndex(of: file.file)!)),
                    digest: file.afterDigest!, count: file.afterCount!))
        }
        let journal = try candidate.initialJournalBytes()
        let entries = RouterSystemInstallRoot.File.allCases.map { kind -> RouterSystemInstallRoot.Entry in
            let image = kind.installFile.flatMap { file in files.first(where: { $0.file == file })?.after }
                ?? .init(node: node(30), digest: RouterSystemObservation.hash(kind == .journal ? journal : Data()), count: kind == .journal ? journal.count : 0)
            return .init(kind: kind, image: image)
        }
        let root = RouterSystemInstallRoot.Receipt(version: 1, transaction: candidate.transaction, transactionDirectory: transaction,
            destinationParent: candidate.destinationParent, tree: .init(root: treeNodes.root, bin: treeNodes.bin,
                core: treeNodes.core, run: treeNodes.run, state: treeNodes.state, files: entries))
        let plan = RouterSystemInstallPlan(version: 1, candidate: candidate, files: files, rootReceipt: root)
        try plan.validate()
        for key in ["transactionDirectory", "targetDirectory"] {
            let bad = try altered(plan) { object in
                var files = object["files"] as! [[String: Any]]
                var parent = files[0][key] as! [String: Any]; parent["inode"] = 99
                files[0][key] = parent; object["files"] = files
            }
            XCTAssertThrowsError(try bad.validate(), key)
        }
        let badRoot = try altered(plan) { object in
            var root = object["rootReceipt"] as! [String: Any], tree = root["tree"] as! [String: Any]
            var entries = tree["files"] as! [[String: Any]], image = entries[0]["image"] as! [String: Any]
            image["count"] = 2; entries[0]["image"] = image; tree["files"] = entries; root["tree"] = tree; object["rootReceipt"] = root
        }
        XCTAssertThrowsError(try badRoot.validate())
    }
    func testOptionalSocketEvidencePreservesHistoricalEncoding() throws {
        let value = candidate(), bytes = try RouterSystemInstallEncoding.encode(value)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertNil(object["priorSocket"])
        XCTAssertEqual(try RouterSystemInstallEncoding.encode(RouterSystemInstallEncoding.decode(RouterSystemInstallCandidate.self, bytes)), bytes)
        let proof = RouterSystemInstallServiceProof(installation: value.installation, registered: false, socketNode: nil)
        let proofBytes = try RouterSystemInstallEncoding.encode(proof)
        XCTAssertNil((try JSONSerialization.jsonObject(with: proofBytes) as? [String: Any])?["residualSocketNode"])
        XCTAssertEqual(try RouterSystemInstallEncoding.encode(RouterSystemInstallEncoding.decode(RouterSystemInstallServiceProof.self, proofBytes)), proofBytes)
        var invalid = value; invalid.priorSocket = node(99)
        XCTAssertThrowsError(try invalid.validate()) // First install cannot adopt a pre-existing socket.
    }
}

final class RouterSystemInstallServiceTests: XCTestCase {
    private func listing(_ extra: String = "", pid: String = "\tpid = 4242\n") -> Data {
        Data(("system/" + RouterSystemLayout.label + " = {\n" +
            "\tpath = " + RouterSystemLayout.launchDaemons + "/" + RouterSystemInstallFile.launchd.leaf + "\n" +
            "\tprogram = " + RouterSystemLayout.helper + "\n\tdomain = system\n\tstate = waiting\n" +
            "\targuments = {\n\t\t" + RouterSystemLayout.helper + "\n\t\t--host\n\t}\n" + pid + extra + "}\n").utf8)
    }
    func testExactJobAndDormantJobParsing() throws {
        XCTAssertEqual(try RouterSystemInstallJobParser.pid(listing()), 4242)
        XCTAssertNil(try RouterSystemInstallJobParser.pid(listing(pid: "")))
        for invalid in ["-1", "0", "1", "04242", "4242 ", "2147483648"] {
            XCTAssertThrowsError(try RouterSystemInstallJobParser.pid(listing(pid: "\tpid = " + invalid + "\n")))
        }
    }
    func testDuplicateOrForeignJobAndNestedLookalikesAreRejected() throws {
        XCTAssertThrowsError(try RouterSystemInstallJobParser.pid(listing("\tprogram = /tmp/foreign\n")))
        XCTAssertEqual(try RouterSystemInstallJobParser.pid(listing("\tenvironment = {\n\t\tprogram = ignored\n\t}\n")), 4242)
        XCTAssertThrowsError(try RouterSystemInstallJobParser.pid(listing("\tenvironment = {\n\tprogram = forged\n\t}\n")))
        let text = String(decoding: listing(), as: UTF8.self)
        for (old, new) in [("\tprogram = ", "\t\tprogram = "), ("\tdomain = system", "\tdomain = gui/501"),
                           ("\t\t--host", "\t\t--core-child"), ("\t\t--host", "\t\t--host\n\t\tunexpected")] {
            XCTAssertThrowsError(try RouterSystemInstallJobParser.pid(Data(text.replacingOccurrences(of: old, with: new).utf8)))
        }
        let running = String(decoding: listing(pid: ""), as: UTF8.self).replacingOccurrences(of: "state = waiting", with: "state = running")
        XCTAssertThrowsError(try RouterSystemInstallJobParser.pid(Data(running.utf8)))
    }

    func testModernLaunchctlLWCRCdhashListingParsesPid() throws {
        // Fixture mirrors macOS 15+ launchctl print: LWCR/cdhash nests use `=> {` and deeper tabs.
        let text = """
            system/\(RouterSystemLayout.label) = {
            \tpath = \(RouterSystemLayout.launchDaemons)/\(RouterSystemInstallFile.launchd.leaf)
            \tprogram = \(RouterSystemLayout.helper)
            \tstate = running
            \targuments = {
            \t\t\(RouterSystemLayout.helper)
            \t\t--host
            \t}
            \tLWCR = {
            \t\t"reqs" => {
            \t\t\t"cdhash" => {
            \t\t\t\t"$in" => [
            \t\t\t\t\t0 = \t\t\t\t]
            \t\t\t}
            \t\t}
            \t\t"vers" => 1
            \t}
            \tdomain = system
            \tpid = 560
            }
            """
        XCTAssertEqual(try RouterSystemInstallJobParser.pid(Data(text.utf8)), 560)
    }
    func testPlistIsSocketDemandOnlyWithFixedPathsAndNumericOwner() throws {
        let bytes = try RouterSystemInstallPlist.bytes(ownerUID: 501)
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: bytes, format: nil) as? [String: Any])
        XCTAssertEqual(plist["ProgramArguments"] as? [String], [RouterSystemLayout.helper, "--host"])
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, false)
        XCTAssertEqual(plist["KeepAlive"] as? Bool, false)
        XCTAssertEqual(plist["AbandonProcessGroup"] as? Bool, false)
        let sockets = try XCTUnwrap(plist["Sockets"] as? [String: [String: Any]])
        XCTAssertEqual(sockets["Control"]?["SockPathOwner"] as? Int, 501)
        XCTAssertEqual(sockets["Control"]?["SockPathMode"] as? Int, 384)
        XCTAssertEqual(sockets["Control"]?["SockPathName"] as? String, RouterSystemLayout.socket)
        XCTAssertEqual(try RouterSystemInstallPlist.bytes(ownerUID: 501), bytes)
        XCTAssertThrowsError(try RouterSystemInstallPlist.bytes(ownerUID: 0))
    }

}

final class RouterSystemInstallerProcessTests: XCTestCase {
    func testOldBootSettlesWithoutSamplingReusedPIDOrGroup() throws {
        let old = RouterSystemWork(bootID: UUID(), pid: 4512, birthSeconds: 12, birthMicroseconds: 0), now = UUID()
        let reader = RouterSystemKernelObservation.Reader(boot: { now }, sample: { _, _ in
            XCTFail("A PID in the new boot is irrelevant"); return .unknown
        }, group: { _ in XCTFail("A PGID in the new boot is irrelevant"); return [4512] })
        XCTAssertEqual(reader.formerHostGroup(old), .formerBootEnded)
        var count = 0
        let unstable = RouterSystemKernelObservation.Reader(boot: { count += 1; return count == 1 ? now : UUID() },
            sample: { _, _ in .unknown }, group: { _ in [] })
        XCTAssertEqual(unstable.formerHostGroup(old), .unknown)
    }
    func testSameBootRequiresOriginalExitAndBothGroupSamplesEmpty() {
        let old = RouterSystemWork(bootID: UUID(), pid: 4512, birthSeconds: 12, birthMicroseconds: 0)
        var reads = 0
        let clear = RouterSystemKernelObservation.Reader(boot: { old.bootID }, sample: { _, _ in .absent },
            group: { _ in reads += 1; return [] })
        XCTAssertEqual(clear.formerHostGroup(old), .formerHostGroupEmpty)
        XCTAssertEqual(reads, 2)
        let occupied = RouterSystemKernelObservation.Reader(boot: { old.bootID }, sample: { _, _ in .absent }, group: { _ in [999] })
        XCTAssertEqual(occupied.formerHostGroup(old), .unsettled)
        let unknown = RouterSystemKernelObservation.Reader(boot: { old.bootID }, sample: { _, _ in .unknown }, group: { _ in [] })
        XCTAssertEqual(unknown.formerHostGroup(old), .unknown)
    }


}

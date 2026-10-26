import Foundation
import Darwin

/// Declarative packet-filter fail-closed ruleset derived from
/// `RouterCoreExitFailClosed.Recipe`. Pure generation — never calls `pfctl`.
///
/// Review notes for other agents:
/// - Anchor is fixed and distinct from legacy `clguard_*` destination guards.
/// - Empty-subject (direct-only) plans are **not applicable**; do not invent a global block.
/// - Domain subjects become table placeholders; filling IPs is a separate discovery step
///   (`generate --address …` or existing `pf_policy.discover`; no auto fill-table yet).
/// - Process-path subjects are recorded as **unsupported on macOS pf** in this package
///   (no silent drop-all).
public enum RouterPFArmingRuleset {
    public static let policyVersion = 1
    public static let anchorName = "claude_router_failclosed"
    public static let tableName = "claude_router_failclosed_dst"

    public struct Artifact: Equatable, Sendable {
        public let policyVersion: Int
        public let anchorName: String
        public let tableName: String
        public let applicable: Bool
        public let designedLayer: RouterCoreExitFailClosed.SystemLayerKind
        public let subjectCount: Int
        public let planDigest: String?
        public let pfConf: String
        public let sourceSHA256: String
        public let blockers: [String]
        public let notes: [String]
        public let routingVerified: Bool
        public let accepted: Bool
        public let summary: String
    }

    public static func generate(recipe: RouterCoreExitFailClosed.Recipe,
                                planDigest: String? = nil,
                                destinationAddresses: [String] = [],
                                transportExclusions: [String] = []) -> Artifact {
        var blockers: [String] = []
        var notes = recipe.notes
        notes.append("anchor=\(anchorName); distinct from legacy clguard_* destination guards.")
        notes.append("Generation never invokes pfctl; use tools/router_pf_failclosed.py for dry-run/apply.")

        if !recipe.requiresIndependentLayer {
            blockers.append("no_protected_subjects_fail_closed_not_applicable")
            let body = "# fail-closed not applicable: no protected subjects\n"
            return artifact(recipe: recipe, planDigest: planDigest, applicable: false,
                            pfConf: body, blockers: blockers, notes: notes,
                            summary: "规则集不适用（无受保护 subjects）。不生成 block；routing_verified=false · accepted=false。")
        }

        var hasDomain = false
        var hasProcess = false
        var hasDefault = false
        for subject in recipe.subjects {
            switch subject.kind {
            case .domainExact, .domainSuffix: hasDomain = true
            case .processPath: hasProcess = true
            case .defaultBlock: hasDefault = true
            }
        }
        if hasProcess {
            // Partial coverage is not fail-closed; a domain+processPath selector would also be
            // widened to every process by a destination-only block.
            blockers.append("process_path_subjects_unsupported_on_macos_pf")
            notes.append("processPath subjects are listed for review only; this ruleset does not emit user/process pf matches.")
        }
        if hasDefault {
            // defaultBlock without destinations would be a global out-block — refuse to emit.
            blockers.append("default_block_subject_requires_explicit_destination_scope")
            notes.append("defaultBlock subjects must not become 'block all'; they stay as review blockers until scoped.")
        }

        let addrs = normalizeAddresses(destinationAddresses)
        if hasDomain && addrs.isEmpty {
            blockers.append("destination_table_empty_fill_required_before_apply")
            notes.append("table <\(tableName)> is empty until --address / DNS discovery supplies public destinations.")
        }
        let excluded = Set(transportExclusions.compactMap(addressBytes))
        var addressRejected = false
        for addr in addrs {
            if !isPublicUnicast(addr) {
                blockers.append("destination_address_not_public_unicast:\(addr)")
                addressRejected = true
            } else if let bytes = addressBytes(addr), excluded.contains(bytes) {
                blockers.append("destination_overlaps_proxy_transport:\(addr)")
                addressRejected = true
            }
        }

        let applicable = hasDomain && !hasProcess && !hasDefault && !addressRejected
        // Never emit loadable block rules when not applicable.
        if !applicable {
            let stub = [
                "# \(anchorName) — NOT applicable; no loadable rules emitted",
                "# policyVersion=\(policyVersion) designedLayer=\(recipe.designedLayer.rawValue)",
                "# subjects=\(recipe.subjects.count) planDigest=\(planDigest ?? "nil")",
                "# blockers=\(Array(Set(blockers)).sorted().joined(separator: ","))",
                ""
            ].joined(separator: "\n")
            return artifact(recipe: recipe, planDigest: planDigest, applicable: false,
                            pfConf: stub, blockers: blockers, notes: notes,
                            summary: "规则集不适用；未发射可加载 block。routing_verified=false · accepted=false。")
        }

        // Per-host block lines (same shape as pf_policy / pf_guard). macOS pfctl
        // rejected multi-line `table <…> persist { … }` braces in live dry-run.
        var lines: [String] = [
            "# claude_router_failclosed — generated; do not hand-edit for apply",
            "# policyVersion=\(policyVersion) designedLayer=\(recipe.designedLayer.rawValue)",
            "# subjects=\(recipe.subjects.count) planDigest=\(planDigest ?? "nil")",
            "# table_name=\(tableName) (logical; emit is per-host block lines)",
        ]
        if addrs.isEmpty {
            lines.append("# empty — fill with destinationAddresses before apply")
        } else {
            for addr in addrs.sorted() {
                let family = addr.contains(":") ? "inet6" : "inet"
                lines.append("block drop out quick \(family) from any to \(addr)")
            }
        }
        let pfConf = lines.joined(separator: "\n") + "\n"

        let summary: String
        if addrs.isEmpty {
            summary = "已生成 anchor 草稿（无目的地址）。apply 前须填公网 IP。armed 不得被本生成步骤声称。"
        } else {
            summary = "已生成 anchor 规则（\(addrs.count) 个目的）。仍须 dry-run/显式 apply；routing_verified=false · accepted=false。"
        }
        return artifact(recipe: recipe, planDigest: planDigest, applicable: true,
                        pfConf: pfConf, blockers: blockers, notes: notes, summary: summary)
    }

    public static func generate(plan: RouterPlan,
                                profile: RouterSystemProfile = .init(resolver: .cloudflare),
                                destinationAddresses: [String] = []) throws -> Artifact {
        let digest = try RouterSystemCompiler.digest(plan: plan, profile: profile)
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        return generate(recipe: recipe, planDigest: digest, destinationAddresses: destinationAddresses,
                        transportExclusions: plan.proxies.map(\.host))
    }

    private static func artifact(recipe: RouterCoreExitFailClosed.Recipe, planDigest: String?,
                                 applicable: Bool, pfConf: String, blockers: [String],
                                 notes: [String], summary: String) -> Artifact {
        let unique = Array(Set(blockers)).sorted()
        return .init(
            policyVersion: policyVersion,
            anchorName: anchorName,
            tableName: tableName,
            applicable: applicable,
            designedLayer: recipe.designedLayer,
            subjectCount: recipe.subjects.count,
            planDigest: planDigest,
            pfConf: pfConf,
            sourceSHA256: RouterSystemObservation.hash(Data(pfConf.utf8)),
            blockers: unique,
            notes: notes,
            routingVerified: false,
            accepted: false,
            summary: summary)
    }

    private static func normalizeAddresses(_ values: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for raw in values {
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, value.count <= 64, !seen.contains(value) else { continue }
            seen.insert(value)
            out.append(value)
        }
        return out
    }

    /// inet_pton bytes (4 or 16), or nil for anything that is not a literal host address.
    static func addressBytes(_ value: String) -> [UInt8]? {
        guard !value.utf8.contains(0) else { return nil }
        var v4 = in_addr(), v6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        if value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }

    /// Global unicast host only. Mirrors Python `ipaddress.is_global and not is_multicast`
    /// for the ranges that matter here — notably Mihomo fake-ip 198.18.0.0/15 and CGNAT.
    static func isPublicUnicast(_ value: String) -> Bool {
        guard let b = addressBytes(value) else { return false }
        if b.count == 16 {
            // 2000::/3 only; exclude 2001::/23 (Teredo/ORCHID/benchmark…), 2001:db8::/32, 2002::/16.
            guard b[0] & 0xE0 == 0x20 else { return false }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] < 0x02 { return false }
            if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8 { return false }
            if b[0] == 0x20 && b[1] == 0x02 { return false }
            return true
        }
        switch (b[0], b[1], b[2]) {
        case (0, _, _), (10, _, _), (127, _, _): return false
        case (100, 64...127, _): return false          // CGNAT
        case (169, 254, _): return false
        case (172, 16...31, _): return false
        case (192, 0, 0), (192, 0, 2), (192, 168, _): return false
        case (198, 18...19, _): return false           // benchmark / Mihomo fake-ip
        case (198, 51, 100), (203, 0, 113): return false
        case (224..., _, _): return false              // multicast + reserved + broadcast
        default: return true
        }
    }
}

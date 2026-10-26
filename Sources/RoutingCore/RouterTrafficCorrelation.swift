import Foundation

struct RouterTrafficRuleSignature {
    let ordinal: Int
    let ruleID: UUID?
    let udpGuard: Bool
    let type: String
    let payload: String
    let chain: String
    let configurationLine: String
}

/// Correlation signatures use the pinned core's display syntax, not config syntax.
/// Compare the entire generated catalog with the existing compiler to detect drift.
enum RouterTrafficRuleCatalog {
    private struct Predicate {
        let configuration: String
        let type: String
        let payload: String
    }
    static func make(_ plan: RouterPlan) throws -> [RouterTrafficRuleSignature] {
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else {
            throw RouterTrafficEvidenceError.invalidPlan
        }
        let proxies = Dictionary(uniqueKeysWithValues: plan.proxies.map { ($0.id, $0) })
        func chain(_ destination: RouterDestination) throws -> String {
            switch destination.kind {
            case .direct: return "DIRECT"
            case .block: return "REJECT"
            case .proxy:
                guard let id = destination.proxyID, let proxy = proxies[id] else { throw RouterTrafficEvidenceError.invalidPlan }
                return proxy.coreName
            }
        }
        var entries: [RouterTrafficRuleSignature] = []
        func append(_ id: UUID?, _ predicates: [Predicate], _ guardUDP: Bool, _ target: String) {
            let type: String, payload: String, line: String
            if predicates.isEmpty {
                type = "Match"; payload = ""; line = "MATCH," + target
            } else if predicates.count == 1 {
                type = predicates[0].type; payload = predicates[0].payload
                line = predicates[0].configuration + "," + target
            } else {
                type = "AND"
                payload = "(" + predicates.map { "(" + $0.type + "," + $0.payload + ")" }.joined(separator: " && ") + ")"
                line = "AND,(" + predicates.map { "(" + $0.configuration + ")" }.joined(separator: ",") + ")," + target
            }
            entries.append(.init(ordinal: entries.count, ruleID: id, udpGuard: guardUDP,
                                 type: type, payload: payload, chain: target, configurationLine: line))
        }
        let udp = Predicate(configuration: "NETWORK,UDP", type: "Network", payload: "udp")
        for rule in plan.rules {
            var predicates: [Predicate] = []
            if let path = rule.selector.processPath {
                predicates.append(.init(configuration: "PROCESS-PATH," + path, type: "ProcessPath", payload: path))
            }
            if let domain = rule.selector.domain {
                let exact = domain.kind == .exact, value = domain.value.lowercased()
                predicates.append(.init(configuration: (exact ? "DOMAIN," : "DOMAIN-SUFFIX,") + value,
                                        type: exact ? "Domain" : "DomainSuffix", payload: value))
            }
            if MihomoRoutingCompiler.blocksUDP(rule.destination, proxies: proxies) {
                append(rule.id, predicates + [udp], true, "REJECT")
            }
            append(rule.id, predicates, false, try chain(rule.destination))
        }
        if MihomoRoutingCompiler.blocksUDP(plan.defaultDestination, proxies: proxies) {
            append(nil, [udp], true, "REJECT")
        }
        append(nil, [], false, try chain(plan.defaultDestination))
        var publicPlan = plan
        for index in publicPlan.proxies.indices { publicPlan.proxies[index].credentialReference = nil }
        guard let compiled = try MihomoRoutingCompiler.preview(publicPlan).fragment,
              compiled.rules == entries.map(\.configurationLine) else { throw RouterTrafficEvidenceError.invalidPlan }
        return entries
    }
}

/// A testable declaration, not a held-socket capability or authenticated measurement.
/// Future capture must independently bracket process birth and local socket lifetime.
struct RouterTrafficProbeTarget {
    let host: String
    let port: UInt16
    let transport: RouterTrafficTransport

    /// Network endpoint identity only. Does not authenticate an echo service,
    /// certificate, HTTP resource or remote address family.
    func digest() throws -> String {
        guard port > 0, RouterValidation.validHost(host) else { throw RouterTrafficEvidenceError.invalidReceipt }
        struct Canonical: Encodable {
            let version: Int
            let domain: String?
            let address: Data?
            let port: UInt16
            let transport: RouterTrafficTransport
        }
        let address = RouterTrafficAddress.bytes(host)
        return RouterSystemObservation.hash(try RouterTrafficCodec.encode(Canonical(
            version: 1, domain: address == nil ? host.lowercased() : nil,
            address: address, port: port, transport: transport)))
    }
}

struct RouterTrafficAttemptFacts {
    let id: RouterTrafficCase
    let attempt: UUID
    let session: UUID
    let bindingDigest: String
    let nonce: UUID
    let interval: RouterTrafficInterval
    let process: RouterSystemWork
    let processPath: String
    let sourceIP: String
    let sourcePort: UInt16
    let destinationIP: String
    let destinationPort: UInt16
    let domain: String?
    let target: RouterTrafficProbeTarget
}

struct RouterTrafficCorrelationResult: Encodable {
    enum Relation: String, Encodable { case insufficient, contradictory, candidateUnverified }
    let relation: Relation
    let connection: UUID?
    let compiledOrdinal: Int?
    let reason: String
    let gaps: [RouterTrafficGap] = [.ruleUncorrelated, .liveCollectorUnavailable]
    let collectorAuthenticated = false
    let canPromoteAccepted = false
}

enum RouterTrafficCorrelator {
    private struct FlowIdentity {
        let transport: RouterTrafficTransport
        let processPath: String
        let sourceIP: String
        let sourcePort: UInt16
        let destinationIP: String
        let destinationPort: UInt16
        let domain: String?
    }
    private static func result(_ relation: RouterTrafficCorrelationResult.Relation, _ reason: String,
                               _ connection: UUID? = nil, _ ordinal: Int? = nil) -> RouterTrafficCorrelationResult {
        .init(relation: relation, connection: connection, compiledOrdinal: ordinal, reason: reason)
    }
    private static func expectedRule(_ explanation: RouterExplanation, plan: RouterPlan) throws -> RouterTrafficRuleSignature {
        let signatures = try RouterTrafficRuleCatalog.make(plan).filter {
            $0.ruleID == explanation.ruleID && $0.udpGuard == (explanation.reason == "proxy_udp_not_supported")
        }
        guard signatures.count == 1, let rule = signatures.first else { throw RouterTrafficEvidenceError.invalidPlan }
        return rule
    }
    /// Shared checks for declared attempts and held own-socket observations.
    /// Each caller must establish its own identity, interval and semantic evidence first.
    private static func match(_ flow: FlowIdentity, startedAfter: Date, observedBefore: Date,
                              trackers: [RouterTrafficTracker], rule: RouterTrafficRuleSignature,
                              dnsBound: Bool, priorTrackerIDs: Set<UUID> = []) throws -> RouterTrafficCorrelationResult {
        guard trackers.count <= RouterConnectionProjection.connectionLimit,
              priorTrackerIDs.count <= RouterConnectionProjection.connectionLimit,
              Set(trackers.map(\.id)).count == trackers.count else { throw RouterTrafficEvidenceError.invalidReceipt }
        let candidates = trackers.filter {
            $0.origin == "Tun" && $0.transport == flow.transport.rawValue &&
            RouterTrafficAddress.equal($0.sourceIP, flow.sourceIP) && $0.sourcePort == flow.sourcePort &&
            $0.destinationPort == flow.destinationPort && $0.startedAt.timeIntervalSince1970.isFinite &&
            // At Date's precision, equality cannot distinguish a rounded older
            // connection from a new one. Keep that boundary uncertain.
            $0.startedAt > startedAfter && $0.startedAt < observedBefore
        }
        guard candidates.count == 1, let row = candidates.first else {
            return result(.insufficient, candidates.isEmpty ? "no_current_probe_tracker" : "ambiguous_probe_tracker")
        }
        // Do not filter old IDs before uniqueness: that could hide a second candidate.
        guard !priorTrackerIDs.contains(row.id) else {
            return result(.insufficient, "tracker_predates_own_connect", row.id)
        }
        guard RouterValidation.validProcessPath(row.processPath), row.processPath == flow.processPath else {
            return result(.insufficient, "full_process_path_missing_or_changed")
        }
        guard !row.hasOverride, row.sniffHost == nil || row.sniffHost?.lowercased() == row.host?.lowercased() else {
            return result(.insufficient, "unmodelled_override_or_sniff_domain", row.id)
        }
        guard row.host?.lowercased() == flow.domain?.lowercased() else {
            return result(.contradictory, "probe_domain_mismatch", row.id)
        }
        switch row.dnsMode {
        case "fake-ip":
            guard dnsBound else {
                return result(.insufficient, "fake_ip_dns_mapping_not_bound", row.id)
            }
            // The core clears or rewrites this address, including 0.0.0.0 for UDP
            // REJECT. It is not independent upstream family or egress evidence.
            if let value = row.destinationIP, RouterTrafficAddress.bytes(value) == nil {
                return result(.insufficient, "invalid_rewritten_destination", row.id)
            }
        case "normal":
            guard !RouterTrafficAddress.isFake(flow.destinationIP),
                  let value = row.destinationIP, RouterTrafficAddress.equal(value, flow.destinationIP) else {
                return result(.insufficient, "probe_destination_not_bound", row.id)
            }
        default: return result(.insufficient, "unmodelled_dns_mode", row.id)
        }
        guard row.rule == rule.type, row.payload == rule.payload, row.chains == [rule.chain] else {
            return result(.contradictory, "compiled_rule_or_chain_mismatch", row.id, rule.ordinal)
        }
        return result(.candidateUnverified, "candidate_requires_authenticated_capture", row.id, rule.ordinal)
    }

    /// Correlates this helper's numeric TCP observation without inventing an
    /// application coverage case, request nonce or remote response.
    static func evaluateOwn(_ observation: RouterSystemConnections.OwnProbeObservation,
                            plan: RouterPlan, profile: RouterSystemProfile) throws -> RouterTrafficCorrelationResult {
        let binding = observation.binding, operation = observation.interval
        let held = observation.socketInterval, sampled = observation.controllerInterval
        let connecting = RouterTrafficInterval(start: observation.connectStartedAt, end: held.start)
        let connectionLifetime = RouterTrafficInterval(start: connecting.start, end: held.end)
        try binding.validate()
        guard binding.planDigest == (try RouterSystemCompiler.digest(plan: plan, profile: profile)) else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
        for interval in [operation, held, connectionLifetime] {
            try interval.validate(boot: binding.work.bootID, maximumDuration: 60)
        }
        try connecting.validate(boot: binding.work.bootID, maximumDuration: 3)
        try sampled.validate(boot: binding.work.bootID, maximumDuration: 5)
        guard operation.contains(connectionLifetime), connectionLifetime.contains(held),
              held.contains(sampled), held.end == operation.end,
              Double(binding.work.birthSeconds) + Double(binding.work.birthMicroseconds) / 1_000_000 <=
                operation.start.date.timeIntervalSince1970 else { throw RouterTrafficEvidenceError.invalidReceipt }
        return try evaluateNumericOwn(binding: binding, process: observation.socket.process.identity,
            path: observation.socket.process.path, tuple: observation.socket.tuple,
            installed: observation.source == .installedReaders, started: connecting.start.date,
            operationStart: operation.start.date, controllerEnd: sampled.end.date,
            trackers: observation.trackers, priorIDs: observation.priorTrackerIDs,
            plan: plan, label: "own_tcp")
    }

    /// SNI authenticates a TLS peer but does not establish a DNS/domain routing fact.
    static func evaluateOwnTLS(_ observation: RouterSystemConnections.OwnTLSObservation,
                               plan: RouterPlan, profile: RouterSystemProfile) throws -> RouterTrafficCorrelationResult {
        try observation.validate()
        guard observation.binding.planDigest == (try RouterSystemCompiler.digest(plan: plan, profile: profile)) else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
        let sample = observation.after
        return try evaluateNumericOwn(binding: observation.binding, process: sample.socket.process.identity,
            path: sample.socket.process.path, tuple: sample.socket.socket.tuple,
            installed: observation.source == .installedReaders, started: observation.before.connectStartedAt.date,
            operationStart: observation.interval.start.date, controllerEnd: observation.controllerInterval.end.date,
            trackers: observation.trackers, priorIDs: observation.priorTrackerIDs, plan: plan, label: "own_tls")
    }

    private static func evaluateNumericOwn(binding: RouterTrafficBinding,
        process: RouterSystemKernelObservation.ProcessSnapshot, path: String,
        tuple: RouterOwnedTCPProbe.Tuple, installed: Bool, started: Date, operationStart: Date,
        controllerEnd: Date, trackers: [RouterTrafficTracker], priorIDs: Set<UUID>,
        plan: RouterPlan, label: String) throws -> RouterTrafficCorrelationResult {
        let work = process.work
        guard work.bootID == binding.work.bootID, work.pid > 1, work.birthSeconds > 0,
              work.birthMicroseconds < 1_000_000,
              Double(work.birthSeconds) + Double(work.birthMicroseconds) / 1_000_000 <=
                operationStart.timeIntervalSince1970,
              Double(binding.work.birthSeconds) + Double(binding.work.birthMicroseconds) / 1_000_000 <=
                operationStart.timeIntervalSince1970,
              RouterValidation.validProcessPath(path),
              tuple.local.port > 0, tuple.peer.port > 0,
              RouterTrafficAddress.bytes(tuple.local.address) == tuple.local.bytes,
              RouterTrafficAddress.bytes(tuple.peer.address) == tuple.peer.bytes,
              tuple.local.family == tuple.peer.family else {
            return result(.insufficient, "probe_socket_or_process_identity_missing")
        }
        if installed {
            guard process.uid == 0, process.realUID == 0, path == RouterSystemLayout.helper else {
                return result(.insufficient, "probe_socket_or_process_identity_missing")
            }
        }
        _ = try RouterOwnedTCPProbe.Endpoint(address: tuple.peer.address, port: tuple.peer.port)
        let explanation = try RouterExplainer.explain(plan, flow: .init(processPath: path, domain: nil, transport: .tcp))
        guard explanation.status == "planned" else { return result(.insufficient, "earlier_rule_identity_unknown") }
        let rule = try expectedRule(explanation, plan: plan)
        let correlated = try match(.init(transport: .tcp, processPath: path,
            sourceIP: tuple.local.address, sourcePort: tuple.local.port,
            destinationIP: tuple.peer.address, destinationPort: tuple.peer.port, domain: nil),
            startedAfter: started, observedBefore: controllerEnd,
            trackers: trackers, rule: rule, dnsBound: false, priorTrackerIDs: priorIDs)
        guard correlated.relation == .candidateUnverified else { return correlated }
        return result(.candidateUnverified,
            rule.chain == "REJECT" ? label + "_reject_controls_still_required" : label + "_candidate_incomplete",
            correlated.connection, correlated.compiledOrdinal)
    }

    private static func fitsCase(_ id: RouterTrafficCase, attempt: RouterTrafficAttemptFacts,
                                 plan: RouterPlan, explanation: RouterExplanation) -> Bool {
        if id.variation == .fallback { return id.rule == nil && explanation.ruleID == nil }
        guard let rule = plan.rules.first(where: { $0.id == id.rule }) else { return false }
        let processMatches = rule.selector.processPath.map { $0.lowercased() == attempt.processPath.lowercased() } ?? true
        let domainMatches = rule.selector.domain.map { pattern in
            attempt.domain.map { RouterValidation.domainMatches(pattern, $0) } ?? false
        } ?? true
        switch id.variation {
        case .selected:
            // Root and descendant are separate required cases for a suffix selector.
            let rootMatches = rule.selector.domain.map { $0.value.lowercased() == attempt.domain?.lowercased() } ?? true
            return processMatches && domainMatches && rootMatches && explanation.ruleID == rule.id
        case .suffixDescendant:
            guard let domain = rule.selector.domain, domain.kind == .suffix else { return false }
            return processMatches && domainMatches && attempt.domain?.lowercased() != domain.value.lowercased() &&
                explanation.ruleID == rule.id
        case .suffixBoundaryOutside:
            guard let domain = rule.selector.domain, domain.kind == .suffix, let actual = attempt.domain else { return false }
            return processMatches && !domainMatches && actual.lowercased().hasSuffix(domain.value.lowercased())
        case .processOutside: return rule.selector.processPath != nil && !processMatches && domainMatches
        case .domainOutside: return rule.selector.domain != nil && processMatches && !domainMatches
        case .fallback, .dnsA, .dnsAAAA: return false
        }
    }

    static func evaluate(record: RouterTrafficCaseRecord, binding: RouterTrafficBinding,
                         plan: RouterPlan, profile: RouterSystemProfile,
                         attempt: RouterTrafficAttemptFacts, snapshotBinding: RouterTrafficBinding,
                         snapshotInterval: RouterTrafficInterval, trackers: [RouterTrafficTracker],
                         dns: RouterTrafficDNSMapping? = nil) throws -> RouterTrafficCorrelationResult {
        try binding.validate(); try snapshotBinding.validate()
        let digest = try binding.digest()
        guard binding.planDigest == (try RouterSystemCompiler.digest(plan: plan, profile: profile)),
              try RouterTrafficCodec.encode(binding) == RouterTrafficCodec.encode(snapshotBinding),
              record.bindingDigest == digest, attempt.bindingDigest == digest,
              record.id == attempt.id, record.attempt == attempt.attempt, record.session == attempt.session,
              record.transcript.requestNonce == attempt.nonce,
              record.interval.start == attempt.interval.start, record.interval.end == attempt.interval.end,
              try RouterTrafficCoveragePolicy.requirements(plan).contains(record.id),
              trackers.count <= RouterConnectionProjection.connectionLimit,
              Set(trackers.map(\.id)).count == trackers.count else { throw RouterTrafficEvidenceError.invalidReceipt }
        try record.transcript.validateShape()
        guard record.transcript.endpointDigest == (try attempt.target.digest()),
              attempt.target.transport == record.id.transport, attempt.target.port == attempt.destinationPort,
              attempt.domain.map({ $0.lowercased() == attempt.target.host.lowercased() }) ??
                RouterTrafficAddress.equal(attempt.target.host, attempt.destinationIP) else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
        try attempt.interval.validate(boot: binding.work.bootID, maximumDuration: 60)
        try snapshotInterval.validate(boot: binding.work.bootID, maximumDuration: 5)
        guard attempt.interval.contains(snapshotInterval),
              Double(binding.work.birthSeconds) + Double(binding.work.birthMicroseconds) / 1_000_000 <=
                attempt.interval.start.date.timeIntervalSince1970 else { throw RouterTrafficEvidenceError.invalidReceipt }
        guard attempt.process.bootID == binding.work.bootID, attempt.process.pid > 1,
              attempt.process.birthSeconds > 0, attempt.process.birthMicroseconds < 1_000_000,
              Double(attempt.process.birthSeconds) + Double(attempt.process.birthMicroseconds) / 1_000_000 <=
                attempt.interval.start.date.timeIntervalSince1970,
              RouterValidation.validProcessPath(attempt.processPath),
              attempt.domain.map(RouterValidation.validDomain) ?? true,
              attempt.sourcePort > 0, attempt.destinationPort > 0,
              let source = RouterTrafficAddress.bytes(attempt.sourceIP),
              let destination = RouterTrafficAddress.bytes(attempt.destinationIP),
              source.count == destination.count, destination.count == (record.id.family == .ipv4 ? 4 : 16) else {
            return result(.insufficient, "probe_socket_or_process_identity_missing")
        }
        if record.id.variation == .dnsA || record.id.variation == .dnsAAAA {
            return result(.insufficient, "dns_exchange_semantics_required")
        }
        let explanation = try RouterExplainer.explain(plan, flow: .init(processPath: attempt.processPath,
            domain: attempt.domain, transport: record.id.transport == .tcp ? .tcp : .udp))
        guard explanation.status == "planned" else { return result(.insufficient, "earlier_rule_identity_unknown") }
        guard fitsCase(record.id, attempt: attempt, plan: plan, explanation: explanation) else {
            return result(.insufficient, "case_selector_or_shadowing_gap")
        }
        let rule = try expectedRule(explanation, plan: plan)
        let correlated = try match(.init(transport: record.id.transport, processPath: attempt.processPath,
            sourceIP: attempt.sourceIP, sourcePort: attempt.sourcePort,
            destinationIP: attempt.destinationIP, destinationPort: attempt.destinationPort, domain: attempt.domain),
            startedAfter: attempt.interval.start.date, observedBefore: snapshotInterval.end.date,
            trackers: trackers, rule: rule, dnsBound: dns?.matches(attempt: attempt, binding: binding) ?? false)
        guard correlated.relation == .candidateUnverified else { return correlated }
        if (record.transcript.outcome == .forwarded && rule.chain == "REJECT") ||
            (record.transcript.outcome == .rejected && rule.chain != "REJECT") {
            return result(.contradictory, "transcript_route_outcome_mismatch", correlated.connection, rule.ordinal)
        }
        return result(.candidateUnverified,
                      rule.chain == "REJECT" ? "candidate_reject_controls_still_required" : "candidate_requires_authenticated_capture",
                      correlated.connection, rule.ordinal)
    }
}

extension RouterTrafficCaseRecord {
    /// Record-linked entry point. It cannot fill a different attempt's coverage slot
    /// or remove gaps in the immutable receipt's assessment.
    func correlate(binding: RouterTrafficBinding, plan: RouterPlan, profile: RouterSystemProfile,
                   attempt: RouterTrafficAttemptFacts, snapshotBinding: RouterTrafficBinding,
                   snapshotInterval: RouterTrafficInterval, body: Data,
                   dns: RouterTrafficDNSMapping? = nil) throws -> RouterTrafficCorrelationResult {
        try RouterTrafficCorrelator.evaluate(record: self, binding: binding, plan: plan, profile: profile,
            attempt: attempt, snapshotBinding: snapshotBinding, snapshotInterval: snapshotInterval,
            trackers: RouterTrafficTrackerParser.parse(body), dns: dns)
    }
}

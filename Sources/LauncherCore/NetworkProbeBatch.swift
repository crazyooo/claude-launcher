import Foundation

/// A single inspection round shares identical origin probes across targets.
/// This object is never retained across rounds or used as a launch permission.
public final class NetworkProbeBatch: @unchecked Sendable {
    private let condition = NSCondition()
    private var pending = Set<String>()
    private var observations: [String: DomainObservation] = [:]
    private var services: [String: NetworkCheck] = [:]
    public init() {}
    func observation(key: String, produce: () -> DomainObservation) -> DomainObservation {
        condition.lock()
        while pending.contains(key) { condition.wait() }
        if let value = observations[key] { condition.unlock(); return value }
        pending.insert(key); condition.unlock()
        let value = produce()
        condition.lock(); observations[key] = value; pending.remove(key); condition.broadcast(); condition.unlock()
        return value
    }
    func service(key: String, produce: () -> NetworkCheck) -> NetworkCheck {
        let key = "service:" + key
        condition.lock()
        while pending.contains(key) { condition.wait() }
        if let value = services[key] { condition.unlock(); return value }
        pending.insert(key); condition.unlock()
        let value = produce()
        condition.lock(); services[key] = value; pending.remove(key); condition.broadcast(); condition.unlock()
        return value
    }
}

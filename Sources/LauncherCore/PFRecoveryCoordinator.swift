import Foundation

public enum PFAuthorizationOutcome { case acknowledged, cancelled, unknown }

public struct PFAuthorizationResult {
    public let outcome: PFAuthorizationOutcome
    public let localProcessSettled: Bool
    init(_ outcome: PFAuthorizationOutcome, settled: Bool = true) {
        self.outcome = outcome; localProcessSettled = settled
    }
    /// Only when the caller has not spawned the authorization helper.
    public static var notStarted: Self { .init(.unknown) }
}

/// Tracks only an explicit PF recheck. It never resumes a connector or launches a client.
public struct PFRecoveryCoordinator {
    public enum Phase: String {
        case idle, authorizing, awaiting, received, checking, passed, failed, interrupted
        case cancelled, unknown, invalidated
    }
    public private(set) var phase: Phase = .idle
    public private(set) var authorizationInFlight = false
    public private(set) var authorizationID: UUID?
    public private(set) var request: PFRecoveryRequest?
    public private(set) var restoredForObservationOnly = false
    public private(set) var executionIdentity: PFAuthorizationExecutionIdentity?
    private var startNeverPermitted = false
    private var matchedReceipt = false
    private var retryWasUncertain = false
    private var lastReportTime = -Double.infinity
    private var lastReceiptTime = -Double.infinity
    private var lastRequestDeadline: Double?

    public init() {}

    /// Reopening the App never replays authorization or restores forwarding permission.
    /// The caller has already validated the journal and owns its lifecycle lock.
    public mutating func restoreForObservation(_ intent: PFAuthorizationIntent) {
        self = Self()
        request = intent.request; restoredForObservationOnly = true
        startNeverPermitted = !intent.startMayHaveBeenSent
        executionIdentity = intent.identity
        authorizationID = intent.startMayHaveBeenSent ? intent.executionID : nil
        authorizationInFlight = intent.startMayHaveBeenSent
        phase = intent.startMayHaveBeenSent ? .unknown : .interrupted
    }

    public mutating func observeExecution(_ state: PFAuthorizationExecutionState,
                                         identity: PFAuthorizationExecutionIdentity) {
        guard identity == executionIdentity, identity.executionID == authorizationID else { return }
        if state == .originalExited {
            authorizationInFlight = false; authorizationID = nil
            // This says nothing about a root descendant or the original request's outcome.
        }
    }

    public mutating func recordExecution(_ intent: PFAuthorizationIntent) {
        guard intent.request == request, intent.executionID == authorizationID, authorizationInFlight,
              intent.startMayHaveBeenSent, let identity = intent.identity else { return }
        guard executionIdentity == nil || executionIdentity == identity else { return }
        executionIdentity = identity
    }

    public func canBegin(report: PFObservation?, at now: Date) -> Bool {
        !authorizationInFlight && ![Phase.authorizing, .awaiting, .received, .checking, .unknown].contains(phase) &&
            report?.canBeginRecovery(at: now) == true
    }

    public mutating func begin(report: PFObservation, epoch: Int, now: Date) -> PFRecoveryRequest? {
        guard canBegin(report: report, at: now), let context = report.availableControlContext(at: now) else { return nil }
        let next = PFRecoveryRequest(context: context, epoch: epoch, now: now)
        restoredForObservationOnly = false; executionIdentity = nil; startNeverPermitted = false
        request = next; matchedReceipt = false; retryWasUncertain = false
        lastReportTime = report.checked_at; lastReceiptTime = -.infinity; lastRequestDeadline = nil
        authorizationID = UUID()
        phase = .authorizing; authorizationInFlight = true
        return next
    }

    public func canRetry(report: PFObservation?, epoch: Int, at now: Date) -> Bool {
        guard !authorizationInFlight, phase == .unknown, let request,
              restoredForObservationOnly || epoch == request.epoch,
              now >= request.createdAt, let context = report?.availableControlContext(at: now) else { return false }
        // A matching newer receipt is resolved by observation, without another prompt.
        return context.sameInstallation(as: request.context) && context.receipt_revision == request.context.receipt_revision
    }

    public mutating func retry(report: PFObservation, epoch: Int, now: Date) -> PFRecoveryRequest? {
        guard canRetry(report: report, epoch: epoch, at: now) else { return nil }
        retryWasUncertain = true; authorizationInFlight = true; authorizationID = UUID(); phase = .authorizing
        executionIdentity = nil
        return request
    }

    public mutating func completed(_ result: PFAuthorizationResult, for submitted: PFRecoveryRequest,
                                   executionID: UUID, epoch: Int) {
        guard submitted == request, executionID == authorizationID else { return }
        // Even a root receipt does not prove the local authorization process exited.
        if result.localProcessSettled { authorizationInFlight = false; authorizationID = nil }
        guard (restoredForObservationOnly || submitted.epoch == epoch), phase != .invalidated else { invalidate(); return }
        guard !matchedReceipt else { return }
        switch result.outcome {
        case .acknowledged: phase = .awaiting
        case .unknown: phase = .unknown
        case .cancelled: phase = retryWasUncertain ? .unknown : .cancelled
        }
    }

    public mutating func invalidate() {
        // Restored state is only historical correlation, already ineligible for connectorBinding.
        if restoredForObservationOnly { return }
        if request != nil { phase = .invalidated }
        // The root command may already have begun; this does not revoke it.
    }

    public mutating func observe(_ report: PFObservation?, epoch: Int, now: Date) {
        guard let request, phase != .invalidated else { return }
        guard (restoredForObservationOnly || request.epoch == epoch), now >= request.createdAt else {
            phase = .invalidated; return
        }
        if phase == .awaiting, now.timeIntervalSince(request.createdAt) >= 240 { phase = .unknown }
        if [.received, .checking].contains(phase), let deadline = lastRequestDeadline,
           now.timeIntervalSince1970 >= deadline + 10 { phase = .unknown }
        guard let report, report.isCurrent(at: now), report.checked_at >= lastReportTime else { return }
        lastReportTime = report.checked_at
        guard report.service_running else { phase = .invalidated; return }
        guard let context = report.availableControlContext(at: now) else { return }
        guard context.sameInstallation(as: request.context) else { phase = .invalidated; return }
        if let receipt = report.recovery, let value = receipt.correlatedStatus(for: request),
           let next = Phase(rawValue: value), receipt.updatedAt >= lastReceiptTime {
            if matchedReceipt && [.passed, .failed, .interrupted].contains(phase) && phase != next {
                phase = .invalidated; return
            }
            lastReceiptTime = receipt.updatedAt; lastRequestDeadline = receipt.requestDeadline
            phase = receipt.active && now.timeIntervalSince1970 >= receipt.requestDeadline + 10 ? .unknown : next
            matchedReceipt = true
        } else if context.receipt_revision != request.context.receipt_revision {
            phase = .invalidated
        }
    }

    public func lines(report: PFObservation?, at now: Date) -> [String] {
        if startNeverPermitted {
            return ["上次操作尚未准许发起系统授权；重开应用不会自动执行。", "这不代表旧辅助进程已确认退出，也不授予网络许可。"]
        }
        let text: String
        switch phase {
        case .idle: text = "尚未从此窗口发起管理员复检。"
        case .authorizing: text = "正在等待系统授权与提交结果。"
        case .awaiting: text = "请求已提交，等待后台发布属于本次操作的结果。"
        case .received, .checking, .passed, .failed, .interrupted:
            if let request, let report, report.isCurrent(at: now),
               report.recovery?.correlatedStatus(for: request) == phase.rawValue {
                return ["以下记录已与本次点击对应："] + report.recoveryLines(at: now) + activityLines
            }
            text = "已收到本次操作的记录；当前报告缺失或过期，等待重新核对。"
        case .cancelled: text = "已取消本次系统授权；不会自动重试。"
        case .unknown: text = "提交结果未知。先核对后台记录，必要时手动重试原请求，避免重复复检。"
        case .invalidated: text = "网络、配置或后台上下文已变化，本次界面操作失效。已提交的后台请求可能仍会完成。"
        }
        return [text] + activityLines + ["此操作只复检已批准的 PF 地址；不恢复连接器，受保护启动仍锁定。"]
    }

    public func connectorBinding(report: PFObservation?, at now: Date) -> ConnectorPFBinding? {
        guard !restoredForObservationOnly, phase == .passed, !authorizationInFlight, let request, let report,
              let binding = report.recovery?.connectorBinding(for: request),
              report.connectorExpiry(matching: binding, at: now) != nil else { return nil }
        return binding
    }

    private var activityLines: [String] {
        authorizationInFlight ? ["授权操作尚未确认结束，暂不接受另一操作。"] : []
    }
}

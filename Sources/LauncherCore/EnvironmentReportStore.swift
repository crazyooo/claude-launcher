import Foundation

public enum EnvironmentReportStore {
    public static let cliURL = Paths.root.appendingPathComponent("environment-cli-report.json")
    public static func saveCLI(_ report: EnvironmentReport) throws { try saveCLI(report, at: cliURL) }
    static func saveCLI(_ report: EnvironmentReport, at location: URL) throws {
        guard report.target == .cli, report.validEvidenceShape else {
            throw LauncherError.message("独立 CLI 检测记录不完整，没有保存。")
        }
        try EnvironmentStorage.withLock(at: location.deletingLastPathComponent().appendingPathComponent("environment-report.lock")) {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            try EnvironmentStorage.writeBytes(encoder.encode(report), to: location)
        }
    }
    public static func latestCLI() throws -> EnvironmentReport? { try latestCLI(at: cliURL) }
    static func latestCLI(at location: URL) throws -> EnvironmentReport? {
        guard let bytes = try EnvironmentStorage.readBytes(location) else { return nil }
        guard let report = try? JSONDecoder().decode(EnvironmentReport.self, from: bytes),
              report.target == .cli, report.validEvidenceShape else {
            throw LauncherError.message("独立 CLI 历史检测记录无法读取，已保留原文件。")
        }
        return report
    }
}

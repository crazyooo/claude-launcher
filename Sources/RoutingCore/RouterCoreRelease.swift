import Foundation
import CryptoKit
import Darwin

public enum RouterRuntimeError: String, Error {
    case unsupportedArchitecture, invalidPlan, invalidController, credentialUnavailable
    case unsafeFile, coreDigestMismatch, configurationRejected, processTimedOut, processUnsettled
    case operationFailed, portOccupied, alreadyLoaded, ownershipUnknown, stalePlan, workspaceFull
}

/// This identity is compiled into the app; neither plans nor downloaded manifests select code.
public enum RouterCoreRelease {
    public static let version = "1.19.32"
    public static let archiveSHA256 = "3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652"
    public static let executableSHA256 = "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66"
    public static let assetURL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-darwin-arm64-v1.19.32.gz"
    public static let label = "local.claude-launcher.router-runtime"

    public static func verify(_ url: URL) throws {
        _ = try verifiedBytes(url)
    }

    static func verifiedBytes(_ url: URL) throws -> Data {
        #if !arch(arm64)
        throw RouterRuntimeError.unsupportedArchitecture
        #else
        let bytes = try readExecutable(url)
        guard SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == executableSHA256 else {
            throw RouterRuntimeError.coreDigestMismatch
        }
        return bytes
        #endif
    }

    private static func readExecutable(_ url: URL) throws -> Data {
        guard url.path == RouterRuntimeFiles.physicalPath(url) else { throw RouterRuntimeError.unsafeFile }
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RouterRuntimeError.unsafeFile }
        defer { close(fd) }
        var before = stat(), after = stat(), linked = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_uid == getuid() || before.st_uid == 0,
              before.st_mode & 0o022 == 0, before.st_mode & 0o111 != 0, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= 128 * 1024 * 1024 else { throw RouterRuntimeError.unsafeFile }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65_536), total = 0
        while total <= 128 * 1024 * 1024 {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw RouterRuntimeError.unsafeFile }
            if n == 0 { break }
            data.append(contentsOf: buffer.prefix(n)); total += n
        }
        guard fstat(fd, &after) == 0, lstat(url.path, &linked) == 0,
              total == before.st_size, before.st_size == after.st_size,
              before.st_dev == linked.st_dev, before.st_ino == linked.st_ino,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw RouterRuntimeError.unsafeFile }
        return data
    }
}

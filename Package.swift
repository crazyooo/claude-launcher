// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ClaudeLauncher", platforms: [.macOS(.v13)], products: [
    .executable(name: "launcher-tool", targets: ["LauncherTool"]),
    .executable(name: "ClaudeLauncher", targets: ["LauncherApp"]),
    .executable(name: "router-runtime", targets: ["RouterRuntime"]),
    .executable(name: "router-system-helper", targets: ["RouterSystemHelper"])
], targets: [
    .target(name: "RoutingCore"),
    .executableTarget(name: "RouterRuntime", dependencies: ["RoutingCore"]),
    .executableTarget(name: "RouterSystemHelper", dependencies: ["RoutingCore"]),
    .target(name: "LauncherCore"),
    .executableTarget(name: "LauncherTool", dependencies: ["LauncherCore", "RoutingCore"]),
    .executableTarget(name: "LauncherApp", dependencies: ["LauncherCore", "RoutingCore"]),
    .testTarget(name: "RoutingCoreTests", dependencies: ["RoutingCore"]),
    .testTarget(name: "LauncherCoreTests", dependencies: ["LauncherCore", "LauncherApp", "RoutingCore"])
])

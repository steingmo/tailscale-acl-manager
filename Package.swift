// swift-tools-version:5.9
import PackageDescription
import Foundation

// The policy engine and the command-line tool build on macOS and Linux; the
// app — everything in a Mac/ folder — only on macOS.
// TAILSCALE_ACL_ENGINE=1 builds the engine alone on a Mac, which is the quick
// way to check that it doesn't lean on the app.
#if os(macOS)
let app = ProcessInfo.processInfo.environment["TAILSCALE_ACL_ENGINE"] == nil
#else
let app = false
#endif

let package = Package(
    name: "TailscaleACL",
    platforms: [.macOS(.v14)],
    dependencies: app ? [
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.0"),
    ] : [],
    targets: [
        .executableTarget(
            name: "TailscaleACL",
            dependencies: app ? [
                .product(name: "Sparkle", package: "Sparkle"),
            ] : [],
            path: "Sources/TailscaleACL",
            exclude: app ? [] : ["Mac"],
            // For the few places where engine code hands over to the app.
            swiftSettings: app ? [.define("MAC_APP")] : [],
            linkerSettings: app ? [
                // Sparkle.framework is embedded in Contents/Frameworks by build_app.sh.
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"]),
            ] : []
        ),
        .testTarget(
            name: "TailscaleACLTests",
            dependencies: ["TailscaleACL"],
            path: "Tests/TailscaleACLTests",
            exclude: app ? [] : ["Mac"],
            swiftSettings: app ? [.define("MAC_APP")] : []
        ),
    ]
)

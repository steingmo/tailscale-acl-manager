// swift-tools-version:5.9
import PackageDescription
import Foundation

// One module, built two ways:
// - the Mac app (default on macOS): the engine plus everything in Mac/;
// - the engine with the command-line tool and the web server (Linux, or
//   TAILSCALE_ACL_ENGINE=1 on a Mac): the engine plus everything in Server/.
// The app never contains the server or its libraries, and the server never
// contains the app.
#if os(macOS)
let app = ProcessInfo.processInfo.environment["TAILSCALE_ACL_ENGINE"] == nil
#else
let app = false
#endif

// The same list whichever way it's built on a Mac, so Package.resolved — which
// pins every version, Sparkle's included — doesn't change with the build mode.
// (An engine-only build once deleted it.) The app links only Sparkle, the
// server only the others; what a target doesn't use isn't compiled.
var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    // SHA-256 for the sign-in flow on Linux; macOS has CryptoKit.
    .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
]
#if os(macOS)
dependencies.append(.package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.0"))
#endif

let package = Package(
    name: "TailscaleACL",
    platforms: [.macOS(.v14)],
    dependencies: dependencies,
    targets: [
        .executableTarget(
            name: "TailscaleACL",
            dependencies: app ? [
                .product(name: "Sparkle", package: "Sparkle"),
            ] : [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ],
            path: "Sources/TailscaleACL",
            exclude: app ? ["Server"] : ["Mac"],
            // For the few places where engine code hands over to the app.
            swiftSettings: app ? [.define("MAC_APP")] : [],
            linkerSettings: app ? [
                // Sparkle.framework is embedded in Contents/Frameworks by build_app.sh.
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"]),
            ] : []
        ),
        .testTarget(
            name: "TailscaleACLTests",
            dependencies: app ? ["TailscaleACL"] : [
                "TailscaleACL",
                .product(name: "HummingbirdTesting", package: "hummingbird"),
            ],
            path: "Tests/TailscaleACLTests",
            exclude: app ? ["Server"] : ["Mac"],
            swiftSettings: app ? [.define("MAC_APP")] : []
        ),
    ]
)

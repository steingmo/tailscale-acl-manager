// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TailscaleACL",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "TailscaleACL",
            dependencies: [
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            path: "Sources/TailscaleACL",
            linkerSettings: [
                // Sparkle.framework is embedded in Contents/Frameworks by build_app.sh.
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"]),
            ]
        )
    ]
)

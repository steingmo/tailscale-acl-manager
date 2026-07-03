// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TailscaleACL",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "TailscaleACL",
            path: "Sources/TailscaleACL"
        )
    ]
)

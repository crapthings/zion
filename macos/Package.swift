// swift-tools-version: 6.0
import PackageDescription
import Foundation

// Native packet linking is enabled only when a real Rust static library was supplied.
let packetLibrary = ProcessInfo.processInfo.environment["ZION_PACKET_LIBRARY"]
// Optional native-bridge tests enable the Swift wrapper when a real Rust archive is supplied.
let packetSettings: [SwiftSetting] = packetLibrary == nil ? [] : [.define("ZION_PACKET_CORE")]
// The caller supplies an absolute library path to avoid accidental linking of an unrelated installation.
let packetLinker: [LinkerSetting] = packetLibrary.map { [.unsafeFlags([$0])] } ?? []

// The package separates native presentation from independently testable macOS control services.
let package = Package(
    name: "ZionMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ZionControl", targets: ["ZionControl"]),
        .executable(name: "ZionMac", targets: ["ZionMac"]),
        .executable(name: "ZionHelper", targets: ["ZionHelper"]),
    ],
    targets: [
        .target(name: "CZionPacket", publicHeadersPath: "include"),
        .target(name: "ZionHelperProtocol"),
        .executableTarget(name: "ZionHelper", dependencies: ["ZionHelperProtocol"]),
        .target(name: "ZionControl", dependencies: ["CZionPacket", "ZionHelperProtocol"], swiftSettings: packetSettings, linkerSettings: packetLinker),
        .executableTarget(name: "ZionMac", dependencies: ["ZionControl"]),
        .testTarget(name: "ZionControlTests", dependencies: ["ZionControl", "ZionMac"]),
    ]
)

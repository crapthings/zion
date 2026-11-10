// swift-tools-version: 6.0
import PackageDescription
import Foundation

// Native packet linking is enabled only when a real Rust static library was supplied.
let packetLibrary = ProcessInfo.processInfo.environment["ZION_PACKET_LIBRARY"]
// Packet-enabled builds compile the same bridge into host and extension targets.
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
    ],
    targets: [
        .target(name: "CZionPacket", publicHeadersPath: "include"),
        .target(name: "ZionControl", dependencies: ["CZionPacket"], swiftSettings: packetSettings, linkerSettings: packetLinker),
        .executableTarget(name: "ZionMac", dependencies: ["ZionControl"]),
        .testTarget(name: "ZionControlTests", dependencies: ["ZionControl", "ZionMac"]),
    ]
)

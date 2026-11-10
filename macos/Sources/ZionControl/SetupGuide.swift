import Darwin
import Foundation
import Observation
import SystemConfiguration

/// Proxy kinds identify enabled system mechanisms without exposing their credentials or URLs.
public enum SystemProxyKind: String, CaseIterable, Sendable {
    case http = "HTTP", https = "HTTPS", socks = "SOCKS", pac = "PAC", discovery = "自动发现"

    /// Map a displayed mechanism to its SystemConfiguration enable flag.
    private var key: String {
        switch self {
        case .http: "HTTPEnable"
        case .https: "HTTPSEnable"
        case .socks: "SOCKSEnable"
        case .pac: "ProxyAutoConfigEnable"
        case .discovery: "ProxyAutoDiscoveryEnable"
        }
    }

    /// Combine global and interface-scoped flags without counting a disabled mechanism as active.
    public static func enabled(in values: [String: Any]) -> [Self] {
        let scoped = (values["__SCOPED__"] as? [String: [String: Any]])?.values.map { $0 } ?? []
        let configurations = [values] + scoped
        return allCases.filter { kind in configurations.contains { ($0[kind.key] as? NSNumber)?.intValue == 1 } }
    }
}

/// A read-only snapshot separates system proxy configuration from observed virtual interfaces.
public struct SetupNetworkSnapshot: Sendable {
    public let proxies: [SystemProxyKind]
    public let virtualInterfaces: [String]
    public let date: Date

    /// Create an observed snapshot or an injected fixture without changing the host network.
    public init(proxies: [SystemProxyKind], virtualInterfaces: [String], date: Date = Date()) {
        self.proxies = proxies; self.virtualInterfaces = virtualInterfaces; self.date = date
    }
}

/// A snapshot provider allows setup tests to avoid inspecting or changing the host's network.
@MainActor public protocol SetupNetworkReading {
    func read() throws -> SetupNetworkSnapshot
}

/// Native detection reads effective proxy flags and up virtual interfaces without requesting authorization.
@MainActor public struct NativeSetupNetworkReader: SetupNetworkReading {
    public init() {}

    /// Capture current system state without treating another app's virtual interface as Zion ownership.
    public func read() throws -> SetupNetworkSnapshot {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { throw ControlError("无法读取系统代理状态。") }
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0 else { throw ControlError("无法读取网络接口状态。") }
        defer { freeifaddrs(first) }
        var current = first
        var names = Set<String>()
        while let pointer = current {
            let item = pointer.pointee
            let name = String(cString: item.ifa_name)
            if item.ifa_flags & UInt32(IFF_UP) != 0,
               ["utun", "tun", "tap", "ppp"].contains(where: { name.hasPrefix($0) }),
               let address = item.ifa_addr, [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family)) {
                names.insert(name)
            }
            current = item.ifa_next
        }
        return SetupNetworkSnapshot(proxies: SystemProxyKind.enabled(in: proxies), virtualInterfaces: names.sorted { $0.localizedStandardCompare($1) == .orderedAscending })
    }
}

/// Setup preferences remember completion separately from the optional every-launch guide.
private struct SetupPreferences: Codable {
    var version = 1
    var completed = false
    var showOnLaunch = false
}

/// The guide owns presentation and read-only detection while network actions remain explicit app commands.
@Observable @MainActor public final class SetupGuide {
    public private(set) var isPresented: Bool
    public var showOnLaunch: Bool
    public private(set) var snapshot: SetupNetworkSnapshot?
    public private(set) var detectionError: String?
    public private(set) var preferenceError: String?
    private let file: URL
    private let reader: any SetupNetworkReading
    private let preferencesReadable: Bool

    /// Load private launch preferences without probing networking or changing any proxy setting.
    public init(directory: URL, reader: any SetupNetworkReading = NativeSetupNetworkReader()) {
        file = directory.appendingPathComponent("setup.json")
        self.reader = reader
        var preferences = SetupPreferences()
        var readable = true
        if FileManager.default.fileExists(atPath: file.path) {
            do {
                let handle = try FileHandle(forReadingFrom: file)
                defer { try? handle.close() }
                let data = try handle.read(upToCount: 4097) ?? Data()
                guard data.count <= 4096 else { throw ControlError("引导偏好文件过大。") }
                preferences = try JSONDecoder().decode(SetupPreferences.self, from: data)
                guard preferences.version == 1 else { throw ControlError("引导偏好版本不受支持。") }
            } catch { readable = false; preferenceError = "无法读取引导偏好，本次仍可跳过；原文件不会被覆盖。" }
        }
        preferencesReadable = readable
        isPresented = !preferences.completed || preferences.showOnLaunch || !readable
        showOnLaunch = preferences.showOnLaunch
    }

    /// Reopen the guide without resetting completion or enabling a connection.
    public func open() { isPresented = true }

    /// Re-read the current network state and distinguish failed detection from an inactive network feature.
    public func refresh() {
        do { snapshot = try reader.read(); detectionError = nil }
        catch { snapshot = nil; detectionError = "状态检测失败，请刷新重试；系统设置未被修改。" }
    }

    /// Dismiss on both continue and skip while recording only the user's launch preference.
    public func finish(persist: Bool = true) {
        isPresented = false
        guard persist, preferencesReadable else { return }
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(SetupPreferences(completed: true, showOnLaunch: showOnLaunch))
            try data.write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            preferenceError = nil
        } catch { preferenceError = "引导偏好未能保存，下次启动可能再次显示。" }
    }
}

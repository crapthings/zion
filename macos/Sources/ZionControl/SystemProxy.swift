import Foundation
import Security
import SystemConfiguration

/// A protocol snapshot preserves both configuration values and the original enabled state.
public struct ProxyProtocolState {
    public var activationEligible: Bool
    public var exists: Bool
    public var enabled: Bool
    public var configuration: [String: Any]?

    public init(exists: Bool = true, enabled: Bool = true, configuration: [String: Any]?, activationEligible: Bool = true) {
        self.activationEligible = activationEligible
        self.exists = exists; self.enabled = enabled; self.configuration = configuration
    }

    /// Compare ownership using the complete protocol state rather than just its proxy port.
    public func matches(_ other: Self) -> Bool {
        exists == other.exists && enabled == other.enabled && Self.equal(configuration, other.configuration)
    }

    /// Compare optional property-list dictionaries without treating absent values as empty ones.
    private static func equal(_ first: [String: Any]?, _ second: [String: Any]?) -> Bool {
        switch (first, second) {
        case (nil, nil): true
        case let (first?, second?): NSDictionary(dictionary: first).isEqual(to: second)
        default: false
        }
    }
}

/// A preference change includes the expected old state to prevent overwriting another app.
public struct ProxyChange {
    public let serviceID: String
    public let expected: ProxyProtocolState
    public let desired: ProxyProtocolState
}

/// Preference adapters let policy and recovery tests avoid changing the host's network.
@MainActor public protocol ProxyPreferences: AnyObject {
    func read() throws -> [String: ProxyProtocolState]
    func write(_ changes: [ProxyChange]) throws
}

/// System proxy control restores only settings still owned by the current connection.
@MainActor public protocol SystemProxyServing: AnyObject {
    var needsRecovery: Bool { get }
    func enable(endpoint: ProxyEndpoint) throws
    func restore() throws
}

/// Proxy policy selects the local SOCKS5 listener while retaining unrelated network settings.
public enum ProxyPolicy {
    /// Disable competing proxy mechanisms and remove credentials belonging to the old SOCKS host.
    public static func applied(to original: ProxyProtocolState, endpoint: ProxyEndpoint) -> ProxyProtocolState {
        var values = original.configuration ?? [:]
        for key in ["HTTPEnable", "HTTPSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] { values[key] = 0 }
        values["SOCKSEnable"] = 1
        values["SOCKSProxy"] = endpoint.host
        values["SOCKSPort"] = endpoint.port
        values.removeValue(forKey: "SOCKSUser")
        values.removeValue(forKey: "SOCKSPassword")
        var exceptions = values["ExceptionsList"] as? [String] ?? []
        for name in ["localhost", "127.0.0.1", "::1"] where !exceptions.contains(name) { exceptions.append(name) }
        values["ExceptionsList"] = exceptions
        return ProxyProtocolState(configuration: values)
    }
}

/// A proxy journal survives a process crash without containing any new server password.
@MainActor public final class SystemProxyController: SystemProxyServing {
    private let preferences: any ProxyPreferences
    private let journal: URL

    /// Inject a preference adapter and journal location for deterministic recovery tests.
    public init(preferences: any ProxyPreferences = NativeProxyPreferences(), journal: URL) {
        self.preferences = preferences; self.journal = journal
    }

    public var needsRecovery: Bool { FileManager.default.fileExists(atPath: journal.path) }

    /// Record the old state before applying a transaction that may require macOS authorization.
    public func enable(endpoint: ProxyEndpoint) throws {
        if needsRecovery { try restore() }
        let current = try preferences.read().filter { $0.value.activationEligible }
        guard !current.isEmpty else { throw ControlError("没有找到可配置的网络服务。") }
        let changes = current.map { id, before in ProxyChange(serviceID: id, expected: before, desired: ProxyPolicy.applied(to: before, endpoint: endpoint)) }
        try save(changes)
        do { try preferences.write(changes) }
        catch {
            do { try restore() }
            catch { throw ControlError("系统代理启用失败，原设置尚需恢复，请在设置中重试恢复网络。") }
            throw error
        }
    }

    /// Restore journal entries only if no other application has replaced their applied state.
    public func restore() throws {
        guard needsRecovery else { return }
        let entries = try load()
        let current = try preferences.read()
        let changes = entries.compactMap { entry -> ProxyChange? in
            guard let value = current[entry.serviceID], value.matches(entry.desired) else { return nil }
            return ProxyChange(serviceID: entry.serviceID, expected: value, desired: entry.expected)
        }
        if !changes.isEmpty { try preferences.write(changes) }
        try FileManager.default.removeItem(at: journal)
    }

    /// Persist property-list snapshots atomically before a system preference transaction.
    private func save(_ changes: [ProxyChange]) throws {
        let directory = journal.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let entries: [[String: Any]] = changes.map { ["service": $0.serviceID, "before": encode($0.expected), "applied": encode($0.desired)] }
        let data = try PropertyListSerialization.data(fromPropertyList: entries, format: .binary, options: 0)
        try data.write(to: journal, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)
    }

    /// Decode a journal strictly so corruption cannot replace the current network preferences.
    private func load() throws -> [ProxyChange] {
        let data = try Data(contentsOf: journal)
        guard data.count <= 1024 * 1024,
              let entries = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [[String: Any]] else {
            throw ControlError("网络恢复记录无法读取，系统设置未被修改。")
        }
        return try entries.map { entry in
            guard let service = entry["service"] as? String,
                  let before = entry["before"] as? [String: Any],
                  let applied = entry["applied"] as? [String: Any] else { throw ControlError("网络恢复记录不完整。") }
            return ProxyChange(serviceID: service, expected: try decode(before), desired: try decode(applied))
        }
    }

    /// Encode optional protocol configuration without introducing unsupported null property-list values.
    private func encode(_ state: ProxyProtocolState) -> [String: Any] {
        var result: [String: Any] = ["exists": state.exists, "enabled": state.enabled]
        if let configuration = state.configuration { result["configuration"] = configuration }
        return result
    }

    /// Validate required snapshot fields before constructing a restoration state.
    private func decode(_ value: [String: Any]) throws -> ProxyProtocolState {
        guard let exists = value["exists"] as? Bool, let enabled = value["enabled"] as? Bool else {
            throw ControlError("网络恢复记录不完整。")
        }
        if let configuration = value["configuration"], !(configuration is [String: Any]) {
            throw ControlError("网络恢复记录中的代理配置无效。")
        }
        return ProxyProtocolState(exists: exists, enabled: enabled, configuration: value["configuration"] as? [String: Any])
    }
}

/// Native preference access obtains authorization only for an actual requested write.
@MainActor public final class NativeProxyPreferences: ProxyPreferences {
    private var authorization: AuthorizationRef?
    public init() {}

    /// Read all services while marking enabled services in the current location for activation.
    public func read() throws -> [String: ProxyProtocolState] {
        guard let preferences = SCPreferencesCreate(nil, "Zion" as CFString, nil) else { throw failure() }
        let set = SCNetworkSetCopyCurrent(preferences)
        let active = set.flatMap { SCNetworkSetCopyServices($0) as? [SCNetworkService] } ?? []
        let identifiers = Set(active.filter { SCNetworkServiceGetEnabled($0) }.compactMap { SCNetworkServiceGetServiceID($0) as String? })
        return try services(preferences).mapValues { service in
            var value = state(service)
            value.activationEligible = (SCNetworkServiceGetServiceID(service) as String?).map { identifiers.contains($0) } ?? false
            return value
        }
    }

    /// Apply all changes under one lock after verifying that their expected states still match.
    public func write(_ changes: [ProxyChange]) throws {
        try authorize()
        guard let preferences = SCPreferencesCreateWithAuthorization(nil, "Zion" as CFString, nil, authorization) else { throw failure() }
        guard SCPreferencesLock(preferences, false) else { throw failure() }
        defer { SCPreferencesUnlock(preferences) }
        SCPreferencesSynchronize(preferences)
        let current = try services(preferences)
        for change in changes {
            guard let service = current[change.serviceID], state(service).matches(change.expected) else {
                throw ControlError("网络设置已被其他应用修改，请重试。")
            }
        }
        for change in changes { try set(change.desired, on: current[change.serviceID]!) }
        guard SCPreferencesCommitChanges(preferences), SCPreferencesApplyChanges(preferences) else { throw failure() }
    }

    /// Enumerate services across locations so recovery can also restore a previous location.
    private func services(_ preferences: SCPreferences) throws -> [String: SCNetworkService] {
        guard let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else { throw failure() }
        return Dictionary(uniqueKeysWithValues: services.compactMap { service in (SCNetworkServiceGetServiceID(service) as String?).map { ($0, service) } })
    }

    /// Capture the proxy protocol's existence, enabled flag, and complete configuration.
    private func state(_ service: SCNetworkService) -> ProxyProtocolState {
        guard let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            return ProxyProtocolState(exists: false, enabled: false, configuration: nil)
        }
        return ProxyProtocolState(enabled: SCNetworkProtocolGetEnabled(proto), configuration: SCNetworkProtocolGetConfiguration(proto) as? [String: Any])
    }

    /// Create, restore, or remove one service's proxy protocol within the pending transaction.
    private func set(_ desired: ProxyProtocolState, on service: SCNetworkService) throws {
        if !desired.exists {
            guard SCNetworkServiceRemoveProtocolType(service, kSCNetworkProtocolTypeProxies) else { throw failure() }
            return
        }
        if SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) == nil {
            guard SCNetworkServiceAddProtocolType(service, kSCNetworkProtocolTypeProxies) else { throw failure() }
        }
        guard let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies),
              SCNetworkProtocolSetConfiguration(proto, desired.configuration as CFDictionary?),
              SCNetworkProtocolSetEnabled(proto, desired.enabled) else { throw failure() }
    }

    /// Ask macOS for network preference rights while keeping the authorization for later restoration.
    private func authorize() throws {
        if authorization != nil { return }
        let status = "system.preferences.network".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                return AuthorizationCreate(&rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], &authorization)
            }
        }
        guard status == errAuthorizationSuccess else { throw ControlError("未获得网络设置授权（\(status)）。") }
    }

    /// Convert an operating-system status into a bounded user-facing diagnostic.
    private func failure() -> ControlError { ControlError("无法更新系统代理设置（\(SCError())）。") }
}

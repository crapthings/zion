import Foundation

/// A backend identifies the single mechanism that owns the current network takeover.
public enum ConnectionBackend: String, Codable, CaseIterable, Identifiable, Sendable {
    case systemProxy, networkExtension, helperTun
    public var id: Self { self }
    public var title: String {
        switch self {
        case .systemProxy: "系统代理"
        case .networkExtension: "NetworkExtension"
        case .helperTun: "辅助服务 TUN"
        }
    }
    public var explanation: String {
        switch self {
        case .systemProxy: "代理遵循 macOS SOCKS 设置的应用。"
        case .networkExtension: "由 macOS 网络扩展管理虚拟网卡。"
        case .helperTun: "由授权的辅助服务管理虚拟网卡。"
        }
    }
}

/// Backend readiness distinguishes missing implementation from an actual authorization requirement.
public enum BackendReadiness: Equatable, Sendable {
    case ready
    case unavailable(String)

    public var canConnect: Bool { self == .ready }
    public var explanation: String? {
        if case let .unavailable(reason) = self { reason } else { nil }
    }
}

/// Local connection preferences remain separate from server metadata and Keychain credentials.
public struct ConnectionPreferences: Codable, Equatable, Sendable {
    public var backend: ConnectionBackend
    public init(backend: ConnectionBackend = .systemProxy) { self.backend = backend }
}

/// A private settings file preserves explicit backend choices across application launches.
@MainActor public final class ConnectionPreferencesStore {
    public let file: URL
    public init(directory: URL) { file = directory.appendingPathComponent("connection.json") }

    /// Load an explicit selection without silently substituting a different backend for corrupt data.
    public func load() throws -> ConnectionPreferences {
        guard FileManager.default.fileExists(atPath: file.path) else { return ConnectionPreferences() }
        let data = try Data(contentsOf: file)
        guard data.count <= 4096 else { throw ControlError("接管方式设置文件过大。") }
        return try JSONDecoder().decode(ConnectionPreferences.self, from: data)
    }

    /// Atomically persist metadata without including a server password or transport configuration.
    public func save(_ preferences: ConnectionPreferences) throws {
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(preferences).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
}

/// Enhanced adapters report readiness only after their real packet transport and network setup succeed.
@MainActor public protocol TunnelBackendServing: AnyObject {
    var backend: ConnectionBackend { get }
    var readiness: BackendReadiness { get }
    var needsRecovery: Bool { get }
    var onExit: (@MainActor (String) -> Void)? { get set }
    func start(configuration: CoreConfiguration) async throws
    func stop() async throws
}

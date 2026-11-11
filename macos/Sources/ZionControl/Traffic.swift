import Foundation
import Observation

/// An egress policy maps one process to the current server, direct access, or rejection.
public enum RoutingPolicy: String, Codable, CaseIterable, Sendable {
    case proxy, direct, reject
    public var title: String {
        switch self { case .proxy: "代理"; case .direct: "直连"; case .reject: "拒绝" }
    }
}

/// Exact matchers avoid accidentally routing similarly named executables.
public enum ProcessMatcher: String, Codable, CaseIterable, Sendable {
    case processName = "process_name", processPath = "process_path"
    public var title: String { self == .processPath ? "进程路径" : "进程名" }
}

/// A persisted process rule is evaluated in array order by the Rust core.
public struct ProcessRule: Codable, Equatable, Sendable {
    public var matcher: ProcessMatcher
    public var value: String
    public var policy: RoutingPolicy
    public var enabled: Bool
    public init(matcher: ProcessMatcher, value: String, policy: RoutingPolicy, enabled: Bool = true) {
        self.matcher = matcher; self.value = value; self.policy = policy; self.enabled = enabled
    }
}

/// A routing document contains ordered rules and the FINAL policy for unmatched connections.
public struct RoutingDocument: Codable, Equatable, Sendable {
    public var defaultPolicy: RoutingPolicy = .proxy
    public var rules: [ProcessRule] = []
    public init() {}
    enum CodingKeys: String, CodingKey { case defaultPolicy = "default_policy", rules }

    /// Keep native editing limits consistent with the core's routing schema.
    public func validate() throws {
        guard rules.count <= 256 else { throw ControlError("最多保存 256 条进程规则。") }
        for rule in rules {
            guard !rule.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  rule.value.utf8.count <= 4096, !rule.value.contains("\0"),
                  rule.matcher != .processPath || rule.value.hasPrefix("/") else {
                throw ControlError("规则需要有效进程名或绝对路径，最长 4096 字节。")
            }
        }
    }
}

/// A process identity is supplied by local socket attribution rather than by the remote server.
public struct TrafficProcess: Decodable, Equatable, Sendable {
    public let pid: UInt32?
    public let name: String?
    public let path: String?
    public var key: String { path ?? name ?? "unknown" }
    public var title: String { name ?? "未识别进程" }
}

/// Traffic snapshots carry cumulative counters and explain the policy chosen at connection start.
public struct TrafficRecord: Decodable, Identifiable, Sendable {
    public let id: UInt64
    public let process: TrafficProcess
    public let target: String
    public let `protocol`: String
    public let policy: RoutingPolicy
    public let rule: String
    public let up: UInt64
    public let down: UInt64
    public let durationMS: UInt64
    public var status: String
    public var active: Bool { status == "active" }
    enum CodingKeys: String, CodingKey {
        case id, process, target, `protocol`, policy, rule, up, down, status
        case durationMS = "duration_ms"
    }
}

/// A process row summarizes only the connections retained in the bounded traffic window.
public struct ProcessTraffic: Identifiable {
    public let process: TrafficProcess
    public var up: UInt64 = 0
    public var down: UInt64 = 0
    public var active: Int = 0
    public var connections: Int = 0
    public var id: String { process.key }
}

/// Traffic state persists rules and retains at most 500 connection snapshots without payload capture.
@Observable @MainActor public final class TrafficCenter {
    public private(set) var routing = RoutingDocument()
    public private(set) var records: [TrafficRecord] = []
    public private(set) var storageError: String?
    private let file: URL

    /// Read local rules without replacing malformed storage with defaults on disk.
    public init(directory: URL) {
        file = directory.appendingPathComponent("routing.json")
        do {
            if FileManager.default.fileExists(atPath: file.path) {
                let value = try JSONDecoder().decode(RoutingDocument.self, from: Data(contentsOf: file))
                try value.validate(); routing = value
            }
        } catch { storageError = "无法读取 routing.json，请修复后重启应用。" }
    }

    /// Commit validated rules atomically before making them available for the next connection.
    public func save(_ value: RoutingDocument) throws {
        guard storageError == nil else { throw ControlError(storageError!) }
        try value.validate()
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(value).write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        routing = value
    }

    /// Replace cumulative snapshots without double counting repeated updates or evicting active flows.
    public func receive(_ record: TrafficRecord) {
        guard let index = records.firstIndex(where: { $0.id == record.id }) else {
            insert(record)
            return
        }
        // A terminal snapshot must not regress when a periodic update arrives late.
        guard records[index].active else { return }
        records[index] = record
    }

    /// Insert a new connection after freeing a completed history slot when necessary.
    private func insert(_ record: TrafficRecord) {
        guard makeHistorySpace() else { return }
        records.insert(record, at: 0)
    }

    /// Preserve active connections while enforcing the retained-history capacity.
    private func makeHistorySpace() -> Bool {
        guard records.count >= 500 else { return true }
        guard let index = records.lastIndex(where: { !$0.active }) else { return false }
        records.remove(at: index)
        return true
    }

    /// Reset process-local IDs when starting another core while preserving saved routing rules.
    public func beginSession() { records.removeAll() }

    /// Preserve last counters and mark orphaned sessions when the supervised core stops.
    public func endSession() {
        for index in records.indices where records[index].active { records[index].status = "cancelled" }
    }

    /// Clear completed history while keeping the counters of active connections continuous.
    public func clearCompleted() { records.removeAll { !$0.active } }

    /// Group retained connections by executable and keep unknown ownership explicitly separate.
    public var processes: [ProcessTraffic] {
        var groups: [String: ProcessTraffic] = [:]
        for record in records {
            var row = groups[record.process.key] ?? ProcessTraffic(process: record.process)
            row.up += record.up; row.down += record.down
            row.active += record.active ? 1 : 0; row.connections += 1
            groups[record.process.key] = row
        }
        return groups.values.sorted { ($0.up + $0.down) > ($1.up + $1.down) }
    }
}

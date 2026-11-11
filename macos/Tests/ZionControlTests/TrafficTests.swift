import Foundation
import Testing
@testable import ZionControl

/// Traffic tests exercise persistent routing and bounded cumulative statistics without system proxy changes.
@Suite @MainActor struct TrafficTests {
    /// Build isolated storage so routing tests never touch the user's configuration.
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Construct a decoded core snapshot through the actual event schema.
    private func record(_ id: UInt64, up: UInt64 = 10, status: String = "active") throws -> TrafficRecord {
        let value: [String: Any] = ["event": "traffic", "id": id, "process": ["pid": 42, "name": "curl", "path": "/usr/bin/curl"],
                                    "target": "example.test:443", "protocol": "TCP", "policy": "direct", "rule": "PROCESS-PATH: /usr/bin/curl",
                                    "up": up, "down": 5, "duration_ms": 1000, "status": status]
        return try JSONDecoder().decode(TrafficRecord.self, from: JSONSerialization.data(withJSONObject: value))
    }

    /// Rule priority, disabled state, and the final policy survive persistence and core encoding.
    @Test func rulesRoundTripToCoreSchema() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let center = TrafficCenter(directory: path)
        var routing = RoutingDocument()
        routing.defaultPolicy = .reject
        routing.rules = [ProcessRule(matcher: .processPath, value: "/usr/bin/curl", policy: .direct),
                         ProcessRule(matcher: .processName, value: "curl", policy: .proxy, enabled: false)]
        try center.save(routing)
        #expect(TrafficCenter(directory: path).routing == routing)
        var profile = ServerProfile(); profile.server = "localhost:8443"
        var config = try profile.configuration(password: "secret")
        config.routing = routing
        let fields = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any])
        let encoded = try #require(fields["routing"] as? [String: Any])
        #expect(encoded["default_policy"] as? String == "reject")
        let rules = try #require(encoded["rules"] as? [[String: Any]])
        #expect(rules.first?["matcher"] as? String == "process_path")
        #expect(rules.last?["enabled"] as? Bool == false)
        #expect(!String(decoding: try Data(contentsOf: path.appendingPathComponent("routing.json")), as: UTF8.self).contains("secret"))
    }

    /// Corrupt storage and invalid matchers cannot be silently replaced by permissive defaults.
    @Test func invalidRoutingPreservesStorage() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let file = path.appendingPathComponent("routing.json")
        try Data("broken".utf8).write(to: file)
        let center = TrafficCenter(directory: path)
        #expect(center.storageError != nil)
        #expect(throws: (any Error).self) { try center.save(RoutingDocument()) }
        #expect(try String(contentsOf: file, encoding: .utf8) == "broken")
        var invalid = RoutingDocument()
        invalid.rules = [ProcessRule(matcher: .processPath, value: "relative", policy: .proxy)]
        #expect(throws: (any Error).self) { try invalid.validate() }
    }

    /// Repeated cumulative updates replace counters while a final event cannot regress to active.
    @Test func cumulativeSnapshotsAndSessionLifecycle() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let center = TrafficCenter(directory: path)
        center.receive(try record(1)); center.receive(try record(1, up: 20))
        center.receive(try record(2, up: 7, status: "closed"))
        #expect(center.processes.count == 1)
        #expect(center.processes[0].up == 27)
        #expect(center.processes[0].active == 1)
        center.clearCompleted()
        #expect(center.records.count == 1)
        center.receive(try record(1, up: 30, status: "closed"))
        center.receive(try record(1, up: 20))
        #expect(center.records[0].up == 30)
        #expect(!center.records[0].active)
        center.receive(try record(3)); center.endSession()
        #expect(center.processes[0].active == 0)
        center.beginSession(); #expect(center.records.isEmpty)
    }

    /// History evicts completed rows before any active connection regardless of insertion order.
    @Test func boundedHistoryPreservesActiveFlows() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let center = TrafficCenter(directory: path)
        center.receive(try record(1))
        for id in 2...650 { center.receive(try record(UInt64(id), status: "closed")) }
        #expect(center.records.count == 500)
        #expect(center.records.contains { $0.id == 1 && $0.active })
    }

    /// A supervisor accepts traffic events alongside readiness and keeps them out of diagnostics.
    @Test func supervisorDeliversTrafficEvents() async throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let script = path.appendingPathComponent("core")
        let source = """
        #!/usr/bin/env python3
        import json, signal, sys
        config = json.load(sys.stdin)
        assert config["routing"]["default_policy"] == "reject"
        signal.signal(signal.SIGINT, lambda *args: sys.exit(0))
        print(json.dumps({"event":"ready","listen":"127.0.0.1:12345"}), flush=True)
        print(json.dumps({"event":"traffic","id":1,"process":{"pid":42,"name":"curl","path":"/usr/bin/curl"},"target":"example.test:443","protocol":"TCP","policy":"reject","rule":"FINAL","up":0,"down":0,"duration_ms":0,"status":"rejected"}), flush=True)
        signal.pause()
        """
        try Data(source.utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let center = TrafficCenter(directory: path)
        let engine = CoreProcess(executable: script)
        engine.onTraffic = { center.receive($0) }
        var profile = ServerProfile(); profile.server = "localhost:8443"
        var config = try profile.configuration(password: "test")
        config.routing.defaultPolicy = .reject
        do {
            _ = try await engine.start(configuration: config)
            for _ in 0..<40 {
                if !center.records.isEmpty { break }
                try await Task.sleep(for: .milliseconds(25))
            }
            #expect(center.records.first?.status == "rejected")
            #expect(center.records.first?.policy == .reject)
        } catch { await engine.stop(); throw error }
        await engine.stop()
    }
}

import Foundation
import Testing
@testable import ZionControl

/// In-memory preferences exercise recovery without modifying the host network.
@MainActor private final class MemoryPreferences: ProxyPreferences {
    var states: [String: ProxyProtocolState] = ["wifi": .init(configuration: ["HTTPEnable": 1, "HTTPProxy": "old.example", "SOCKSUser": "old-user"])]
    var writes = 0
    var failNext = false
    func read() throws -> [String: ProxyProtocolState] { states }
    func write(_ changes: [ProxyChange]) throws {
        if failNext { failNext = false; throw ControlError("write failed") }
        for change in changes {
            guard states[change.serviceID]?.matches(change.expected) == true else { throw ControlError("concurrent write") }
        }
        writes += 1
        for change in changes { states[change.serviceID] = change.desired }
    }
}

/// A controllable engine exposes startup and shutdown sequencing to lifecycle tests.
@MainActor private final class MemoryEngine: EngineServing {
    var onLog: (@MainActor (String) -> Void)?
    var onExit: (@MainActor (Int32) -> Void)?
    var startupError = false
    var stops = 0
    var suspension: CheckedContinuation<ProxyEndpoint, Error>?
    var suspendStartup = false
    func start(configuration: CoreConfiguration) async throws -> ProxyEndpoint {
        if startupError { throw ControlError("authentication failed") }
        if suspendStartup { return try await withCheckedThrowingContinuation { suspension = $0 } }
        return try ProxyEndpoint(listen: "127.0.0.1:12345")
    }
    func stop() async { stops += 1 }
}

/// A controllable proxy adapter reports activation and restoration failures.
@MainActor private final class MemoryProxy: SystemProxyServing {
    var needsRecovery = false
    var enables = 0
    var restores = 0
    var rejectRestore = false
    var failActivationWithJournal = false
    func enable(endpoint: ProxyEndpoint) throws {
        enables += 1; needsRecovery = true
        if failActivationWithJournal { throw ControlError("partial activation needs recovery") }
    }
    func restore() throws {
        if rejectRestore { throw ControlError("restore failed") }
        restores += 1; needsRecovery = false
    }
}

/// Native control regressions use isolated storage and injectable platform adapters.
@Suite @MainActor struct ControlTests {
    /// Allocate a unique temporary directory for private metadata and recovery journals.
    private func directory() throws -> URL {
        let result = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: result, withIntermediateDirectories: true)
        return result
    }

    /// Build a minimal password configuration without touching Keychain.
    private func configuration() throws -> CoreConfiguration {
        var profile = ServerProfile(); profile.server = "example.com:38443"
        return try profile.configuration(password: "test-secret")
    }

    @Test func rejectsNonLoopbackEndpoints() throws {
        for address in ["example.com:1080", "0.0.0.0:1080", "127.0.0.1:0", "user@127.0.0.1:1080"] {
            #expect(throws: (any Error).self) { try ProxyEndpoint(listen: address) }
        }
        #expect(try ProxyEndpoint(listen: "[::1]:1080").host == "::1")
    }

    @Test func metadataExcludesPassword() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let store = ProfileStore(directory: path)
        var profile = ServerProfile(); profile.server = "example.com:38443"
        var document = ProfileDocument(); document.profiles = [profile]; document.selectedID = profile.id
        try store.save(document)
        #expect(try store.load() == document)
        let data = try Data(contentsOf: store.file)
        #expect(!String(decoding: data, as: UTF8.self).contains("test-secret"))
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let profiles = try #require(object["profiles"] as? [[String: Any]])
        #expect(profiles[0]["password"] == nil)
    }

    @Test func proxyRestoresExactOriginalAcrossLocationChange() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let memory = MemoryPreferences()
        let before = try #require(memory.states["wifi"])
        let proxy = SystemProxyController(preferences: memory, journal: path.appendingPathComponent("journal"))
        try proxy.enable(endpoint: ProxyEndpoint(listen: "127.0.0.1:12345"))
        #expect(proxy.needsRecovery)
        #expect(memory.states["wifi"]?.configuration?["HTTPEnable"] as? Int == 0)
        #expect(memory.states["wifi"]?.configuration?["SOCKSUser"] == nil)
        memory.states["wifi"]?.activationEligible = false
        try proxy.restore()
        #expect(memory.states["wifi"]?.matches(before) == true)
        #expect(!proxy.needsRecovery)
    }

    @Test func externalChangesArePreserved() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let memory = MemoryPreferences()
        let proxy = SystemProxyController(preferences: memory, journal: path.appendingPathComponent("journal"))
        try proxy.enable(endpoint: ProxyEndpoint(listen: "127.0.0.1:12345"))
        memory.states["wifi"]?.configuration?["SOCKSPort"] = 23456
        try proxy.restore()
        #expect(memory.states["wifi"]?.configuration?["SOCKSPort"] as? Int == 23456)
        #expect(memory.writes == 1)
    }

    @Test func failedActivationRemovesUnusedJournal() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let memory = MemoryPreferences(); memory.failNext = true
        let proxy = SystemProxyController(preferences: memory, journal: path.appendingPathComponent("journal"))
        #expect(throws: (any Error).self) { try proxy.enable(endpoint: ProxyEndpoint(listen: "127.0.0.1:12345")) }
        #expect(!proxy.needsRecovery)
        #expect(memory.states["wifi"]?.configuration?["HTTPEnable"] as? Int == 1)
    }

    @Test func corruptJournalDoesNotWritePreferences() throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let journal = path.appendingPathComponent("journal")
        try Data("invalid".utf8).write(to: journal)
        let memory = MemoryPreferences()
        let proxy = SystemProxyController(preferences: memory, journal: journal)
        #expect(throws: (any Error).self) { try proxy.restore() }
        #expect(memory.writes == 0)
        #expect(proxy.needsRecovery)
    }

    @Test func authenticationFailureNeverEnablesProxy() async throws {
        let engine = MemoryEngine(); engine.startupError = true
        let proxy = MemoryProxy()
        let controller = ConnectionController(engine: engine, proxy: proxy)
        var messages: [String] = []
        controller.onLog = { messages.append($0) }
        await controller.connect(configuration: try configuration())
        #expect(messages.contains(where: { $0.hasPrefix("ERROR 连接失败：") }))
        #expect(controller.phase.idle)
        #expect(proxy.enables == 0)
        #expect(engine.stops == 1)
    }

    @Test func failedRestoreKeepsWorkingCore() async throws {
        let engine = MemoryEngine(), proxy = MemoryProxy()
        let controller = ConnectionController(engine: engine, proxy: proxy)
        await controller.connect(configuration: try configuration())
        #expect(controller.phase.connected)
        #expect(!controller.needsRecovery)
        controller.recover()
        #expect(proxy.restores == 0)
        proxy.rejectRestore = true
        #expect(await controller.disconnect() == false)
        #expect(engine.stops == 0)
        #expect(controller.phase.connected)
        proxy.rejectRestore = false
        #expect(await controller.disconnect())
        #expect(engine.stops == 1)
    }

    @Test func unexpectedExitRestoresProxy() async throws {
        let engine = MemoryEngine(), proxy = MemoryProxy()
        let controller = ConnectionController(engine: engine, proxy: proxy)
        await controller.connect(configuration: try configuration())
        engine.onExit?(9)
        #expect(proxy.restores == 1)
        #expect(controller.endpoint == nil)
        #expect(controller.phase.idle)
    }

    @Test func coreProcessUsesPipeAndExplicitReadiness() async throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let script = path.appendingPathComponent("core")
        let source = """
        #!/usr/bin/env python3
        import json, signal, sys
        assert sys.argv[1:] == ["client", "--config", "-", "--events-json"]
        config = json.load(sys.stdin)
        assert config["password"] == "test-secret"
        assert config["listen"] == "127.0.0.1:0"
        def stop(*args):
            print('{"event":"stopped"}', flush=True)
            sys.exit(0)
        signal.signal(signal.SIGINT, stop)
        print("INFO credential " + config["password"], file=sys.stderr, flush=True)
        print('{"event":"ready","listen":"127.0.0.1:12345"}', flush=True)
        signal.pause()
        """
        try Data(source.utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let engine = CoreProcess(executable: script)
        var messages: [String] = []
        engine.onLog = { messages.append($0) }
        let endpoint = try await engine.start(configuration: configuration())
        #expect(endpoint.port == 12345)
        await engine.stop()
        let restarted = try await engine.start(configuration: configuration())
        #expect(restarted == endpoint)
        await engine.stop()
        #expect(messages.contains(where: { $0.contains("[redacted]") }))
        #expect(!messages.contains(where: { $0.contains("test-secret") }))
    }
    @Test func startupWaitsForReadinessBeforeChangingProxy() async throws {
        let engine = MemoryEngine(), proxy = MemoryProxy()
        engine.suspendStartup = true
        let controller = ConnectionController(engine: engine, proxy: proxy)
        let config = try configuration()
        let task = Task { await controller.connect(configuration: config) }
        while engine.suspension == nil { await Task.yield() }
        #expect(controller.phase == .connecting)
        #expect(proxy.enables == 0)
        engine.suspension?.resume(returning: try ProxyEndpoint(listen: "127.0.0.1:12345"))
        engine.suspension = nil
        await task.value
        #expect(controller.phase.connected)
        #expect(proxy.enables == 1)
        #expect(await controller.disconnect())
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ZION_INTEGRATION_CORE"] != nil))
    func realRustCoreAuthenticatesThroughNativeSupervisor() async throws {
        let path = try directory(); defer { try? FileManager.default.removeItem(at: path) }
        let binary = try #require(ProcessInfo.processInfo.environment["ZION_INTEGRATION_CORE"])
        let identity = path.appendingPathComponent("identity")
        let issuer = Process()
        issuer.executableURL = URL(fileURLWithPath: binary)
        issuer.arguments = ["credentials", "--server-name", "127.0.0.1", "--output", identity.path]
        issuer.standardOutput = FileHandle.nullDevice
        try issuer.run(); issuer.waitUntilExit()
        #expect(issuer.terminationStatus == 0)

        let server = Process(), diagnostics = Pipe()
        let capture = ServerLog()
        server.executableURL = URL(fileURLWithPath: binary)
        server.arguments = ["server", "--transport", "both", "--listen", "127.0.0.1:0", "--credentials", identity.path]
        server.standardOutput = FileHandle.nullDevice
        server.standardError = diagnostics
        var environment = ProcessInfo.processInfo.environment
        environment["NO_COLOR"] = "1"; environment["RUST_LOG"] = "zion=info"
        server.environment = environment
        diagnostics.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            Task { @MainActor in capture.value += String(decoding: data, as: UTF8.self) }
        }
        try server.run()
        defer {
            diagnostics.fileHandleForReading.readabilityHandler = nil
            if server.isRunning { server.terminate() }
            server.waitUntilExit()
        }
        for _ in 0..<100 {
            if capture.value.contains("authenticated QUIC tunnel listening") || !server.isRunning { break }
            try await Task.sleep(for: .milliseconds(50))
        }
        let range = try #require(capture.value.range(of: #"127\.0\.0\.1:[0-9]+"#, options: .regularExpression))
        var profile = ServerProfile()
        profile.server = String(capture.value[range])
        profile.authentication = .certificate
        profile.ca = identity.appendingPathComponent("ca.pem").path
        profile.certificate = identity.appendingPathComponent("client.pem").path
        profile.privateKey = identity.appendingPathComponent("client.key").path
        for transport in TunnelTransport.allCases {
            profile.transport = transport
            let engine = CoreProcess(executable: URL(fileURLWithPath: binary))
            do {
                let endpoint = try await engine.start(configuration: profile.configuration(password: nil))
                #expect(endpoint.host == "127.0.0.1")
                #expect(endpoint.port > 0)
            } catch {
                await engine.stop()
                throw error
            }
            await engine.stop()
            if NativePacketEngine.isLinked {
                let payload = try PacketConfiguration(client: profile.configuration(password: nil)).encoded()
                let native = NativePacketEngine()
                var exits = 0
                native.onExit = { _ in exits += 1 }
                try await native.start(payload: payload, onPacket: { _ in })
                #expect(!native.send(Data([0])))
                do {
                    try await native.start(payload: payload, onPacket: { _ in })
                    Issue.record("running native engine accepted a second start")
                } catch {}

                async let firstStop: Void = native.stop()
                async let secondStop: Void = native.stop()
                _ = await (firstStop, secondStop)
                try await native.start(payload: payload, onPacket: { _ in })
                await native.stop()
                #expect(exits == 0)
            }
        }
    }

    @Test func failedActivationWithPendingRecoveryKeepsCore() async throws {
        let engine = MemoryEngine(), proxy = MemoryProxy()
        proxy.failActivationWithJournal = true
        let controller = ConnectionController(engine: engine, proxy: proxy)
        await controller.connect(configuration: try configuration())
        #expect(controller.phase == .recoveryRequired)
        #expect(!controller.phase.idle)
        #expect(engine.stops == 0)
        #expect(await controller.disconnect())
        #expect(engine.stops == 1)
        #expect(controller.phase == .disconnected)
    }

    @Test func manualRecoveryRefreshesObservableState() {
        let proxy = MemoryProxy(); proxy.needsRecovery = true
        let controller = ConnectionController(engine: MemoryEngine(), proxy: proxy)
        #expect(controller.needsRecovery)
        controller.recover()
        #expect(!controller.needsRecovery)
    }

}

/// A main-actor buffer collects server diagnostics for the optional real-core integration.
@MainActor private final class ServerLog {
    var value = ""
}

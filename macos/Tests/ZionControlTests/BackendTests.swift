import Foundation
import Testing
@testable import ZionControl

/// A fake local engine detects any unintended fallback to the existing system proxy path.
@MainActor private final class BackendTestEngine: EngineServing {
    var onLog: (@MainActor (String) -> Void)?
    var onExit: (@MainActor (Int32) -> Void)?
    var starts = 0
    func start(configuration: CoreConfiguration) async throws -> ProxyEndpoint {
        starts += 1; return try ProxyEndpoint(listen: "127.0.0.1:12345")
    }
    func stop() async {}
}

/// An isolated proxy adapter keeps backend-selection tests away from system preferences.
@MainActor private final class BackendTestProxy: SystemProxyServing {
    var needsRecovery = false
    var failRestore = false
    func enable(endpoint: ProxyEndpoint) throws { needsRecovery = true }
    func restore() throws {
        if failRestore { throw ControlError("system restore rejected") }
        needsRecovery = false
    }
}

/// A controllable enhanced adapter proves mutual exclusion and cleanup semantics independently of signing.
@MainActor private final class TestTunnelBackend: TunnelBackendServing {
    let backend: ConnectionBackend
    var readiness = BackendReadiness.ready
    var needsRecovery = false
    var onExit: (@MainActor (String) -> Void)?
    var failStart = false
    var failStop = false
    var delayStop = false
    var starts = 0
    var stops = 0
    init(_ backend: ConnectionBackend) { self.backend = backend }
    func start(configuration: CoreConfiguration) async throws {
        starts += 1
        if failStart { throw ControlError("start rejected") }
        needsRecovery = true
    }
    func stop() async throws {
        stops += 1
        if delayStop { try await Task.sleep(for: .milliseconds(40)) }
        if failStop { throw ControlError("restore rejected") }
        needsRecovery = false
    }
}

/// Backend tests validate persistence and honest failure behavior without activating system components.
@Suite @MainActor struct BackendTests {
    /// Create a valid in-memory profile while leaving Keychain and metadata storage untouched.
    private func config() throws -> CoreConfiguration {
        var profile = ServerProfile(); profile.server = "example.com:38443"
        return try profile.configuration(password: "test-only")
    }

    /// Build a coordinator with fake transports so no real network write can occur.
    private func coordinator(_ selected: ConnectionBackend = .systemProxy) -> (BackendConnection, BackendTestEngine, TestTunnelBackend, TestTunnelBackend) {
        let engine = BackendTestEngine(), native = TestTunnelBackend(.networkExtension), helper = TestTunnelBackend(.helperTun)
        let control = ConnectionController(engine: engine, proxy: BackendTestProxy())
        return (BackendConnection(system: control, enhanced: [native, helper], selected: selected), engine, native, helper)
    }

    @Test func selectionPersistsWithoutSecrets() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ConnectionPreferencesStore(directory: directory)
        #expect(try store.load().backend == .systemProxy)
        for backend in ConnectionBackend.allCases {
            try store.save(ConnectionPreferences(backend: backend))
            #expect(try store.load().backend == backend)
        }
        let text = try String(contentsOf: store.file, encoding: .utf8)
        #expect(!text.contains("password"))
        try Data(#"{"backend":"unknown"}"#.utf8).write(to: store.file)
        #expect(throws: (any Error).self) { try store.load() }
    }

    @Test func unavailableBackendNeverFallsBack() async throws {
        let (control, engine, native, helper) = coordinator(.networkExtension)
        native.readiness = .unavailable("component missing")
        await control.connect(configuration: try config())
        #expect(control.phase.idle)
        #expect(control.lastError == "component missing")
        #expect(engine.starts == 0)
        #expect(native.starts == 0)
        #expect(helper.starts == 0)
        #expect(control.selectedBackend == .networkExtension)
    }

    @Test func runningBackendCannotBeSwitched() async throws {
        let (control, engine, native, helper) = coordinator(.networkExtension)
        await control.connect(configuration: try config())
        #expect(control.activeBackend == .networkExtension)
        #expect(control.statusTitle == "增强模式已开启")
        #expect(!control.needsRecovery)
        #expect(throws: (any Error).self) { try control.select(.helperTun) }
        #expect(engine.starts == 0)
        #expect(helper.starts == 0)
        #expect(await control.disconnect())
        #expect(native.stops == 1)
        try control.select(.helperTun)
        await control.connect(configuration: try config())
        #expect(control.activeBackend == .helperTun)
        #expect(helper.starts == 1)
        #expect(await control.disconnect())
    }

    @Test func startupFailureDoesNotClaimConnectedOrStartAnotherBackend() async throws {
        let (control, engine, native, helper) = coordinator(.networkExtension)
        native.failStart = true
        await control.connect(configuration: try config())
        #expect(!control.phase.connected)
        #expect(engine.starts == 0)
        #expect(helper.starts == 0)
        #expect(control.activeBackend == nil)
    }

    @Test func cleanupFailureRetainsOwnerAndPreventsSwitching() async throws {
        let (control, _, _, helper) = coordinator(.helperTun)
        await control.connect(configuration: try config())
        helper.failStop = true
        #expect(await control.disconnect() == false)
        #expect(control.phase == .recoveryRequired)
        #expect(control.activeBackend == .helperTun)
        #expect(throws: (any Error).self) { try control.select(.networkExtension) }
        helper.failStop = false
        await control.recover()
        #expect(control.phase == .disconnected)
        #expect(control.activeBackend == nil)
    }

    @Test func systemProxyUsesOnlyItsExistingDriver() async throws {
        let (control, engine, native, helper) = coordinator()
        await control.connect(configuration: try config())
        #expect(control.phase.connected)
        #expect(control.activeBackend == .systemProxy)
        #expect(engine.starts == 1)
        #expect(native.starts == 0 && helper.starts == 0)
        #expect(await control.disconnect())
    }

    @Test func missingNativeDriversRemainExplicitlyUnavailable() {
        let system = ConnectionController(engine: BackendTestEngine(), proxy: BackendTestProxy())
        let control = BackendConnection(system: system, enhanced: [])
        #expect(!control.readiness(for: .networkExtension).canConnect)
        #expect(!control.readiness(for: .helperTun).canConnect)
        #expect(control.readiness(for: .systemProxy).canConnect)
    }
    @Test func startupRecoveryFailureRemainsVisibleWithoutAnActiveBackend() async {
        let proxy = BackendTestProxy(); proxy.needsRecovery = true; proxy.failRestore = true
        let system = ConnectionController(engine: BackendTestEngine(), proxy: proxy)
        let control = BackendConnection(system: system, enhanced: [], selected: .networkExtension)
        #expect(control.needsRecovery)
        await control.recover()
        #expect(control.lastError == "system restore rejected")
        #expect(control.needsRecovery)
        #expect(await control.disconnect() == false)
        proxy.failRestore = false
        await control.recover()
        #expect(!control.needsRecovery)
        #expect(control.lastError == nil)
    }

    @Test func overlappingDisconnectsShareOneTeardown() async throws {
        let (control, _, _, helper) = coordinator(.helperTun)
        helper.delayStop = true
        await control.connect(configuration: try config())
        async let first: Bool = control.disconnect()
        async let second: Bool = control.disconnect()
        let results = await (first, second)
        #expect(results.0 && results.1)
        #expect(helper.stops == 1)
        #expect(control.activeBackend == nil)
        #expect(control.phase == .disconnected)
        try control.select(.networkExtension)
    }

}

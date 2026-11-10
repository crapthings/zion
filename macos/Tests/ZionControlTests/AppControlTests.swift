import Foundation
import Testing
@testable import ZionControl
@testable import ZionMac

/// An in-memory secret store lets command tests verify transactions without accessing Keychain.
@MainActor private final class CommandSecrets: SecretStore {
    var values: [UUID: String] = [:]
    func password(for id: UUID) throws -> String? { values[id] }
    func save(_ password: String, for id: UUID) throws { values[id] = password }
    func delete(for id: UUID) throws { values.removeValue(forKey: id) }
}

/// A fake engine makes command-driven connection transitions independent of remote servers.
@MainActor private final class CommandEngine: EngineServing {
    var onLog: (@MainActor (String) -> Void)?
    var onExit: (@MainActor (Int32) -> Void)?
    var starts = 0
    func start(configuration: CoreConfiguration) async throws -> ProxyEndpoint {
        starts += 1; return try ProxyEndpoint(listen: "127.0.0.1:18080")
    }
    func stop() async {}
}

/// A fake proxy records ownership without touching macOS network preferences.
@MainActor private final class CommandProxy: SystemProxyServing {
    var needsRecovery = false
    func enable(endpoint: ProxyEndpoint) throws { needsRecovery = true }
    func restore() throws { needsRecovery = false }
}

/// App command tests use the same dispatcher as the UI with isolated storage and fake platform services.
@Suite @MainActor struct AppControlTests {
    /// Create an app model whose dependencies cannot change live networking or credentials.
    private func model(_ directory: URL, _ secrets: CommandSecrets, _ engine: CommandEngine = CommandEngine()) -> AppModel {
        AppModel(store: ProfileStore(directory: directory), secrets: secrets,
                 connection: BackendConnection(system: ConnectionController(engine: engine, proxy: CommandProxy()), enhanced: [], selected: .systemProxy))
    }

    /// Encode one request and decode its public response envelope.
    private func call(_ model: AppModel, _ command: String, _ arguments: [String: String] = [:], version: Int = 1) async throws -> [String: Any] {
        let request = AppControlRequest(version: version, command: command, arguments: arguments)
        return try JSONSerialization.jsonObject(with: await model.handleControl(request)) as! [String: Any]
    }

    /// Exercise profile import, connection, busy rejection, disconnect, and secret deletion as one workflow.
    @Test func profileLifecycleSharesLiveAppState() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secrets = CommandSecrets(); let engine = CommandEngine(); let app = model(directory, secrets, engine)
        let config = #"{"server":"passage.example.com:8443","password":"command-secret"}"#
        let imported = try await call(app, "profiles.import", ["name": "Test", "config": config])
        #expect(imported["ok"] as? Bool == true)
        let id = try #require(app.document.selectedID)
        #expect(secrets.values[id] == "command-secret")
        let listing = try await call(app, "profiles.list")
        let listingData = try JSONSerialization.data(withJSONObject: listing)
        #expect(!String(decoding: listingData, as: UTF8.self).contains("command-secret"))
        #expect(!String(decoding: try Data(contentsOf: directory.appendingPathComponent("profiles.json")), as: UTF8.self).contains("command-secret"))
        #expect(try await call(app, "connect")["ok"] as? Bool == true)
        #expect(app.connection.phase.connected)
        #expect(try await call(app, "connect")["ok"] as? Bool == true)
        #expect(engine.starts == 1)
        let busy = try await call(app, "profiles.remove", ["id": id.uuidString])
        #expect((busy["error"] as? [String: String])?["code"] == "busy")
        #expect(try await call(app, "disconnect")["ok"] as? Bool == true)
        #expect(try await call(app, "profiles.remove", ["id": id.uuidString])["ok"] as? Bool == true)
        #expect(app.document.profiles.isEmpty && secrets.values.isEmpty)
    }

    /// Unsupported versions, unexpected arguments, and missing profiles fail without starting a connection.
    @Test func invalidCommandsCannotMutateState() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let app = model(directory, CommandSecrets())
        for (command, arguments, version, code) in [
            ("status", [:], 2, "unsupported_version"),
            ("status", ["password": "secret"], 1, "invalid_arguments"),
            ("connect", [:], 1, "no_profile"),
            ("unknown", [:], 1, "unknown_command"),
            ("profiles.select", ["id": UUID().uuidString], 1, "not_found")
        ] {
            let response = try await call(app, command, arguments, version: version)
            #expect((response["error"] as? [String: String])?["code"] == code)
        }
        #expect(app.document.profiles.isEmpty)
    }

    /// An unavailable backend can be saved but cannot trigger an unintended system-proxy connection.
    @Test func unavailableBackendNeverFallsBack() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let engine = CommandEngine(); let app = model(directory, CommandSecrets(), engine)
        #expect(try await call(app, "backend.select", ["backend": "networkExtension"])["ok"] as? Bool == true)
        let response = try await call(app, "connect")
        #expect((response["error"] as? [String: String])?["code"] == "backend_unavailable")
        #expect(engine.starts == 0)
    }

    /// Metadata write failures roll back newly stored passwords and leave live profiles unchanged.
    @Test func importRollsBackSecretOnStorageFailure() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secrets = CommandSecrets(); let app = model(directory, secrets)
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("profiles.json"), withIntermediateDirectories: true)
        let response = try await call(app, "profiles.import", ["name": "Test", "config": #"{"server":"passage.example.com:8443","password":"secret"}"#])
        #expect(response["ok"] as? Bool == false)
        #expect(app.document.profiles.isEmpty && secrets.values.isEmpty)
    }

    /// Unknown imported fields are rejected before any credentials are persisted.
    @Test func importRejectsUnknownFields() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secrets = CommandSecrets(); let app = model(directory, secrets)
        let response = try await call(app, "profiles.import", ["name": "Test", "config": #"{"server":"passage.example.com:8443","password":"secret","unexpected":true}"#])
        #expect((response["error"] as? [String: String])?["code"] == "invalid_arguments")
        #expect(secrets.values.isEmpty)
    }

    /// CLI log reads and copied diagnostics expose sanitized session entries with bounded limits.
    @Test func logsShareSanitizedEntriesWithCLI() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let app = model(directory, CommandSecrets())
        app.logs.append("ERROR password=hidden failure")
        app.logs.append("INFO latest")
        let result = try await call(app, "logs.read", ["limit": "1"])
        let body = try #require(result["result"] as? [String: Any])
        let entries = try #require(body["entries"] as? [[String: Any]])
        #expect(entries.count == 1 && entries[0]["message"] as? String == "INFO latest")
        #expect(!app.diagnosticReport.contains("hidden"))
        let invalid = try await call(app, "logs.read", ["limit": "101"])
        #expect((invalid["error"] as? [String: String])?["code"] == "invalid_arguments")
    }

    /// An agent can register a helper but approval never changes the unavailable TUN adapter state.
    @Test func componentCommandsKeepApprovalSeparateFromTUN() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let service = RegistrationFixture()
        let app = AppModel(store: ProfileStore(directory: directory), secrets: CommandSecrets(),
            connection: BackendConnection(system: ConnectionController(engine: CommandEngine(), proxy: CommandProxy()), enhanced: [], selected: .helperTun),
            helperInstallation: HelperInstallation(service: service, bundled: true))
        app.editing = ServerProfile()
        #expect(!app.canManageComponents)
        let busy = try await call(app, "component.install")
        #expect((busy["error"] as? [String: String])?["code"] == "busy")
        #expect(service.registers == 0)
        app.editing = nil
        let installed = try await call(app, "component.install")
        let result = try #require(installed["result"] as? [String: Any])
        #expect(result["registration"] as? String == "requiresApproval")
        #expect(result["tun_available"] as? Bool == false)
        service.status = .enabled
        let approved = try await call(app, "component.status")
        #expect((approved["result"] as? [String: Any])?["registration"] as? String == "enabled")
        #expect(!app.connection.readiness(for: .helperTun).canConnect)
        #expect(try await call(app, "component.uninstall")["ok"] as? Bool == true)
        #expect(service.status == .notRegistered)
    }

    /// A real Rust CLI reaches the Swift socket without launching the GUI or writing system settings.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["ZION_CONTROL_CLI"] != nil))
    func rustCLIReachesSwiftControlSocket() async throws {
        let binary = try #require(ProcessInfo.processInfo.environment["ZION_CONTROL_CLI"])
        let directory = URL(fileURLWithPath: "/tmp/zion-test-" + String(UUID().uuidString.prefix(8)))
        let path = directory.appendingPathComponent("control.sock").path
        let app = model(directory, CommandSecrets())
        app.logs.append("INFO socket diagnostic")
        let server = ControlSocket(path: path) { request in await app.handleControl(request) }
        try server.start()
        defer { server.stop(); try? FileManager.default.removeItem(at: directory) }
        let response = try await Task.detached {
            let process = Process(); let output = Pipe()
            process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = ["app", "--socket", path, "logs", "--limit", "1"]
            process.standardOutput = output
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw ControlError("CLI failed.") }
            return data
        }.value
        let result = try JSONSerialization.jsonObject(with: response) as! [String: Any]
        let body = try #require(result["result"] as? [String: Any])
        let entries = try #require(body["entries"] as? [[String: Any]])
        #expect(entries.count == 1 && entries[0]["message"] as? String == "INFO socket diagnostic")
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let duplicate = ControlSocket(path: path) { _ in Data() }
        #expect(throws: (any Error).self) { try duplicate.start() }
        duplicate.stop()
        #expect(FileManager.default.fileExists(atPath: path))
    }
}

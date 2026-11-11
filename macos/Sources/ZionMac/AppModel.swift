import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers
import ZionControl

/// Import values mirror the existing JSON schema and keep imported passwords out of profile storage.
struct ImportedConfiguration: Decodable {
    let server: String
    let transport: TunnelTransport?
    let password: String?
    let ca: String?
    let cert: String?
    let key: String?
    let serverName: String?
    let interface: String?
    enum CodingKeys: String, CodingKey {
        case server, transport, password, ca, cert, key, interface
        case serverName = "server_name"
    }

    /// Distinguish an omitted optional carrier from an invalid explicit value such as null.
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        server = try values.decode(String.self, forKey: .server)
        transport = values.contains(.transport) ? try values.decode(TunnelTransport.self, forKey: .transport) : nil
        password = try values.decodeIfPresent(String.self, forKey: .password)
        ca = try values.decodeIfPresent(String.self, forKey: .ca)
        cert = try values.decodeIfPresent(String.self, forKey: .cert)
        key = try values.decodeIfPresent(String.self, forKey: .key)
        serverName = try values.decodeIfPresent(String.self, forKey: .serverName)
        interface = try values.decodeIfPresent(String.self, forKey: .interface)
    }

    /// Validate the same bounded profile-import schema for file imports and local commands.
    static func parse(_ data: Data) throws -> Self {
        guard data.count <= 64 * 1024,
              let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(fields.keys).isSubset(of: ["server", "transport", "password", "ca", "cert", "key", "listen", "server_name", "interface"]) else {
            throw ControlError("无效的服务器配置；全局规则请在规则页配置。")
        }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.password == nil || (1...1024).contains(value.password!.utf8.count),
              value.server.utf8.count <= 512,
              [value.ca, value.cert, value.key, value.serverName, value.interface].allSatisfy({ ($0?.utf8.count ?? 0) <= 4096 }) else {
            throw ControlError("服务器配置字段超过长度限制。")
        }
        return value
    }

}

/// The application model coordinates profile storage, Keychain, and connection presentation.
@Observable @MainActor final class AppModel {
    var document = ProfileDocument()
    let logs = DiagnosticLog()
    let traffic: TrafficCenter
    var alert: String? { didSet { if let alert { logs.append(alert, level: .error) } } }
    var editing: ServerProfile?
    var editingPassword = ""
    var storageError = false
    let setupGuide: SetupGuide
    let helperInstallation: HelperInstallation
    let connection: BackendConnection
    private let preferences: ConnectionPreferencesStore
    private var preferencesReadable = true
    let store: ProfileStore
    private var control: ControlSocket?
    private let secrets: any SecretStore

    /// Assemble native services without starting a core or modifying network preferences.
    init(store: ProfileStore = ProfileStore(), secrets: any SecretStore = KeychainStore(), connection: BackendConnection? = nil, helperInstallation: HelperInstallation = HelperInstallation(), setupGuide: SetupGuide? = nil) {
        self.setupGuide = setupGuide ?? SetupGuide(directory: store.directory)
        self.helperInstallation = helperInstallation
        self.store = store
        let traffic = TrafficCenter(directory: store.directory)
        self.traffic = traffic
        let core = CoreProcess()
        core.onTraffic = { [weak traffic] record in traffic?.receive(record) }
        core.onTrafficEnd = { [weak traffic] in traffic?.endSession() }
        self.secrets = secrets
        let preferences = ConnectionPreferencesStore(directory: store.directory)
        self.preferences = preferences
        var selected = ConnectionBackend.systemProxy
        do { selected = try preferences.load().backend }
        catch { preferencesReadable = false; alert = "无法读取接管方式设置，连接已暂停，请检查 connection.json。" }
        self.connection = connection ?? BackendConnection(
            system: ConnectionController(engine: core, proxy: SystemProxyController(journal: store.directory.appendingPathComponent("proxy-recovery.plist"))),
            enhanced: [], selected: selected
        )
        helperInstallation.onLog = { [weak self] message in self?.append(message) }
        self.connection.onLog = { [weak self] message in self?.append(message) }
        do { document = try store.load() }
        catch { storageError = true; alert = "无法读取服务器列表，现有配置未被覆盖。" }
        logs.append("应用已启动，已加载 \(document.profiles.count) 台服务器。")
    }

    /// Start local command handling without opening a window or changing network settings.
    func startControl() {
        guard control == nil else { return }
        let service = ControlSocket { [weak self] request in
            guard let self else { return controlFailure("unavailable", "Application is stopping.") }
            return await self.handleControl(request)
        }
        do { try service.start(); control = service }
        catch { storageError = true; preferencesReadable = false; alert = error.localizedDescription }
    }

    var selectedProfile: ServerProfile? { document.profiles.first { $0.id == document.selectedID } }

    /// Save an explicit transport choice only after the current owner has fully disconnected.
    func selectBackend(_ backend: ConnectionBackend) {
        guard preferencesReadable, !helperInstallation.busy else { return }
        do {
            let previous = connection.selectedBackend
            try connection.select(backend)
            do { try preferences.save(ConnectionPreferences(backend: backend)) }
            catch { try? connection.select(previous); throw error }
        } catch { alert = error.localizedDescription }
    }

    var canConnect: Bool { editing == nil && !helperInstallation.busy && !storageError && traffic.storageError == nil && preferencesReadable && connection.readiness(for: connection.selectedBackend).canConnect }

    /// Allow component changes only after all network ownership and recovery have ended.
    var canManageComponents: Bool { !storageError && connection.phase.idle && !connection.needsRecovery && !helperInstallation.busy && editing == nil }

    /// Register the bundled helper without changing the connection backend or creating a TUN device.
    func installHelper() {
        guard canManageComponents else { return }
        helperInstallation.install()
    }

    /// Remove the helper registration only while no connection owns network settings.
    func uninstallHelper() async {
        guard canManageComponents else { return }
        await helperInstallation.uninstall()
    }

    /// Show setup again without changing the selected profile, backend, or connection.
    func showSetup() { setupGuide.open() }

    /// Complete or skip setup even when network permissions or a server are unavailable.
    func finishSetup() {
        setupGuide.finish(persist: !storageError)
        if let error = setupGuide.preferenceError { logs.append(error, level: .warning) }
    }

    /// Permit guide configuration only while storage, connection ownership, and editing are ready.
    var canConfigureSetupProxy: Bool {
        !storageError && preferencesReadable && !helperInstallation.busy && connection.phase.idle && !connection.needsRecovery && editing == nil
    }

    /// Run system-proxy activation only after the guide's explicit connection action.
    func connectFromSetup() async {
        guard canConfigureSetupProxy else { return }
        guard selectedProfile != nil else { edit(); return }
        selectBackend(.systemProxy)
        guard connection.selectedBackend == .systemProxy else { return }
        await toggle()
        setupGuide.refresh()
    }

    /// Select a profile only when doing so cannot silently change a running connection.
    func select(_ profile: ServerProfile) {
        guard !storageError, !helperInstallation.busy, connection.phase.idle else { return }
        document.selectedID = profile.id
        persist()
    }

    /// Open a profile editor and retrieve its password only for this explicit edit action.
    func edit(_ profile: ServerProfile? = nil) {
        guard !storageError, !helperInstallation.busy, connection.phase.idle else { return }
        do {
            let value = profile ?? ServerProfile()
            editingPassword = try profile.flatMap { try secrets.password(for: $0.id) } ?? ""
            editing = value
        } catch { alert = error.localizedDescription }
    }

    /// Save metadata and Keychain content while rolling back a failed metadata transaction.
    func save(_ profile: ServerProfile, password: String) throws {
        guard connection.phase.idle, !connection.needsRecovery, !helperInstallation.busy else { throw ControlError("请先断开连接，再修改服务器配置。") }
        guard !storageError else { throw ControlError("服务器列表尚未恢复，请先检查现有配置文件。") }
        try profile.validate()
        if profile.authentication == .password && password.isEmpty { throw ControlError("请输入服务器密码。") }
        let previous = try secrets.password(for: profile.id)
        var next = document
        if let index = next.profiles.firstIndex(where: { $0.id == profile.id }) { next.profiles[index] = profile }
        else { next.profiles.append(profile) }
        next.selectedID = profile.id
        do {
            if profile.authentication == .password { try secrets.save(password, for: profile.id) }
            else { try secrets.delete(for: profile.id) }
            try store.save(next)
            document = next
            editingPassword = ""
            editing = nil
            append("服务器配置已保存。")
        } catch {
            if let previous { try? secrets.save(previous, for: profile.id) }
            else { try? secrets.delete(for: profile.id) }
            throw error
        }
    }

    /// Remove a profile without leaving its password in the Keychain.
    func remove(_ profile: ServerProfile) {
        guard !storageError, !helperInstallation.busy, connection.phase.idle else { return }
        do {
            let oldPassword = try secrets.password(for: profile.id)
            var next = document
            next.profiles.removeAll { $0.id == profile.id }
            if next.selectedID == profile.id { next.selectedID = next.profiles.first?.id }
            try secrets.delete(for: profile.id)
            do { try store.save(next) }
            catch { if let oldPassword { try? secrets.save(oldPassword, for: profile.id) }; throw error }
            document = next
        } catch { alert = error.localizedDescription }
    }

    /// Recover network settings only while this app has readable storage and control ownership.
    func recover() async {
        guard !storageError else { return }
        await connection.recover()
    }

    /// Toggle the selected authenticated core and its owned system proxy settings.
    func toggle() async {
        if connection.phase.active || connection.phase.busy { _ = await connection.disconnect(); return }
        guard !helperInstallation.busy, editing == nil else { return }
        guard !storageError else { alert = "Profile storage or app ownership is unavailable."; return }
        guard preferencesReadable else { alert = "请先修复接管方式设置文件。"; return }
        guard let profile = selectedProfile else { edit(); return }
        do {
            await connection.connect(configuration: try connectionConfiguration(for: profile))
        } catch { alert = error.localizedDescription }
    }

    /// Prepare credentials, saved routing, and traffic state for one authenticated connection.
    private func connectionConfiguration(for profile: ServerProfile) throws -> CoreConfiguration {
        if let error = traffic.storageError { throw ControlError(error) }
        let password = profile.authentication == .password ? try secrets.password(for: profile.id) : nil
        var configuration = try profile.configuration(password: password)
        configuration.routing = traffic.routing
        traffic.beginSession()
        return configuration
    }

    /// Persist routing changes only when no core is using an earlier rules snapshot.
    func saveRouting(_ value: RoutingDocument) {
        guard connection.phase.idle, !connection.needsRecovery else { return }
        do { try traffic.save(value) }
        catch { alert = error.localizedDescription }
    }

    /// Import JSON into the normal editor so secrets are stored only after explicit saving.
    func importJSON() {
        guard !storageError, !helperInstallation.busy, connection.phase.idle else { return }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url)
            let value = try ImportedConfiguration.parse(data)
            var profile = ServerProfile()
            profile.name = URLComponents(string: "quic://\(value.server)")?.host ?? "导入的服务器"
            profile.transport = value.transport ?? .quic
            profile.server = value.server
            profile.authentication = value.password == nil ? .certificate : .password
            profile.ca = resolve(value.ca, relativeTo: url)
            profile.certificate = resolve(value.cert, relativeTo: url)
            profile.privateKey = resolve(value.key, relativeTo: url)
            profile.serverName = value.serverName ?? ""
            profile.interface = value.interface ?? ""
            editingPassword = value.password ?? ""
            editing = profile
        } catch { alert = "无法导入 JSON 配置，请检查字段与文件格式。" }
    }

    /// Keep imported credential paths relative to their original configuration location.
    private func resolve(_ path: String?, relativeTo url: URL) -> String {
        guard let path, !path.isEmpty else { return "" }
        return (path as NSString).isAbsolutePath ? path : url.deletingLastPathComponent().appendingPathComponent(path).standardized.path
    }

    /// Persist selection changes without discarding a document that failed initial loading.
    private func persist() {
        guard !storageError else { return }
        do { try store.save(document) } catch { alert = error.localizedDescription }
    }

    /// Bound activity history to avoid retaining an unbounded stream of diagnostic messages.
    private func append(_ message: String) {
        logs.append(message)
    }
}

/// Local commands reuse the app's live state and never return stored authentication secrets.
extension AppModel {
    /// Dispatch one versioned request and report failures with stable machine-readable codes.
    func handleControl(_ request: AppControlRequest) async -> Data {
        guard request.version == 1 else { return controlFailure("unsupported_version", "Expected control version 1.") }
        do {
            let allowed: Set<String>
            switch request.command {
            case "status", "profiles.list", "connect", "disconnect", "component.status", "component.install", "component.uninstall": allowed = []
            case "logs.read": allowed = ["limit"]
            case "profiles.import": allowed = ["name", "config"]
            case "profiles.select", "profiles.remove": allowed = ["id"]
            case "profiles.transport": allowed = ["id", "transport"]
            case "backend.select": allowed = ["backend"]
            default: return controlFailure("unknown_command", "Unknown control command.")
            }
            guard Set(request.arguments.keys) == allowed else { return controlFailure("invalid_arguments", "Unexpected or missing arguments.") }
            let result = try await executeControl(request)
            return try JSONSerialization.data(withJSONObject: ["version": 1, "ok": true, "result": result], options: [.sortedKeys])
        } catch let error as AppCommandError { return controlFailure(error.code, error.message) }
        catch { return controlFailure("operation_failed", "Operation failed; inspect the app activity and local configuration.") }
    }

    /// Enforce command preconditions before touching profiles, credentials, or connection ownership.
    private func executeControl(_ request: AppControlRequest) async throws -> [String: Any] {
        let arguments = request.arguments
        switch request.command {
        case "status": return controlStatus()
        case "component.status":
            helperInstallation.refresh()
            return componentStatus()
        case "component.install":
            try requireControlIdle()
            guard helperInstallation.bundled else { throw AppCommandError("component_missing", "This app bundle does not contain the helper.") }
            guard helperInstallation.canInstall else { throw AppCommandError("component_state", "Inspect component status before requesting registration again.") }
            helperInstallation.install()
            guard helperInstallation.lastError == nil else { throw AppCommandError("operation_failed", "System registration failed; inspect the app logs.") }
            return componentStatus()
        case "component.uninstall":
            try requireControlIdle()
            guard helperInstallation.canUninstall else { throw AppCommandError("component_state", "No removable helper registration was found.") }
            await helperInstallation.uninstall()
            guard helperInstallation.lastError == nil else { throw AppCommandError("operation_failed", "System removal failed; inspect the app logs.") }
            return componentStatus()

        case "logs.read":
            guard let raw = arguments["limit"], let limit = Int(raw), (1...100).contains(limit) else {
                throw AppCommandError("invalid_arguments", "Log limit must be from 1 to 100.")
            }
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(Array(logs.entries.suffix(limit)))
            return ["entries": try JSONSerialization.jsonObject(with: data), "retained": logs.entries.count]

        case "profiles.list":
            guard !storageError else { throw AppCommandError("storage_unavailable", "Profile storage is unreadable.") }
            let data = try JSONEncoder().encode(document)
            return try JSONSerialization.jsonObject(with: data) as! [String: Any]
        case "profiles.import":
            try requireControlIdle()
            guard let source = arguments["config"], let data = source.data(using: .utf8), data.count <= 64 * 1024,
                  let name = arguments["name"], !name.isEmpty, name.utf8.count <= 128, document.profiles.count < 64 else { throw AppCommandError("invalid_arguments", "Import requires name and JSON config.") }
            let value: ImportedConfiguration
            do { value = try ImportedConfiguration.parse(data) }
            catch { throw AppCommandError("invalid_arguments", "Invalid server profile configuration; configure global routing separately.") }
            var profile = ServerProfile()
            profile.name = name; profile.server = value.server; profile.transport = value.transport ?? .quic
            profile.authentication = value.password == nil ? .certificate : .password
            profile.ca = value.ca ?? ""; profile.certificate = value.cert ?? ""; profile.privateKey = value.key ?? ""
            profile.serverName = value.serverName ?? ""; profile.interface = value.interface ?? ""
            try save(profile, password: value.password ?? "")
            return ["id": profile.id.uuidString]
        case "profiles.transport":
            try requireControlIdle()
            guard let id = arguments["id"].flatMap(UUID.init(uuidString:)), let index = document.profiles.firstIndex(where: { $0.id == id }) else {
                throw AppCommandError("not_found", "Profile ID was not found.")
            }
            guard let transport = arguments["transport"].flatMap(TunnelTransport.init(rawValue:)) else {
                throw AppCommandError("invalid_arguments", "Transport must be quic or tls.")
            }
            var next = document; next.profiles[index].transport = transport
            try store.save(next); document = next
            append("隧道传输已更新：" + transport.title)
            return ["id": id.uuidString, "transport": transport.rawValue]
        case "profiles.select", "profiles.remove":
            try requireControlIdle()
            guard let id = arguments["id"].flatMap(UUID.init(uuidString:)), let profile = document.profiles.first(where: { $0.id == id }) else {
                throw AppCommandError("not_found", "Profile ID was not found.")
            }
            if request.command == "profiles.select" {
                var next = document; next.selectedID = id
                try store.save(next); document = next
            } else {
                remove(profile)
                guard !document.profiles.contains(where: { $0.id == id }) else { throw AppCommandError("operation_failed", "Profile could not be removed.") }
            }
            return controlStatus()
        case "backend.select":
            try requireControlIdle()
            guard preferencesReadable, let backend = arguments["backend"].flatMap(ConnectionBackend.init(rawValue:)) else {
                throw AppCommandError("invalid_arguments", "Backend must be systemProxy, networkExtension, or helperTun.")
            }
            let old = connection.selectedBackend
            try connection.select(backend)
            do { try preferences.save(ConnectionPreferences(backend: backend)) }
            catch { try? connection.select(old); throw error }
            return controlStatus()
        case "connect":
            if connection.phase.connected { return controlStatus() }
            try requireControlIdle()
            guard canConnect else { throw AppCommandError("backend_unavailable", "Selected backend is unavailable.") }
            guard let profile = selectedProfile else { throw AppCommandError("no_profile", "Import and select a server first.") }
            await connection.connect(configuration: try connectionConfiguration(for: profile))
            guard connection.phase.connected else { throw AppCommandError("connection_failed", "Connection did not complete; inspect app status and activity.") }
            return controlStatus()
        case "disconnect":
            guard await connection.disconnect() else { throw AppCommandError("recovery_required", "Network settings could not be restored.") }
            return controlStatus()
        default: throw AppCommandError("unknown_command", "Unknown control command.")
        }
    }

    /// Report registration without conflating installed components with available TUN routing.
    private func componentStatus() -> [String: Any] {
        ["bundled": helperInstallation.bundled, "registration": helperInstallation.status.rawValue,
         "busy": helperInstallation.busy, "tun_available": false]
    }

    /// Reject metadata changes during a connection, recovery, or an open profile edit.
    private func requireControlIdle() throws {
        guard !storageError else { throw AppCommandError("storage_unavailable", "Profile storage is unreadable.") }
        guard !helperInstallation.busy, connection.phase.idle, !connection.needsRecovery, editing == nil else { throw AppCommandError("busy", "Disconnect, recover networking, and close the profile editor first.") }
    }

    /// Expose stable state names without returning passwords, logs, or private-key contents.
    private func controlStatus() -> [String: Any] {
        let phase: String
        switch connection.phase {
        case .disconnected: phase = "disconnected"
        case .connecting: phase = "connecting"
        case .authorizing: phase = "authorizing"
        case .connected: phase = "connected"
        case .disconnecting: phase = "disconnecting"
        case .recoveryRequired: phase = "recovery_required"
        case .failed: phase = "failed"
        }
        return ["phase": phase, "transport": selectedProfile?.transport.rawValue as Any? ?? NSNull(), "selected_backend": connection.selectedBackend.rawValue,
                "active_backend": connection.activeBackend?.rawValue as Any? ?? NSNull(),
                "selected_profile": document.selectedID?.uuidString as Any? ?? NSNull(),
                "endpoint": connection.endpoint?.description as Any? ?? NSNull(),
                "needs_recovery": connection.needsRecovery, "can_connect": canConnect && selectedProfile != nil && connection.phase.idle && !connection.needsRecovery && editing == nil]
    }
}

/// Command failures separate stable protocol codes from presentation-layer error messages.
private struct AppCommandError: Error {
    let code: String
    let message: String
    init(_ code: String, _ message: String) { self.code = code; self.message = message }
}

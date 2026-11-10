import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers
import ZionControl

/// An activity entry contains a bounded diagnostic line and its arrival time.
struct ActivityEntry: Identifiable {
    let id = UUID()
    let date = Date()
    let message: String
}

/// Import values mirror the existing JSON schema and keep imported passwords out of profile storage.
private struct ImportedConfiguration: Decodable {
    let server: String
    let password: String?
    let ca: String?
    let cert: String?
    let key: String?
    let serverName: String?
    let interface: String?
    enum CodingKeys: String, CodingKey {
        case server, password, ca, cert, key, interface
        case serverName = "server_name"
    }
}

/// The application model coordinates profile storage, Keychain, and connection presentation.
@Observable @MainActor final class AppModel {
    var document = ProfileDocument()
    var activities: [ActivityEntry] = []
    var alert: String?
    var editing: ServerProfile?
    var editingPassword = ""
    var storageError = false
    let connection: BackendConnection
    private let preferences: ConnectionPreferencesStore
    private var preferencesReadable = true
    let store: ProfileStore
    private let secrets: any SecretStore

    /// Assemble native services without starting a core or modifying network preferences.
    init() {
        let store = ProfileStore()
        self.store = store
        secrets = KeychainStore()
        let preferences = ConnectionPreferencesStore(directory: store.directory)
        self.preferences = preferences
        var selected = ConnectionBackend.systemProxy
        do { selected = try preferences.load().backend }
        catch { preferencesReadable = false; alert = "无法读取接管方式设置，连接已暂停，请检查 connection.json。" }
        connection = BackendConnection(
            system: ConnectionController(engine: CoreProcess(), proxy: SystemProxyController(journal: store.directory.appendingPathComponent("proxy-recovery.plist"))),
            enhanced: [], selected: selected
        )
        connection.onLog = { [weak self] message in self?.append(message) }
        do { document = try store.load() }
        catch { storageError = true; alert = "无法读取服务器列表，现有配置未被覆盖。" }
    }

    var selectedProfile: ServerProfile? { document.profiles.first { $0.id == document.selectedID } }

    /// Save an explicit transport choice only after the current owner has fully disconnected.
    func selectBackend(_ backend: ConnectionBackend) {
        guard preferencesReadable else { return }
        do {
            let previous = connection.selectedBackend
            try connection.select(backend)
            do { try preferences.save(ConnectionPreferences(backend: backend)) }
            catch { try? connection.select(previous); throw error }
        } catch { alert = error.localizedDescription }
    }

    var canConnect: Bool { preferencesReadable && connection.readiness(for: connection.selectedBackend).canConnect }

    /// Select a profile only when doing so cannot silently change a running connection.
    func select(_ profile: ServerProfile) {
        guard connection.phase.idle else { return }
        document.selectedID = profile.id
        persist()
    }

    /// Open a profile editor and retrieve its password only for this explicit edit action.
    func edit(_ profile: ServerProfile? = nil) {
        guard connection.phase.idle else { return }
        do {
            let value = profile ?? ServerProfile()
            editingPassword = try profile.flatMap { try secrets.password(for: $0.id) } ?? ""
            editing = value
        } catch { alert = error.localizedDescription }
    }

    /// Save metadata and Keychain content while rolling back a failed metadata transaction.
    func save(_ profile: ServerProfile, password: String) throws {
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
        guard connection.phase.idle else { return }
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

    /// Toggle the selected authenticated core and its owned system proxy settings.
    func toggle() async {
        if connection.phase.active || connection.phase.busy { _ = await connection.disconnect(); return }
        guard preferencesReadable else { alert = "请先修复接管方式设置文件。"; return }
        guard let profile = selectedProfile else { edit(); return }
        do {
            let password = profile.authentication == .password ? try secrets.password(for: profile.id) : nil
            let configuration = try profile.configuration(password: password)
            await connection.connect(configuration: configuration)
        } catch { alert = error.localizedDescription }
    }

    /// Import JSON into the normal editor so secrets are stored only after explicit saving.
    func importJSON() {
        guard connection.phase.idle else { return }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url)
            guard data.count <= 64 * 1024 else { throw ControlError("配置文件超过 64 KiB。") }
            let value = try JSONDecoder().decode(ImportedConfiguration.self, from: data)
            var profile = ServerProfile()
            profile.name = URLComponents(string: "quic://\(value.server)")?.host ?? "导入的服务器"
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
        activities.append(ActivityEntry(message: message))
        if activities.count > 500 { activities.removeFirst(activities.count - 500) }
    }
}

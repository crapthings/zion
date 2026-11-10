import Foundation
import Observation
import ServiceManagement
import ZionHelperProtocol

/// Registration status describes system approval independently from TUN connection readiness.
public enum HelperRegistration: String, Sendable {
    case notRegistered, requiresApproval, enabled, notFound, unknown

    public var title: String {
        switch self {
        case .notRegistered: "未安装"
        case .requiresApproval: "等待系统批准"
        case .enabled: "已注册并获准运行"
        case .notFound: "系统未找到组件"
        case .unknown: "未知状态"
        }
    }
}

/// An injectable registration service keeps unit tests away from actual launchd changes.
@MainActor public protocol HelperRegistrationServing {
    var status: HelperRegistration { get }
    func register() throws
    func unregister() async throws
    func openApprovalSettings()
}

/// Apple Service Management owns helper registration, approval, and removal for the containing app.
@MainActor public final class AppHelperRegistration: HelperRegistrationServing {
    private let service = SMAppService.daemon(plistName: HelperComponent.plist)
    public init() {}

    public var status: HelperRegistration {
        switch service.status {
        case .notRegistered: .notRegistered
        case .requiresApproval: .requiresApproval
        case .enabled: .enabled
        case .notFound: .notFound
        @unknown default: .unknown
        }
    }

    /// Ask macOS to register the bundled daemon without writing system launchd directories directly.
    public func register() throws { try service.register() }

    /// Await system removal before allowing the registration to be changed again.
    public func unregister() async throws { try await service.unregister() }

    /// Open Apple's approval page only after an explicit user action.
    public func openApprovalSettings() { SMAppService.openSystemSettingsLoginItems() }
}

/// Installation state combines bundle availability and real OS registration without enabling TUN.
@Observable @MainActor public final class HelperInstallation {
    public private(set) var status: HelperRegistration
    public private(set) var busy = false
    public private(set) var lastError: String?
    public let bundled: Bool
    public var onLog: (@MainActor (String) -> Void)?
    private let service: any HelperRegistrationServing

    /// Inspect bundle resources without installing, authorizing, or launching a helper.
    public init(service: any HelperRegistrationServing = AppHelperRegistration(), bundle: Bundle = .main, bundled: Bool? = nil) {
        self.service = service
        self.bundled = bundled ?? (FileManager.default.isExecutableFile(atPath: bundle.bundleURL.appendingPathComponent(HelperComponent.program).path)
            && FileManager.default.fileExists(atPath: bundle.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/" + HelperComponent.plist).path))
        status = service.status
    }

    public var canInstall: Bool { bundled && !busy && (status == .notRegistered || status == .notFound) }
    public var canUninstall: Bool { !busy && (status == .enabled || status == .requiresApproval) }

    /// Refresh approval changes when the app becomes active or the user requests an update.
    public func refresh() { guard !busy else { return }; status = service.status }

    /// Register only an available component and retain the OS approval state as reported.
    public func install() {
        guard canInstall else { return }
        busy = true; lastError = nil
        defer { status = service.status; busy = false }
        do {
            try service.register()
            onLog?("辅助组件注册请求已提交，状态：" + service.status.title)
        } catch { record(error) }
    }

    /// Remove either an approved or pending registration without modifying the selected backend.
    public func uninstall() async {
        guard canUninstall else { return }
        busy = true; lastError = nil
        defer { status = service.status; busy = false }
        do { try await service.unregister(); onLog?("辅助组件注册已移除。") }
        catch { record(error) }
    }

    /// Show the system approval page while leaving the approval decision to the user.
    public func openApprovalSettings() { service.openApprovalSettings() }

    /// Preserve actionable OS error domain and code without exposing arbitrary error payloads.
    private func record(_ error: Error) {
        let error = error as NSError
        lastError = "辅助组件操作失败（\(error.domain)，\(error.code)），请检查系统授权与应用签名。"
        onLog?("ERROR " + lastError!)
    }
}

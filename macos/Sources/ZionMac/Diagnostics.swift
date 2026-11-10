import Foundation
import ZionControl

/// A diagnostic field reports one observed app or configuration value without probing the network.
struct DiagnosticField: Identifiable {
    let label: String
    let value: String
    var id: String { label }
}

/// Diagnostic snapshots expose live connection state while excluding credential contents and paths.
extension AppModel {
    /// Build the fields shown in the log page and included in copied reports.
    var diagnosticFields: [DiagnosticField] {
        [DiagnosticField(label: "状态", value: connection.statusTitle),
         DiagnosticField(label: "接管方式", value: connection.selectedBackend.title),
         DiagnosticField(label: "服务器", value: selectedProfile.map { $0.server + " · " + $0.transport.title } ?? "尚未选择"),
         DiagnosticField(label: "本地监听", value: connection.endpoint?.description ?? "未运行"),
         DiagnosticField(label: "出口网卡", value: selectedProfile?.interface.nilIfEmpty ?? "系统路由"),
         DiagnosticField(label: "网络恢复", value: connection.needsRecovery ? "需要恢复" : "无待处理恢复")]
    }

    /// Capture current state and retained session logs without reading Keychain or certificate files.
    var diagnosticReport: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
        var lines = ["Zion \(version)", Date().ISO8601Format(), ProcessInfo.processInfo.operatingSystemVersionString]
        lines.append("辅助组件: " + helperInstallation.status.title)
        lines += diagnosticFields.map { "\($0.label): \($0.value)" }
        if let error = connection.lastError { lines.append("最近错误: " + error) }
        if let reason = connection.readiness(for: connection.selectedBackend).explanation { lines.append(reason) }
        lines += ["", "Session log", logs.text()]
        var sanitizer = DiagnosticSanitizer()
        return lines.joined(separator: "\n").components(separatedBy: "\n").map { sanitizer.clean($0) }.joined(separator: "\n")
    }
}

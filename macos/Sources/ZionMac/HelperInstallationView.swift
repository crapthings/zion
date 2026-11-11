import SwiftUI
import ZionControl

/// The component panel exposes real registration and approval separately from unavailable TUN routing.
struct HelperInstallationView: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
            HStack(spacing: InterfaceSpacing.small) {
                Label("辅助组件", systemImage: "shippingbox").help("组件注册独立于 TUN 网络接管；安装后仍无法启用增强模式。")
                Spacer()
                if model.helperInstallation.busy { ProgressView().controlSize(.small) }
                Text(model.helperInstallation.status.title).foregroundStyle(.secondary)
            }.font(.subheadline)
            if !model.helperInstallation.bundled {
                Label("未包含辅助组件", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let error = model.helperInstallation.lastError {
                Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            HStack(spacing: InterfaceSpacing.small) {
                Button("安装") { model.installHelper() }
                    .disabled(!model.canManageComponents || !model.helperInstallation.canInstall)
                if model.helperInstallation.status == .requiresApproval {
                    Button("授权", systemImage: "arrow.up.forward.app") { model.helperInstallation.openApprovalSettings() }
                        .disabled(model.helperInstallation.busy)
                }
                Button("刷新", systemImage: "arrow.clockwise") { model.helperInstallation.refresh() }
                    .labelStyle(.iconOnly).help("刷新组件状态").disabled(model.helperInstallation.busy)
                Spacer()
                Button("卸载", role: .destructive) { Task { await model.uninstallHelper() } }
                    .disabled(!model.canManageComponents || !model.helperInstallation.canUninstall)
            }.controlSize(.small)
        }.padding(.vertical, InterfaceSpacing.medium).frame(maxWidth: .infinity, alignment: .leading)
    }
}

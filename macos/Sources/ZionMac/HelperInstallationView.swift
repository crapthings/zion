import SwiftUI
import ZionControl

/// The component panel exposes real registration and approval separately from unavailable TUN routing.
struct HelperInstallationView: View {
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("TUN 辅助组件", systemImage: "shippingbox")
                Spacer()
                if model.helperInstallation.busy { ProgressView().controlSize(.small) }
                Text(model.helperInstallation.status.title).foregroundStyle(.secondary)
            }.font(.subheadline)
            Text("当前可安装辅助组件；TUN 网络接管尚未完成，安装后仍不能启用全局代理。")
                .font(.caption).foregroundStyle(.secondary)
            if !model.helperInstallation.bundled {
                Label("此构建未包含辅助组件，请使用完整的 Zion.app。", systemImage: "info.circle")
                    .font(.caption).foregroundStyle(.orange)
            }
            if let error = model.helperInstallation.lastError {
                Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            HStack {
                if model.helperInstallation.canInstall {
                    Button("安装辅助组件") { model.installHelper() }.disabled(!model.canManageComponents)
                }
                if model.helperInstallation.status == .requiresApproval {
                    Button("前往系统授权", systemImage: "arrow.up.forward.app") { model.helperInstallation.openApprovalSettings() }
                }
                Button("刷新状态", systemImage: "arrow.clockwise") { model.helperInstallation.refresh() }
                    .disabled(model.helperInstallation.busy)
                if model.helperInstallation.canUninstall {
                    Spacer()
                    Button("卸载组件", role: .destructive) { Task { await model.uninstallHelper() } }
                        .disabled(!model.canManageComponents)
                }
            }.controlSize(.small)
        }.padding(14).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}

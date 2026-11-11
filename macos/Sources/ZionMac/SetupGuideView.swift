import SwiftUI
import ZionControl

/// The first-launch guide presents observed network state and leaves every configuration action explicit.
struct SetupGuideView: View {
    let model: AppModel

    /// Distinguish Zion's established proxy ownership from proxy flags set by another application.
    private var zionProxyActive: Bool {
        model.connection.phase.connected && model.connection.activeBackend == .systemProxy
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                    Text("欢迎使用 Zion").font(.system(size: 26, weight: .semibold, design: .rounded))
                        .padding(.bottom, InterfaceSpacing.small)
                    serverSection
                    proxySection
                    DisclosureGroup("增强模式") { enhancedSection.padding(.top, InterfaceSpacing.medium) }
                        .font(.subheadline).foregroundStyle(.secondary)
                    if model.connection.needsRecovery {
                        Surface {
                            HStack(spacing: InterfaceSpacing.small) {
                                Label("代理设置待恢复", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                                Spacer()
                                Button("恢复网络") { Task { await model.recover(); model.setupGuide.refresh() } }
                                    .disabled(model.connection.phase.busy)
                            }
                        }
                    }
                    if let error = model.setupGuide.detectionError {
                        Label(error, systemImage: "exclamationmark.circle").font(.callout).foregroundStyle(.orange)
                    }
                    if let error = model.setupGuide.preferenceError {
                        Text(error).font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(InterfaceSpacing.large).frame(maxWidth: .infinity, alignment: .leading)
            }
            Divider()
            HStack(spacing: InterfaceSpacing.medium) {
                Toggle("启动时显示", isOn: Binding(get: { model.setupGuide.showOnLaunch }, set: { model.setupGuide.showOnLaunch = $0 }))
                    .toggleStyle(.checkbox).font(.callout)
                Spacer()
                Button("完成") { model.finishSetup() }.buttonStyle(.borderless).keyboardShortcut(.defaultAction)
            }.padding(.horizontal, InterfaceSpacing.medium).padding(.vertical, InterfaceSpacing.medium)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { model.setupGuide.refresh(); model.helperInstallation.refresh() }
    }

    /// Reuse the normal profile editor rather than inventing an onboarding-only credential store.
    private var serverSection: some View {
        Surface {
            HStack(spacing: InterfaceSpacing.medium) {
                Image(systemName: "server.rack").font(.title2).foregroundStyle(.secondary).frame(width: 32)
                VStack(alignment: .leading, spacing: InterfaceSpacing.small) {
                    Text(model.selectedProfile?.name ?? "服务器").font(.headline)
                    Text(model.selectedProfile.map { $0.server + " · " + $0.transport.title } ?? "尚未配置").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button(model.selectedProfile == nil ? "添加服务器" : "编辑") { model.edit(model.selectedProfile) }
                    .disabled(!model.canConfigureSetupProxy)
                Button("导入") { model.importJSON() }.disabled(!model.canConfigureSetupProxy)
            }
        }
    }

    /// Report system proxy flags separately from the core's authenticated connection state.
    private var proxySection: some View {
        Surface {
            VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                HStack(spacing: InterfaceSpacing.medium) {
                    Image(systemName: "network").font(.title2).foregroundStyle(Color.accentColor).frame(width: 32)
                    Text("系统代理").font(.headline)
                    Spacer()
                    Text(zionProxyActive ? "已连接" : "未连接").font(.callout).foregroundStyle(zionProxyActive ? Color.green : .secondary)
                }
                if let snapshot = model.setupGuide.snapshot {
                    Text(snapshot.proxies.isEmpty ? "系统设置 · 未启用" : "系统设置 · " + snapshot.proxies.map(\.rawValue).joined(separator: "、"))
                        .font(.callout).textSelection(.enabled)
                } else { Text("待检测").font(.callout).foregroundStyle(.secondary) }
                HStack(spacing: InterfaceSpacing.small) {
                    Button(zionProxyActive ? "已连接" : "连接") { Task { await model.connectFromSetup() } }
                        .disabled(!model.canConfigureSetupProxy)
                    Button("刷新", systemImage: "arrow.clockwise") { model.setupGuide.refresh() }
                        .labelStyle(.iconOnly).help("刷新网络状态")
                    if let snapshot = model.setupGuide.snapshot {
                        Spacer()
                        Text(snapshot.date, style: .time).font(.caption).foregroundStyle(.tertiary)
                    }
                }
                if let error = model.connection.lastError {
                    Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                }
            }
        }
    }

    /// Expose existing virtual interfaces without treating them as a working Zion tunnel.
    private var enhancedSection: some View {
        Surface {
            VStack(alignment: .leading, spacing: InterfaceSpacing.medium) {
                HStack(spacing: InterfaceSpacing.medium) {
                    Image(systemName: "point.3.connected.trianglepath.dotted").font(.title2).foregroundStyle(.secondary).frame(width: 32)
                    Text("TUN").font(.headline)
                    Spacer()
                    Text("尚未就绪").font(.callout).foregroundStyle(.secondary)
                }
                if let snapshot = model.setupGuide.snapshot {
                    Text(snapshot.virtualInterfaces.isEmpty ? "无活跃虚拟接口" : "虚拟接口：" + snapshot.virtualInterfaces.joined(separator: "、"))
                        .font(.callout).textSelection(.enabled).help("检测到的接口可能属于其他应用，不代表 Zion 已接管流量。")
                } else { Text("待检测").font(.callout).foregroundStyle(.secondary) }
                HelperInstallationView(model: model)
            }
        }
    }
}

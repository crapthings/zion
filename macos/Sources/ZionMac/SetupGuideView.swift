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
                VStack(alignment: .leading, spacing: 22) {
                    VStack(alignment: .leading, spacing: 9) {
                        Text("开始使用 Zion").font(.system(size: 32, weight: .semibold, design: .rounded))
                        Text("查看当前网络状态，选择如何连接。也可以跳过，稍后再设置。")
                            .foregroundStyle(.secondary)
                    }.padding(.bottom, 4)
                    serverSection
                    proxySection
                    enhancedSection
                    if model.connection.needsRecovery {
                        Surface {
                            HStack {
                                Label("有待恢复的系统代理设置。", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
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
                }.padding(32).frame(maxWidth: 800).frame(maxWidth: .infinity)
            }
            Divider()
            HStack(spacing: 16) {
                Toggle("每次启动显示引导", isOn: Binding(get: { model.setupGuide.showOnLaunch }, set: { model.setupGuide.showOnLaunch = $0 }))
                    .toggleStyle(.checkbox).font(.callout)
                Spacer()
                Button("跳过") { model.finishSetup() }
                Button("继续") { model.finishSetup() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }.padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { model.setupGuide.refresh(); model.helperInstallation.refresh() }
    }

    /// Reuse the normal profile editor rather than inventing an onboarding-only credential store.
    private var serverSection: some View {
        Surface {
            HStack(spacing: 16) {
                Image(systemName: "server.rack").font(.title2).foregroundStyle(.secondary).frame(width: 32)
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.selectedProfile?.name ?? "添加服务器").font(.headline)
                    Text(model.selectedProfile?.server ?? "连接前需要一台配置好的服务器。").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button(model.selectedProfile == nil ? "添加服务器" : "编辑") { model.edit(model.selectedProfile) }
                    .disabled(!model.canConfigureSetupProxy)
                Button("导入 JSON") { model.importJSON() }.disabled(!model.canConfigureSetupProxy)
            }
        }
    }

    /// Report system proxy flags separately from the core's authenticated connection state.
    private var proxySection: some View {
        Surface {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: "network").font(.title2).foregroundStyle(Color.accentColor).frame(width: 32)
                    Text("系统代理").font(.headline)
                    Spacer()
                    Text(zionProxyActive ? "Zion 连接已建立" : "Zion 未连接").font(.callout).foregroundStyle(zionProxyActive ? Color.green : .secondary)
                }
                if let snapshot = model.setupGuide.snapshot {
                    Text(snapshot.proxies.isEmpty ? "当前未检测到启用的系统代理。" : "系统当前启用：" + snapshot.proxies.map(\.rawValue).joined(separator: "、"))
                        .font(.callout).textSelection(.enabled)
                } else { Text("系统代理状态待检测。").font(.callout).foregroundStyle(.secondary) }
                Text("适用于遵循 macOS SOCKS 设置的应用。连接时暂时替换现有代理设置，断开后恢复。")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button(zionProxyActive ? "Zion 已连接" : "连接并启用系统代理") { Task { await model.connectFromSetup() } }
                        .disabled(!model.canConfigureSetupProxy)
                    Button("刷新状态", systemImage: "arrow.clockwise") { model.setupGuide.refresh() }
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
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: "point.3.connected.trianglepath.dotted").font(.title2).foregroundStyle(.secondary).frame(width: 32)
                    Text("增强模式").font(.headline)
                    Spacer()
                    Text("尚未就绪").font(.callout).foregroundStyle(.secondary)
                }
                if let snapshot = model.setupGuide.snapshot {
                    Text(snapshot.virtualInterfaces.isEmpty ? "未检测到已启用且配置地址的虚拟接口。" : "检测到虚拟接口：" + snapshot.virtualInterfaces.joined(separator: "、"))
                        .font(.callout).textSelection(.enabled)
                    if !snapshot.virtualInterfaces.isEmpty {
                        Text("这些接口可能属于 VPN 或其他应用，不代表 Zion 已接管流量。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else { Text("虚拟接口状态待检测。").font(.callout).foregroundStyle(.secondary) }
                Text("增强模式用于接管不遵循系统代理的应用。当前 TUN 网络接入尚未完成，安装辅助组件后仍不可启用。")
                    .font(.callout).foregroundStyle(.secondary)
                HelperInstallationView(model: model)
            }
        }
    }
}
